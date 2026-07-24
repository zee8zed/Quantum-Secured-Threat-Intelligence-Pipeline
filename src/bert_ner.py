"""
Transformer-based (BERT-family) NER for cybersecurity threat reports.

This module is purely model-driven: every entity it returns is a prediction
from a trained token-classification model. It first tries to load a model
that has been fine-tuned locally on the AnnoCTR corpus (see train_ner.py);
if no such checkpoint exists, it falls back to the pretrained cybersecurity
NER model on the Hugging Face Hub.
"""
from pathlib import Path
from typing import Any

import torch
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    pipeline,
)

try:
    import config
except ImportError:  # pragma: no cover - allows running from within src/
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import config

DEFAULT_MODEL_NAME = config.NER_DEFAULT_HUB_MODEL


def get_device() -> int | str:
    """
    Select the best available inference device.

    Returns:
        0 for CUDA GPU,
        "mps" for Apple Silicon GPU,
        -1 for CPU.
    """
    if torch.cuda.is_available():
        return 0

    if torch.backends.mps.is_available():
        return "mps"

    return -1


def resolve_model_name(model_name: str | None = None) -> str:
    """
    Decide which model weights to load.

    Preference order:
    1. An explicit ``model_name`` argument.
    2. A locally fine-tuned checkpoint at ``config.NER_MODEL_DIR``
       (produced by ``src/train_ner.py``).
    3. The default pretrained cybersecurity NER model on the HF Hub.
    """
    if model_name:
        return model_name

    local_dir = Path(config.NER_MODEL_DIR)
    if (local_dir / "config.json").exists():
        return str(local_dir)

    return DEFAULT_MODEL_NAME


class TransformerNER:
    """
    Cybersecurity transformer-based NER inference wrapper.

    All entity labels and spans returned by ``extract`` are predictions of
    the underlying token-classification model -- nothing is hardcoded.
    """

    def __init__(
        self,
        model_name: str | None = None,
    ) -> None:
        self.model_name = resolve_model_name(model_name)

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
        )

        self.model = AutoModelForTokenClassification.from_pretrained(
            self.model_name,
        )

        self.pipeline = pipeline(
            task="token-classification",
            model=self.model,
            tokenizer=self.tokenizer,
            aggregation_strategy="max",
            device=get_device(),
        )

    def extract(
        self,
        text: str,
        minimum_score: float = 0.50,
    ) -> list[dict[str, Any]]:
        """
        Extract contextual cybersecurity entities.

        The raw pipeline output is post-processed to merge sub-word /
        punctuation fragments that the aggregation strategy alone does not
        stitch back together (a known issue when a model predicts the same
        label for a run of tokens that are not all contiguous "entity"
        pieces, e.g. long hashes, URLs or dotted IPs). Fragments belonging
        to the same label that are directly adjacent (or separated only by
        punctuation/whitespace) in the source text are merged into a
        single span, and the merged score is the mean of the piece scores.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        if not text.strip():
            return []

        predictions = self.pipeline(text)

        raw: list[dict[str, Any]] = []
        for prediction in predictions:
            score = float(prediction["score"])

            if score < minimum_score:
                continue

            raw.append(
                {
                    "text": prediction["word"],
                    "label": prediction["entity_group"],
                    "score": score,
                    "start": int(prediction["start"]),
                    "end": int(prediction["end"]),
                    "source": "transformer",
                }
            )

        return _merge_adjacent_fragments(raw, text)


def _merge_adjacent_fragments(
    entities: list[dict[str, Any]],
    text: str,
    max_gap: int = 1,
) -> list[dict[str, Any]]:
    """
    Merge consecutive model predictions that share a label and are
    directly adjacent (or nearly so) in the source text into one span.

    This keeps the output strictly a function of the model's own
    predictions -- it only stitches together pieces the model already
    labelled identically, it never introduces a new label.
    """
    if not entities:
        return []

    ordered = sorted(entities, key=lambda e: e["start"])

    merged: list[dict[str, Any]] = [dict(ordered[0])]

    for entity in ordered[1:]:
        last = merged[-1]

        gap = entity["start"] - last["end"]
        same_label = entity["label"] == last["label"]

        if same_label and 0 <= gap <= max_gap:
            last["end"] = entity["end"]
            last["text"] = text[last["start"] : last["end"]]
            last["score"] = round((last["score"] + entity["score"]) / 2, 4)
        else:
            merged.append(dict(entity))

    for entity in merged:
        entity["text"] = entity["text"].strip()
        entity["score"] = round(float(entity["score"]), 4)

    return [e for e in merged if e["text"]]
