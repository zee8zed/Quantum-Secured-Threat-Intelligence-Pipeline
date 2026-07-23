from __future__ import annotations

from typing import Any

import torch
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    pipeline,
)


DEFAULT_MODEL_NAME = "cisco-ai/SecureBERT2.0-NER"


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


class TransformerNER:
    """
    Cybersecurity transformer-based NER inference wrapper.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL_NAME,
    ) -> None:
        self.model_name = model_name

        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name
        )

        self.model = AutoModelForTokenClassification.from_pretrained(
            model_name
        )

        self.pipeline = pipeline(
            task="token-classification",
            model=self.model,
            tokenizer=self.tokenizer,
            aggregation_strategy="simple",
            device=get_device(),
        )

    def extract(
        self,
        text: str,
        minimum_score: float = 0.50,
    ) -> list[dict[str, Any]]:
        """
        Extract contextual cybersecurity entities.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        if not text.strip():
            return []

        predictions = self.pipeline(text)

        results: list[dict[str, Any]] = []

        for prediction in predictions:
            score = float(prediction["score"])

            if score < minimum_score:
                continue

            results.append(
                {
                    "text": prediction["word"],
                    "label": prediction["entity_group"],
                    "score": round(score, 4),
                    "start": int(prediction["start"]),
                    "end": int(prediction["end"]),
                    "source": "transformer",
                }
            )

        return results