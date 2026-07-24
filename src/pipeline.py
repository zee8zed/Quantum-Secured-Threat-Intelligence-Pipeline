"""
End-to-end orchestration: raw report -> tokenizer -> transformer NER ->
ML feature engineering -> ML severity classifier -> report_generator ->
CRYSTALS-Kyber encryption.

Every analytical step (entity recognition, severity classification) is a
prediction from a trained model; this module only wires the stages
together and does not itself make any classification decisions.

Usage
-----
    python3 src/pipeline.py --input ../data/raw/sample_reports/testing/report_001.txt
"""
import argparse
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import config
import tokenizer as tokenizer_module
from bert_ner import TransformerNER
from entity_merger import build_entity_report
import classifier
import report_generator

_NER_MODEL: TransformerNER | None = None


def _get_ner_model() -> TransformerNER:
    global _NER_MODEL
    if _NER_MODEL is None:
        _NER_MODEL = TransformerNER()
    return _NER_MODEL


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path = config.PLAINTEXT_REPORT,
    minimum_entity_score: float = 0.5,
) -> dict[str, Any]:
    """
    Run the full analysis pipeline on a single raw report file and write
    the resulting plaintext JSON report to ``output_path``.
    """
    input_path = Path(input_path)
    raw_text = input_path.read_text(encoding=config.TEXT_ENCODING)

    # 1. Preprocessing / tokenization
    preprocessed = tokenizer_module.preprocess_report(raw_text)
    cleaned_text = preprocessed["cleaned_text"]

    # 2. Transformer NER (model prediction)
    ner_model = _get_ner_model()
    entities = build_entity_report(
        cleaned_text,
        ner_model,
        minimum_score=minimum_entity_score,
    )

    # 3. ML severity classification (model prediction, features computed
    #    internally from the fitted TF-IDF pipeline + entity counts)
    classification = classifier.classify_severity(cleaned_text, entities)

    # 4. Assemble + persist plaintext report
    report_path = report_generator.generate(
        source_path=str(input_path),
        raw_text=raw_text,
        cleaned_text=cleaned_text,
        entities=entities,
        classification=classification,
        output_path=output_path,
    )

    return {
        "report_path": report_path,
        "entities": entities,
        "classification": classification,
    }


def run_pipeline_with_encryption(
    input_path: str | Path,
    plaintext_path: str | Path = config.PLAINTEXT_REPORT,
    encrypted_path: str | Path = config.ENCRYPTED_REPORT,
    minimum_entity_score: float = 0.5,
) -> dict[str, Any]:
    """
    Run the analysis pipeline and then encrypt the resulting report with
    the post-quantum (ML-KEM/Kyber + AES-GCM) crypto module.
    """
    result = run_pipeline(
        input_path,
        output_path=plaintext_path,
        minimum_entity_score=minimum_entity_score,
    )

    from crypto import encrypt as crypto_encrypt

    encrypted_file = crypto_encrypt(
        input_file=Path(plaintext_path),
        output_file=Path(encrypted_path),
    )
    result["encrypted_path"] = encrypted_file
    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full threat-intel pipeline on a raw report.",
    )
    parser.add_argument("--input", required=True, help="Path to a raw report .txt file")
    parser.add_argument(
        "--output",
        default=str(config.PLAINTEXT_REPORT),
        help="Where to write the plaintext JSON report",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Also encrypt the resulting report with the Kyber/AES-GCM module",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.encrypt:
        outcome = run_pipeline_with_encryption(args.input, plaintext_path=args.output)
        print("Plaintext report:", outcome["report_path"])
        print("Encrypted report:", outcome["encrypted_path"])
    else:
        outcome = run_pipeline(args.input, output_path=args.output)
        print("Plaintext report:", outcome["report_path"])

    print("Severity:", outcome["classification"]["severity"])
    print("Confidence:", outcome["classification"]["confidence"])
    print("Entities found:", outcome["entities"]["entity_count"])
