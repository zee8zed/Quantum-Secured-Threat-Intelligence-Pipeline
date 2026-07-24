"""
Assemble the final structured threat-intelligence report from model
outputs (NER entities + severity classification) and write it to disk as
JSON, ready for the CRYSTALS-Kyber encryption stage.

Every field that reflects a judgement call (entities found, severity,
confidence) is copied verbatim from model predictions -- this module only
does bookkeeping/serialization, it makes no classification decisions of
its own.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config


def build_report(
    source_path: str,
    raw_text: str,
    cleaned_text: str,
    entities: dict[str, Any],
    classification: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the JSON-serialisable report structure.
    """
    return {
        "schema_version": config.FILE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_path": str(source_path),
        "report_text": raw_text,
        "cleaned_text": cleaned_text,
        "entities": entities,
        "classification": classification,
    }


def save_report(
    report: dict[str, Any],
    output_path: str | Path = config.PLAINTEXT_REPORT,
) -> Path:
    """
    Write the report to disk as JSON, creating parent directories as
    needed. This is the plaintext input that crypto.crypto.encrypt() will
    subsequently encrypt.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding=config.TEXT_ENCODING) as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    return output_path


def generate(
    source_path: str,
    raw_text: str,
    cleaned_text: str,
    entities: dict[str, Any],
    classification: dict[str, Any],
    output_path: str | Path = config.PLAINTEXT_REPORT,
) -> Path:
    """
    Convenience wrapper: build the report structure and write it to disk.
    """
    report = build_report(source_path, raw_text, cleaned_text, entities, classification)
    return save_report(report, output_path)
