"""
preprocess_attack.py
=====================

Preprocessing module for the MITRE ATT&CK Enterprise STIX 2.1 dataset.

This module converts the raw ``enterprise-attack.json`` STIX bundle into a
clean, machine-learning-ready tabular dataset (CSV). It is the first stage
of a larger cybersecurity threat-intelligence pipeline:

    MITRE ATT&CK STIX Dataset -> [THIS MODULE] -> NER -> Entity Extraction
    -> Feature Engineering -> Threat Classification -> Threat Intel Report
    -> CRYSTALS-Kyber Encryption -> Encrypted Threat Report

Scope
-----
This module ONLY performs preprocessing (loading, filtering, field
extraction, text cleaning, deduplication, validation, and saving). It does
NOT implement any NER model, classifier, or encryption logic -- those are
handled by later stages of the pipeline.

Usage
-----
    python preprocess_attack.py --input enterprise-attack.json \
        --output processed_attack_dataset.csv

Dependencies
------------
    pandas, tqdm (progress bar) -- everything else is standard library
    (json, re, unicodedata, pathlib, argparse, logging).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Any, Optional

import pandas as pd

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - tqdm is an optional convenience
    def tqdm(iterable, *args, **kwargs):  # type: ignore
        return iterable


# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("attack_preprocessing")


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# STIX object types we keep for downstream ML tasks. Every other type
# (identity, marking-definition, note, course-of-action, x-mitre-*, etc.)
# is discarded during filtering.
KEEP_TYPES: frozenset[str] = frozenset(
    {
        "attack-pattern",
        "malware",
        "tool",
        "intrusion-set",
        "campaign",
        "relationship",
    }
)

# Final column order for the output dataframe.
OUTPUT_COLUMNS: list[str] = [
    "id",
    "type",
    "name",
    "description",
    "aliases",
    "external_id",
    "platforms",
    "kill_chain_phases",
    "created",
    "modified",
]

# Regex patterns used by clean_text(). Pre-compiled for performance since
# clean_text() runs once per row over thousands of objects.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\((?:[^)]*)\)")
_URL_RE = re.compile(r"https?://\S+|www\.\S+")
_CITATION_RE = re.compile(r"\(Citation:\s*[^)]*\)", flags=re.IGNORECASE)
_MULTI_SPACE_RE = re.compile(r"[ \t]+")
_NEWLINE_RE = re.compile(r"[\r\n]+")


# --------------------------------------------------------------------------- #
# 1. Load Dataset
# --------------------------------------------------------------------------- #
def load_stix(filepath: str | Path) -> list[dict[str, Any]]:
    """
    Load a STIX 2.1 bundle from disk and return the list of STIX objects.

    Parameters
    ----------
    filepath : str | Path
        Path to the enterprise-attack.json file.

    Returns
    -------
    list[dict[str, Any]]
        The raw list of STIX objects taken from bundle["objects"].

    Raises
    ------
    FileNotFoundError
        If the given path does not exist.
    ValueError
        If the file is not valid JSON or does not contain an "objects" key.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"STIX bundle not found at: {path}")

    logger.info("Loading STIX bundle from %s", path)
    try:
        with path.open("r", encoding="utf-8") as f:
            bundle = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON in {path}: {exc}") from exc

    objects = bundle.get("objects")
    if objects is None:
        raise ValueError("Bundle does not contain an 'objects' field.")

    logger.info("Loaded %d raw STIX objects.", len(objects))
    return objects


# --------------------------------------------------------------------------- #
# 2 & 3. Filter Object Types + Remove Invalid Objects
# --------------------------------------------------------------------------- #
def filter_objects(
    objects: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Keep only whitelisted STIX object types and discard revoked/deprecated
    objects.

    Parameters
    ----------
    objects : list[dict[str, Any]]
        Raw STIX objects as loaded by load_stix().

    Returns
    -------
    tuple[list[dict[str, Any]], dict[str, int]]
        A tuple of (filtered_objects, stats) where stats records how many
        objects were removed for each reason, for later validation
        reporting.
    """
    stats = {
        "total_loaded": len(objects),
        "removed_wrong_type": 0,
        "removed_revoked": 0,
        "removed_deprecated": 0,
        "removed_malformed": 0,
    }

    filtered: list[dict[str, Any]] = []

    for obj in tqdm(objects, desc="Filtering objects"):
        try:
            if not isinstance(obj, dict):
                stats["removed_malformed"] += 1
                continue

            obj_type = obj.get("type")
            if obj_type not in KEEP_TYPES:
                stats["removed_wrong_type"] += 1
                continue

            if obj.get("revoked") is True:
                stats["removed_revoked"] += 1
                continue

            if obj.get("x_mitre_deprecated") is True:
                stats["removed_deprecated"] += 1
                continue

            filtered.append(obj)

        except Exception as exc:  # defensive: never let one bad object crash the run
            logger.warning("Skipping malformed object: %s", exc)
            stats["removed_malformed"] += 1
            continue

    logger.info(
        "Filtering complete: kept %d / %d objects.", len(filtered), len(objects)
    )
    return filtered, stats


# --------------------------------------------------------------------------- #
# 4. Extract Required Fields
# --------------------------------------------------------------------------- #
def _extract_external_id(obj: dict[str, Any]) -> Optional[str]:
    """
    Extract the MITRE ATT&CK technique/software/group ID (e.g. 'T1053')
    from an object's external_references list.

    The MITRE ATT&CK source is identified by source_name == 'mitre-attack'.
    Some objects may have multiple external references (e.g. CAPEC, NIST);
    only the ATT&CK one is relevant here.
    """
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        return None

    for ref in refs:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id")
            if ext_id:
                return str(ext_id)
    return None


def _extract_platforms(obj: dict[str, Any]) -> list[str]:
    """Extract x_mitre_platforms as a list of strings (empty list if absent)."""
    platforms = obj.get("x_mitre_platforms")
    if isinstance(platforms, list):
        return [str(p) for p in platforms]
    return []


def _extract_kill_chain_phases(obj: dict[str, Any]) -> list[str]:
    """
    Convert the kill_chain_phases field into a flat list of phase-name
    strings, e.g. ["persistence", "privilege-escalation"].
    """
    phases = obj.get("kill_chain_phases")
    if not isinstance(phases, list):
        return []

    phase_names: list[str] = []
    for phase in phases:
        if isinstance(phase, dict):
            name = phase.get("phase_name")
            if name:
                phase_names.append(str(name))
    return phase_names


def _extract_aliases(obj: dict[str, Any]) -> list[str]:
    """
    Extract aliases for malware/tool (x_mitre_aliases) or intrusion-set
    (aliases). Always returns a list, empty if none are present.
    """
    aliases = obj.get("aliases") or obj.get("x_mitre_aliases")
    if isinstance(aliases, list):
        return [str(a) for a in aliases]
    return []


def extract_fields(objects: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Build a dataframe with one row per STIX object, containing only the
    fields required for downstream ML tasks.

    Missing fields are stored as None (scalars) or [] (list-valued fields)
    rather than causing the row to be dropped.

    Parameters
    ----------
    objects : list[dict[str, Any]]
        Filtered STIX objects (see filter_objects()).

    Returns
    -------
    pd.DataFrame
        Dataframe with columns matching OUTPUT_COLUMNS (description is not
        yet cleaned at this stage).
    """
    rows: list[dict[str, Any]] = []

    for obj in tqdm(objects, desc="Extracting fields"):
        try:
            row = {
                "id": obj.get("id"),
                "type": obj.get("type"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "aliases": _extract_aliases(obj),
                "external_id": _extract_external_id(obj),
                "platforms": _extract_platforms(obj),
                "kill_chain_phases": _extract_kill_chain_phases(obj),
                "created": obj.get("created"),
                "modified": obj.get("modified"),
            }
            rows.append(row)
        except Exception as exc:
            logger.warning("Skipping object during field extraction: %s", exc)
            continue

    df = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
    logger.info("Extracted fields into dataframe with shape %s.", df.shape)
    return df


# --------------------------------------------------------------------------- #
# 5. Clean Description Text
# --------------------------------------------------------------------------- #
def clean_text(text: Optional[str]) -> str:
    """
    Clean a raw ATT&CK description string for transformer-based NLP use.

    Applies (in order):
        1. HTML tag removal
        2. Markdown link removal (keeps the link text, drops the URL)
        3. Bare URL removal
        4. Citation reference removal, e.g. "(Citation: FireEye2019)"
        5. Unicode normalization (NFKC)
        6. Newline -> space replacement
        7. Multi-space collapsing
        8. Whitespace stripping

    Deliberately does NOT: remove stopwords, stem, lemmatize, or strip
    punctuation -- this text is intended for transformer models that rely
    on natural sentence structure.

    Parameters
    ----------
    text : Optional[str]
        Raw description text. None or non-string input returns "".

    Returns
    -------
    str
        Cleaned description text.
    """
    if not isinstance(text, str) or not text:
        return ""

    cleaned = text

    # 1. Remove HTML tags
    cleaned = _HTML_TAG_RE.sub(" ", cleaned)

    # 2. Remove markdown links [text](url) -> keep "text"
    cleaned = _MARKDOWN_LINK_RE.sub(r"\1", cleaned)

    # 3. Remove bare URLs
    cleaned = _URL_RE.sub(" ", cleaned)

    # 4. Remove citation references, e.g. (Citation: FireEye2019)
    cleaned = _CITATION_RE.sub(" ", cleaned)

    # 5. Normalize unicode characters (e.g. curly quotes -> straight quotes)
    cleaned = unicodedata.normalize("NFKC", cleaned)

    # 6. Replace newlines/carriage returns with a single space
    cleaned = _NEWLINE_RE.sub(" ", cleaned)

    # 7. Collapse multiple spaces/tabs into one
    cleaned = _MULTI_SPACE_RE.sub(" ", cleaned)

    # 8. Strip leading/trailing whitespace
    cleaned = cleaned.strip()

    return cleaned


def apply_text_cleaning(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply clean_text() to the 'description' column of the dataframe.

    Parameters
    ----------
    df : pd.DataFrame
        Dataframe produced by extract_fields().

    Returns
    -------
    pd.DataFrame
        Same dataframe with 'description' cleaned in place (copy returned).
    """
    df = df.copy()
    tqdm.pandas(desc="Cleaning description text")
    if hasattr(df["description"], "progress_apply"):
        df["description"] = df["description"].progress_apply(clean_text)
    else:  # fallback if tqdm.pandas() registration failed
        df["description"] = df["description"].apply(clean_text)
    return df


# --------------------------------------------------------------------------- #
# 6. Remove Duplicate Records
# --------------------------------------------------------------------------- #
def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate rows based on the (name, description) pair, keeping
    the first occurrence.

    Parameters
    ----------
    df : pd.DataFrame
        Dataframe with cleaned descriptions.

    Returns
    -------
    pd.DataFrame
        Deduplicated dataframe with a reset index.
    """
    before = len(df)
    df = df.drop_duplicates(subset=["name", "description"], keep="first")
    df = df.reset_index(drop=True)
    after = len(df)
    logger.info("Removed %d duplicate rows (kept first occurrence).", before - after)
    return df


# --------------------------------------------------------------------------- #
# 7. Validate Data
# --------------------------------------------------------------------------- #
def validate_dataset(df: pd.DataFrame, filter_stats: dict[str, int]) -> None:
    """
    Print summary statistics about the processed dataset for quick sanity
    checking before it's handed off to the NER / classification stages.

    Parameters
    ----------
    df : pd.DataFrame
        Final processed dataframe (post-deduplication).
    filter_stats : dict[str, int]
        Stats dictionary returned by filter_objects().
    """
    print("\n" + "=" * 60)
    print("DATASET VALIDATION SUMMARY")
    print("=" * 60)

    print(f"Number of objects loaded:          {filter_stats['total_loaded']}")
    print(f"Number removed (wrong type):        {filter_stats['removed_wrong_type']}")
    print(f"Number removed (revoked):           {filter_stats['removed_revoked']}")
    print(f"Number removed (deprecated):        {filter_stats['removed_deprecated']}")
    print(f"Number removed (malformed):         {filter_stats['removed_malformed']}")
    print(f"Number remaining (final dataset):   {len(df)}")

    print("\nCount of each object type:")
    if "type" in df.columns and not df.empty:
        for obj_type, count in df["type"].value_counts().items():
            print(f"  {obj_type:<20} {count}")
    else:
        print("  (no rows to summarize)")

    missing_desc = int((df["description"] == "").sum()) if "description" in df else 0
    missing_name = int(df["name"].isna().sum()) if "name" in df else 0

    print(f"\nNumber of missing descriptions:     {missing_desc}")
    print(f"Number of missing names:            {missing_name}")
    print("=" * 60 + "\n")


# --------------------------------------------------------------------------- #
# 8. Save Dataset
# --------------------------------------------------------------------------- #
def save_dataset(df: pd.DataFrame, output_path: str | Path) -> None:
    """
    Save the processed dataframe to CSV.

    List-valued columns (aliases, platforms, kill_chain_phases) are
    serialized as JSON strings so they round-trip cleanly through CSV and
    can be parsed back with json.loads() in later pipeline stages.

    Parameters
    ----------
    df : pd.DataFrame
        Final processed dataframe.
    output_path : str | Path
        Destination CSV path.
    """
    path = Path(output_path)
    df_to_save = df.copy()

    list_columns = ["aliases", "platforms", "kill_chain_phases"]
    for col in list_columns:
        if col in df_to_save.columns:
            df_to_save[col] = df_to_save[col].apply(json.dumps)

    df_to_save.to_csv(path, index=False, encoding="utf-8")
    logger.info("Saved processed dataset to %s (%d rows).", path, len(df_to_save))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def main(
    input_path: str | Path = "enterprise-attack.json",
    output_path: str | Path = "processed_attack_dataset.csv",
) -> pd.DataFrame:
    """
    Run the full preprocessing pipeline end to end.

    Parameters
    ----------
    input_path : str | Path
        Path to the raw enterprise-attack.json STIX bundle.
    output_path : str | Path
        Path to write the processed CSV dataset.

    Returns
    -------
    pd.DataFrame
        The final processed dataframe (also written to disk as CSV).
    """
    raw_objects = load_stix(input_path)
    filtered_objects, filter_stats = filter_objects(raw_objects)
    df = extract_fields(filtered_objects)
    df = apply_text_cleaning(df)
    df = remove_duplicates(df)
    validate_dataset(df, filter_stats)
    save_dataset(df, output_path)
    return df


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for standalone script execution."""
    parser = argparse.ArgumentParser(
        description="Preprocess the MITRE ATT&CK Enterprise STIX bundle into "
        "an ML-ready CSV dataset."
    )
    parser.add_argument(
        "--input",
        type=str,
        default="enterprise-attack.json",
        help="Path to the raw enterprise-attack.json STIX bundle.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="processed_attack_dataset.csv",
        help="Path to write the processed CSV dataset.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    main(input_path=args.input, output_path=args.output)
