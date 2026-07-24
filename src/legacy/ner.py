import json
import re
from pathlib import Path
from typing import Any

import pandas as pd


# ---------------------------------------------------------------------------
# Regex patterns for structured cybersecurity indicators
# ---------------------------------------------------------------------------

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

ATTACK_ID_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s]+",
    re.IGNORECASE,
)

HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b"
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def clean_url(url: str) -> str:
    """
    Remove punctuation that may appear immediately after a URL
    at the end of a sentence.
    """
    return url.rstrip(".,;:!?)]}")


def _normalize_indicator(value: str) -> str:
    """
    Normalize structured indicators while preserving their standard format.
    """
    return value.strip()


# ---------------------------------------------------------------------------
# ATT&CK dictionary loading
# ---------------------------------------------------------------------------

def load_attack_dictionary(
    csv_path: str | Path,
) -> dict[str, dict[str, Any]]:
    """
    Load ATT&CK entity names and aliases from attack_entities.csv.

    Parameters
    ----------
    csv_path:
        Path to the entity-only MITRE ATT&CK CSV.

    Returns
    -------
    dict
        Mapping from lowercase searchable terms to entity metadata.
    """
    path = Path(csv_path)

    if not path.exists():
        raise FileNotFoundError(
            f"ATT&CK entity dataset not found: {path}"
        )

    df = pd.read_csv(path)

    required_columns = {
        "name",
        "type",
        "external_id",
        "aliases",
    }

    missing_columns = required_columns.difference(df.columns)

    if missing_columns:
        raise ValueError(
            f"Dataset is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    entity_dictionary: dict[str, dict[str, Any]] = {}

    for _, row in df.iterrows():
        name = row.get("name")
        entity_type = row.get("type")
        external_id = row.get("external_id")

        if not isinstance(name, str) or not name.strip():
            continue

        canonical_name = name.strip()

        metadata: dict[str, Any] = {
            "name": canonical_name,
            "type": (
                entity_type
                if pd.notna(entity_type)
                else None
            ),
            "external_id": (
                external_id
                if pd.notna(external_id)
                else None
            ),
        }

        entity_dictionary[canonical_name.lower()] = metadata

        aliases = row.get("aliases")

        if not isinstance(aliases, str) or not aliases.strip():
            continue

        try:
            alias_list = json.loads(aliases)
        except json.JSONDecodeError:
            alias_list = []

        if not isinstance(alias_list, list):
            continue

        for alias in alias_list:
            if not isinstance(alias, str):
                continue

            alias = alias.strip()

            if not alias:
                continue

            entity_dictionary[alias.lower()] = {
                **metadata,
                "matched_alias": alias,
            }

    return entity_dictionary


# ---------------------------------------------------------------------------
# Dictionary-based ATT&CK entity matching
# ---------------------------------------------------------------------------

def match_attack_entities(
    text: str,
    entity_dictionary: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Match ATT&CK names and aliases in unstructured threat-report text.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    text_lower = text.lower()
    matches: list[dict[str, Any]] = []

    for search_term, metadata in entity_dictionary.items():
        pattern = rf"(?<!\w){re.escape(search_term)}(?!\w)"

        match = re.search(pattern, text_lower)

        if match is None:
            continue

        record = metadata.copy()
        record["matched_text"] = text[match.start():match.end()]
        matches.append(record)

    unique_matches: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()

    for match in matches:
        key = (
            match.get("name"),
            match.get("type"),
            match.get("external_id"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique_matches.append(match)

    return unique_matches


# ---------------------------------------------------------------------------
# Entity categorization
# ---------------------------------------------------------------------------

def categorize_attack_entities(
    matches: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """
    Group ATT&CK dictionary matches into useful frontend/report categories.
    """
    categories: dict[str, list[dict[str, Any]]] = {
        "threat_actors": [],
        "malware": [],
        "tools": [],
        "techniques": [],
        "campaigns": [],
        "other": [],
    }

    type_mapping = {
        "intrusion-set": "threat_actors",
        "malware": "malware",
        "tool": "tools",
        "attack-pattern": "techniques",
        "campaign": "campaigns",
    }

    for match in matches:
        object_type = match.get("type")
        category = type_mapping.get(object_type, "other")
        categories[category].append(match)

    return categories


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------

def extract_entities(
    text: str,
    attack_dictionary: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Extract structured indicators and optional MITRE ATT&CK entities.

    Extracted structured indicators:
    - CVE identifiers
    - ATT&CK technique identifiers
    - IPv4 addresses
    - URLs
    - MD5, SHA-1 and SHA-256 hashes

    When an ATT&CK dictionary is supplied, the function also extracts:
    - threat actors
    - malware
    - tools
    - techniques
    - campaigns
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    cves = {
        _normalize_indicator(value.upper())
        for value in CVE_PATTERN.findall(text)
    }

    attack_ids = {
        _normalize_indicator(value.upper())
        for value in ATTACK_ID_PATTERN.findall(text)
    }

    ip_addresses = {
        _normalize_indicator(value)
        for value in IP_PATTERN.findall(text)
    }

    urls = {
        clean_url(value)
        for value in URL_PATTERN.findall(text)
        if clean_url(value)
    }

    hashes = {
        _normalize_indicator(value.lower())
        for value in HASH_PATTERN.findall(text)
    }

    attack_matches: list[dict[str, Any]] = []

    if attack_dictionary is not None:
        attack_matches = match_attack_entities(
            text=text,
            entity_dictionary=attack_dictionary,
        )

    categorized_entities = categorize_attack_entities(
        attack_matches
    )

    return {
        "cves": sorted(cves),
        "attack_ids": sorted(attack_ids),
        "ip_addresses": sorted(ip_addresses),
        "urls": sorted(urls),
        "hashes": sorted(hashes),
        "attack_entities": attack_matches,
        "categorized_entities": categorized_entities,
    }