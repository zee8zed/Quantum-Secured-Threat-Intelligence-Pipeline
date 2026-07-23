import re
import unicodedata
from typing import Any


WHITESPACE_PATTERN = re.compile(r"\s+")
HTML_PATTERN = re.compile(r"<[^>]+>")
CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)


def clean_report_text(text: str) -> str:
    """
    Clean report text while preserving cybersecurity indicators.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    text = unicodedata.normalize("NFKC", text)
    text = HTML_PATTERN.sub(" ", text)
    text = CONTROL_CHARACTER_PATTERN.sub(" ", text)
    text = WHITESPACE_PATTERN.sub(" ", text)

    return text.strip()


def tokenize_report(text: str) -> list[str]:
    """
    Split cleaned report text into whitespace-separated tokens.
    """
    cleaned_text = clean_report_text(text)

    if not cleaned_text:
        return []

    return cleaned_text.split()


def preprocess_report(text: str) -> dict[str, Any]:
    """
    Return cleaned text, tokens and basic text statistics.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    cleaned_text = clean_report_text(text)
    tokens = tokenize_report(cleaned_text)

    return {
        "original_text": text,
        "cleaned_text": cleaned_text,
        "tokens": tokens,
        "character_count": len(cleaned_text),
        "token_count": len(tokens),
    }