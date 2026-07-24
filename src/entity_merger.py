"""
Merge entity predictions from the transformer NER model into a single,
deduplicated entity list for downstream feature engineering and reporting.

Entity *typing* (is this a malware name? a threat actor? a vulnerability?)
comes exclusively from the transformer model's predictions -- there is no
keyword or dictionary lookup involved. The only non-model step here is
trivial span deduplication/overlap-resolution, which is bookkeeping rather
than a classification decision.
"""
from typing import Any


def _overlaps(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def merge_entities(
    *entity_lists: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge one or more lists of model-predicted entities (e.g. from multiple
    NER models/runs) into a single de-overlapped, de-duplicated list.

    When two predictions overlap in the source text, the one with the
    higher model confidence score is kept -- this is still a model-driven
    decision (trusting the more confident prediction), not a hardcoded
    rule about entity types.
    """
    all_entities: list[dict[str, Any]] = []
    for entities in entity_lists:
        all_entities.extend(entities or [])

    if not all_entities:
        return []

    ordered = sorted(
        all_entities,
        key=lambda e: (e["start"], -e["score"]),
    )

    merged: list[dict[str, Any]] = []
    for entity in ordered:
        collision = next(
            (kept for kept in merged if _overlaps(kept, entity)),
            None,
        )

        if collision is None:
            merged.append(dict(entity))
            continue

        if entity["score"] > collision["score"]:
            merged.remove(collision)
            merged.append(dict(entity))

    return sorted(merged, key=lambda e: e["start"])


def build_entity_report(
    text: str,
    ner_model: Any,
    minimum_score: float = 0.50,
) -> dict[str, Any]:
    """
    Run the transformer NER model on ``text`` and package the result into
    the entity report structure consumed by feature_engineering.py and
    report_generator.py.
    """
    predictions = ner_model.extract(text, minimum_score=minimum_score)
    merged = merge_entities(predictions)

    by_label: dict[str, list[dict[str, Any]]] = {}
    for entity in merged:
        by_label.setdefault(entity["label"], []).append(entity)

    return {
        "merged_entities": merged,
        "entities_by_label": by_label,
        "entity_count": len(merged),
        "source": "transformer-ner",
    }
