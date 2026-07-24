"""
ML-based feature engineering for threat report severity classification.

Unlike a hand-written keyword list, the features here are produced by a
fitted TF-IDF vectorizer (a statistical model learned from a corpus of
MITRE ATT&CK entity descriptions) plus counts of entities predicted by the
transformer NER model. This means the feature representation generalises
to arbitrary input text instead of only reacting to a fixed vocabulary.
"""
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer

try:
    import config
except ImportError:  # pragma: no cover
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import config

# Entity labels the transformer NER can predict (see notebooks/06, 07 and
# data/external/annoctr). Counting how many of each the model found in a
# report is itself a model-derived (not hardcoded-keyword) signal.
ENTITY_LABELS = [
    "GROUP",
    "MALWARE",
    "TOOL",
    "TECHNIQUE",
    "TACTIC",
    "VULNERABILITY",
    "INDICATOR",
    "SECTOR",
    "ORG",
    "LOC",
    "SYSTEM",
    "DATE",
    "CON",
]

_PIPELINE_CACHE: TfidfVectorizer | None = None


def fit_feature_pipeline(
    texts: list[str],
    max_features: int = 4000,
) -> TfidfVectorizer:
    """
    Fit a TF-IDF vectorizer over a corpus of report/entity-description text
    and persist it to disk so training and inference always use the exact
    same fitted vocabulary.
    """
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),
        min_df=2,
        stop_words="english",
        sublinear_tf=True,
    )
    vectorizer.fit(texts)

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, config.FEATURE_PIPELINE_FILE)

    global _PIPELINE_CACHE
    _PIPELINE_CACHE = vectorizer

    return vectorizer


def _load_pipeline() -> TfidfVectorizer:
    global _PIPELINE_CACHE

    if _PIPELINE_CACHE is not None:
        return _PIPELINE_CACHE

    if not Path(config.FEATURE_PIPELINE_FILE).exists():
        raise FileNotFoundError(
            "No fitted feature pipeline found at "
            f"{config.FEATURE_PIPELINE_FILE}. Run src/train_classifier.py "
            "first to fit and save it."
        )

    _PIPELINE_CACHE = joblib.load(config.FEATURE_PIPELINE_FILE)
    return _PIPELINE_CACHE


def entity_label_counts(
    entities: dict[str, Any] | None,
) -> dict[str, float]:
    """
    Turn the model-predicted entities (from src/entity_merger.py) into
    numeric counts per label. These are model predictions, not a fixed
    keyword list.
    """
    counts = {f"entity_count_{label.lower()}": 0.0 for label in ENTITY_LABELS}

    if not entities:
        return counts

    merged = entities.get("merged_entities", entities.get("entities", []))

    for entity in merged:
        label = str(entity.get("label", "")).upper()
        key = f"entity_count_{label.lower()}"
        if key in counts:
            counts[key] += 1.0
        else:
            counts["entity_count_other"] = counts.get("entity_count_other", 0.0) + 1.0

    return counts


def vectorize(
    text: str,
    entities: dict[str, Any] | None = None,
) -> sparse.csr_matrix:
    """
    Build the full model-ready feature vector (TF-IDF text features plus
    NER-derived entity counts) for a single report. Returns a 1-row sparse
    matrix so it can be fed directly into a scikit-learn classifier.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    vectorizer = _load_pipeline()
    text_features = vectorizer.transform([text])

    counts = entity_label_counts(entities)
    count_matrix = sparse.csr_matrix(np.array([list(counts.values())]))

    return sparse.hstack([text_features, count_matrix]).tocsr()


def create_features(
    text: str,
    entities: dict[str, Any] | None = None,
    top_k: int = 25,
) -> dict[str, float]:
    """
    Convert extracted threat-report entities and text into a human-readable
    numeric feature dictionary, backed by the same fitted TF-IDF model used
    for classification. Kept as a dict (rather than a raw vector) so it can
    double as an explanation of *why* a report scored the way it did.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if entities is not None and not isinstance(entities, dict):
        raise TypeError("entities must be a dictionary")

    vectorizer = _load_pipeline()
    row = vectorizer.transform([text])
    feature_names = vectorizer.get_feature_names_out()

    nonzero = row.nonzero()[1]
    weighted_terms = sorted(
        ((feature_names[i], float(row[0, i])) for i in nonzero),
        key=lambda item: item[1],
        reverse=True,
    )[:top_k]

    features: dict[str, float] = {
        f"tfidf::{term}": round(weight, 6) for term, weight in weighted_terms
    }

    features.update(entity_label_counts(entities))

    return features


def vectorize_batch(
    texts: list[str],
    entities_list: list[dict[str, Any] | None] | None = None,
) -> sparse.csr_matrix:
    """
    Batch version of ``vectorize`` used by src/train_classifier.py to build
    a training/evaluation design matrix efficiently (one TF-IDF transform
    call instead of one per document).
    """
    vectorizer = _load_pipeline()
    text_features = vectorizer.transform(texts)

    if entities_list is None:
        entities_list = [None] * len(texts)

    count_rows = [list(entity_label_counts(e).values()) for e in entities_list]
    count_matrix = sparse.csr_matrix(np.array(count_rows))

    return sparse.hstack([text_features, count_matrix]).tocsr()
