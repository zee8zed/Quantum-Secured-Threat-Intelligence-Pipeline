"""
ML-based severity classification for threat reports.

This replaces the earlier rule-based if/elif scoring baseline
(see notebooks/05_rule_based_classification_baseline.ipynb, kept only for
historical comparison) with predictions from a trained scikit-learn model
(see src/train_classifier.py). Every severity label and confidence score
returned here comes from the model's learned decision function, not from
hand-written thresholds.
"""
import sys
from pathlib import Path
from typing import Any

import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import feature_engineering

_MODEL_CACHE: dict[str, Any] | None = None


def _load_model() -> dict[str, Any]:
    global _MODEL_CACHE

    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if not Path(config.SEVERITY_MODEL_FILE).exists():
        raise FileNotFoundError(
            "No trained severity classifier found at "
            f"{config.SEVERITY_MODEL_FILE}. Run src/train_classifier.py "
            "first."
        )

    _MODEL_CACHE = joblib.load(config.SEVERITY_MODEL_FILE)
    return _MODEL_CACHE


def classify_severity(
    text: str,
    entities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Predict report severity using the trained ML classifier.

    Parameters
    ----------
    text : str
        The (cleaned) report text.
    entities : dict, optional
        The merged entity report produced by src/entity_merger.py. Used to
        derive additional model-predicted-entity-count features.

    Returns
    -------
    dict
        severity, confidence, per-class probabilities, top contributing
        features (for explainability) and the method used.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    bundle = _load_model()
    model = bundle["model"]
    labels = bundle["labels"]

    features = feature_engineering.vectorize(text, entities)

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    class_probabilities = {
        str(label): round(float(prob), 4)
        for label, prob in zip(model.classes_, probabilities)
    }

    confidence = max(class_probabilities.values())

    top_features = feature_engineering.create_features(text, entities, top_k=5)
    reasons = [
        f"top contributing signal: {name} (weight={weight})"
        for name, weight in top_features.items()
        if weight > 0
    ][:5]

    return {
        "severity": str(prediction),
        "confidence": round(float(confidence), 4),
        "class_probabilities": class_probabilities,
        "reasons": reasons or ["model found no strong contributing signals"],
        "method": "ml-model:random-forest-tfidf",
        "labels": labels,
    }
