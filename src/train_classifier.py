"""Train the ML severity classifier.

Ground truth severity labels come from real CVSS v3 base severity scores
pulled from the NVD (National Vulnerability Database) public API -- see
data/external/nvd/nvd_cve_severity_v3_recent.csv. This replaces the earlier
approach of inventing a severity label from ATT&CK structured metadata
(kill-chain-phase / platform / alias counts), which had no real-world
ground truth behind it.

Text features are TF-IDF vectors (src/feature_engineering.py) computed over
the CVE description text. The model itself is a RandomForestClassifier.
"""

import sys
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import config  # noqa: E402
import feature_engineering as _fe_module  # noqa: E402
from feature_engineering import fit_feature_pipeline  # noqa: E402

SEVERITY_LABELS = ["Low", "Medium", "High", "Critical"]

NVD_SEVERITY_DATA_CANDIDATES = [
    config.DATA_DIR / "external" / "nvd" / "nvd_cve_severity_v3_recent.csv",
    config.DATA_DIR / "external" / "nvd" / "nvd_cve_severity.csv",
]

MAX_PER_CLASS = 3000


def _resolve_dataset_path() -> Path:
    for candidate in NVD_SEVERITY_DATA_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No NVD CVSS severity dataset found. Expected one of: "
        + ", ".join(str(c) for c in NVD_SEVERITY_DATA_CANDIDATES)
    )


def build_training_frame(dataset_path: Path | str | None = None) -> pd.DataFrame:
    """Load the NVD CVE dataset and prepare it for training.

    Ground truth: real CVSS v3 baseSeverity (LOW/MEDIUM/HIGH/CRITICAL) assigned
    by NVD analysts -- not a heuristic we invented.
    Feature input: the CVE's English description text.
    """
    path = Path(dataset_path) if dataset_path else _resolve_dataset_path()
    df = pd.read_csv(path)

    df = df[df["description"].notna()].copy()
    df = df[df["description"].str.len() > 20]
    df["cvss_severity"] = df["cvss_severity"].astype(str).str.upper()
    df = df[df["cvss_severity"].isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])]
    df["severity"] = df["cvss_severity"].str.title()

    # Cap dominant classes so the model isn't overwhelmed by MEDIUM/HIGH,
    # while still leaving class_weight="balanced" to handle residual skew.
    balanced_parts = []
    for label in SEVERITY_LABELS:
        subset = df[df["severity"] == label]
        if len(subset) > MAX_PER_CLASS:
            subset = subset.sample(n=MAX_PER_CLASS, random_state=42)
        balanced_parts.append(subset)
    df = pd.concat(balanced_parts, ignore_index=True)

    df = df.drop_duplicates(subset=["description"]).reset_index(drop=True)
    return df[["cve_id", "description", "severity"]]


def train(
    dataset_path: Path | str | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, Any]:
    df = build_training_frame(dataset_path)

    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_state,
        stratify=df["severity"],
    )

    fit_feature_pipeline(train_df["description"].tolist())

    x_train = _fe_module.vectorize_batch(train_df["description"].tolist())
    x_test = _fe_module.vectorize_batch(test_df["description"].tolist())

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(x_train, train_df["severity"])

    predictions = model.predict(x_test)
    report = classification_report(
        test_df["severity"],
        predictions,
        output_dict=True,
        zero_division=0,
    )

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "labels": SEVERITY_LABELS,
            "label_source": "NVD CVSS v3 baseSeverity (real ground truth)",
        },
        config.SEVERITY_MODEL_FILE,
    )

    return {
        "train_size": len(train_df),
        "test_size": len(test_df),
        "classification_report": report,
    }


if __name__ == "__main__":
    results = train()
    print("Train size:", results["train_size"])
    print("Test size:", results["test_size"])
    print("Accuracy:", results["classification_report"]["accuracy"])
    for label in SEVERITY_LABELS:
        stats = results["classification_report"].get(label, {})
        print(f"  {label}: precision={stats.get('precision', 0):.3f} "
              f"recall={stats.get('recall', 0):.3f} f1={stats.get('f1-score', 0):.3f}")
    print(f"Saved model to {config.SEVERITY_MODEL_FILE}")
