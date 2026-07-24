"""
Evaluate the trained ML components of the pipeline:

1. The transformer NER model, against the held-out AnnoCTR test split
   (seqeval precision/recall/F1/accuracy).
2. The severity classifier, against a held-out split of the ATT&CK-derived
   training corpus (scikit-learn classification report).

All numbers reported here come from running the trained models against
data they were not trained on -- there is no rule-based scoring involved.

Usage
-----
    python3 src/evaluate.py --ner
    python3 src/evaluate.py --classifier
    python3 src/evaluate.py --all
"""
import argparse
import sys
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from transformers import DataCollatorForTokenClassification, Trainer, TrainingArguments

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import feature_engineering as fe
from train_ner import (
    build_label_maps,
    load_annoctr,
    make_compute_metrics,
    make_tokenize_fn,
)


def evaluate_ner(model_name: str | None = None, max_eval_samples: int | None = None) -> dict[str, Any]:
    """
    Evaluate a token-classification model (fine-tuned local checkpoint if
    one exists, otherwise whatever ``model_name`` is given) on the AnnoCTR
    test split.
    """
    import bert_ner
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    resolved_name = bert_ner.resolve_model_name(model_name)

    dataset = load_annoctr()
    if max_eval_samples:
        dataset["test"] = dataset["test"].select(
            range(min(max_eval_samples, len(dataset["test"])))
        )

    label_names, label2id, id2label = build_label_maps(dataset)

    tokenizer = AutoTokenizer.from_pretrained(resolved_name)
    model = AutoModelForTokenClassification.from_pretrained(resolved_name)

    model_labels = set(model.config.id2label.values())
    annoctr_labels = set(label_names)
    label_overlap = model_labels & annoctr_labels
    if len(label_overlap) < len(annoctr_labels) / 2:
        print(
            "WARNING: the loaded model's label schema "
            f"({sorted(model_labels)}) does not match the AnnoCTR label "
            f"schema ({sorted(annoctr_labels)}). This happens when "
            "evaluating the generic pretrained hub model, which was not "
            "fine-tuned on AnnoCTR's label set -- the precision/recall/F1 "
            "below are therefore not meaningful. Run src/train_ner.py to "
            "fine-tune a model on AnnoCTR before evaluating it here."
        )

    tokenized_test = dataset["test"].map(
        make_tokenize_fn(tokenizer, label2id),
        batched=True,
        remove_columns=dataset["test"].column_names,
    )

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(config.MODELS_DIR / "_eval_scratch"),
            per_device_eval_batch_size=4,
            report_to="none",
        ),
        processing_class=tokenizer,
        data_collator=DataCollatorForTokenClassification(tokenizer=tokenizer),
        compute_metrics=make_compute_metrics(id2label),
    )

    metrics = trainer.evaluate(tokenized_test)
    metrics["model_used"] = resolved_name
    metrics["num_test_examples"] = len(tokenized_test)
    return metrics


def evaluate_classifier(random_state: int = 42) -> dict[str, Any]:
    """
    Re-create the same held-out split used at training time and report a
    full scikit-learn classification report for the trained severity model.
    """
    import joblib
    from train_classifier import build_training_frame

    if not Path(config.SEVERITY_MODEL_FILE).exists():
        raise FileNotFoundError(
            f"No trained classifier at {config.SEVERITY_MODEL_FILE}. "
            "Run src/train_classifier.py first."
        )

    df = build_training_frame()

    _, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=random_state,
        stratify=df["severity"],
    )

    bundle = joblib.load(config.SEVERITY_MODEL_FILE)
    model = bundle["model"]

    x_test = fe.vectorize_batch(test_df["description"].tolist())
    predictions = model.predict(x_test)

    report = classification_report(
        test_df["severity"],
        predictions,
        output_dict=True,
        zero_division=0,
    )
    report["num_test_examples"] = len(test_df)
    return report


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate trained ML models.")
    parser.add_argument("--ner", action="store_true")
    parser.add_argument("--classifier", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--max-eval-samples", type=int, default=None)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.all or args.ner:
        print("=== NER evaluation (AnnoCTR test split) ===")
        ner_metrics = evaluate_ner(max_eval_samples=args.max_eval_samples)
        for key, value in ner_metrics.items():
            print(f"  {key}: {value}")

    if args.all or args.classifier:
        print("=== Severity classifier evaluation (held-out split) ===")
        clf_report = evaluate_classifier()
        print(f"  accuracy: {clf_report['accuracy']:.3f}")
        for label in ["Low", "Medium", "High", "Critical"]:
            stats = clf_report.get(label, {})
            print(
                f"  {label}: precision={stats.get('precision', 0):.3f} "
                f"recall={stats.get('recall', 0):.3f} f1={stats.get('f1-score', 0):.3f}"
            )
