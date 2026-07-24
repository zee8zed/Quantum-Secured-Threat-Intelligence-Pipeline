"""
Fine-tune the transformer NER model on the AnnoCTR cyber-threat-intel NER
corpus and save the resulting weights so src/bert_ner.py can load a model
fine-tuned specifically for this pipeline instead of only the generic
pretrained checkpoint.

Usage
-----
    python3 src/train_ner.py                      # full training run
    python3 src/train_ner.py --smoke-test         # tiny run to sanity check
"""
import argparse
import sys
from pathlib import Path

import numpy as np
from seqeval.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from datasets import load_dataset
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config

def load_annoctr():
    data_files = {
        "train": str(config.NER_DATA_DIR / "train.json"),
        "validation": str(config.NER_DATA_DIR / "dev.json"),
        "test": str(config.NER_DATA_DIR / "test.json"),
    }
    return load_dataset("json", data_files=data_files)


def build_label_maps(dataset) -> tuple[list[str], dict[str, int], dict[int, str]]:
    label_names = sorted(
        {tag for split in dataset for example in dataset[split] for tag in example["all_tags"]}
    )
    label2id = {label: i for i, label in enumerate(label_names)}
    id2label = {i: label for label, i in label2id.items()}
    return label_names, label2id, id2label


def make_tokenize_fn(tokenizer, label2id):
    def tokenize_and_align_labels(examples):
        tokenized_inputs = tokenizer(
            examples["tokens"],
            truncation=True,
            is_split_into_words=True,
            max_length=512,
        )

        aligned_labels = []
        for batch_index, word_labels in enumerate(examples["all_tags"]):
            word_ids = tokenized_inputs.word_ids(batch_index=batch_index)

            previous_word_id = None
            label_ids = []

            for word_id in word_ids:
                if word_id is None:
                    label_ids.append(-100)
                elif word_id != previous_word_id:
                    label_ids.append(label2id[word_labels[word_id]])
                else:
                    original_label = word_labels[word_id]
                    if original_label.startswith("B-"):
                        inside_label = "I-" + original_label[2:]
                    else:
                        inside_label = original_label
                    label_ids.append(label2id.get(inside_label, label2id[original_label]))

                previous_word_id = word_id

            aligned_labels.append(label_ids)

        tokenized_inputs["labels"] = aligned_labels
        return tokenized_inputs

    return tokenize_and_align_labels


def make_compute_metrics(id2label):
    def compute_metrics(eval_pred):
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=2)

        true_predictions = []
        true_labels = []

        for prediction_row, label_row in zip(predictions, labels):
            predicted_tags = []
            reference_tags = []
            for prediction_id, label_id in zip(prediction_row, label_row):
                if label_id == -100:
                    continue
                predicted_tags.append(id2label[int(prediction_id)])
                reference_tags.append(id2label[int(label_id)])
            true_predictions.append(predicted_tags)
            true_labels.append(reference_tags)

        return {
            "precision": precision_score(true_labels, true_predictions),
            "recall": recall_score(true_labels, true_predictions),
            "f1": f1_score(true_labels, true_predictions),
            "accuracy": accuracy_score(true_labels, true_predictions),
        }

    return compute_metrics


def train(
    epochs: float = 3,
    batch_size: int = 2,
    grad_accum: int = 2,
    max_train_samples: int | None = None,
    max_eval_samples: int | None = None,
) -> dict:
    dataset = load_annoctr()

    if max_train_samples:
        dataset["train"] = dataset["train"].select(
            range(min(max_train_samples, len(dataset["train"])))
        )
    if max_eval_samples:
        dataset["validation"] = dataset["validation"].select(
            range(min(max_eval_samples, len(dataset["validation"])))
        )
        dataset["test"] = dataset["test"].select(
            range(min(max_eval_samples, len(dataset["test"])))
        )

    label_names, label2id, id2label = build_label_maps(dataset)

    tokenizer = AutoTokenizer.from_pretrained(config.NER_BASE_MODEL, use_fast=True)
    model = AutoModelForTokenClassification.from_pretrained(
        config.NER_BASE_MODEL,
        num_labels=len(label_names),
        label2id=label2id,
        id2label=id2label,
    )

    tokenized = dataset.map(
        make_tokenize_fn(tokenizer, label2id),
        batched=True,
        remove_columns=dataset["train"].column_names,
    )

    data_collator = DataCollatorForTokenClassification(tokenizer=tokenizer)

    config.NER_MODEL_DIR.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(config.NER_MODEL_DIR),
        learning_rate=2e-5,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=epochs,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        processing_class=tokenizer,
        data_collator=data_collator,
        compute_metrics=make_compute_metrics(id2label),
    )

    trainer.train()
    test_metrics = trainer.evaluate(tokenized["test"])

    # Persist the best model + tokenizer so bert_ner.py can load it later.
    trainer.save_model(str(config.NER_MODEL_DIR))
    tokenizer.save_pretrained(str(config.NER_MODEL_DIR))

    return {"test_metrics": test_metrics, "label_names": label_names}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune the CTI NER model.")
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--grad-accum", type=int, default=2)
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run a tiny (subset, 1 epoch) training pass to verify the "
        "pipeline works end-to-end, instead of full training.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.smoke_test:
        results = train(
            epochs=1,
            batch_size=4,
            grad_accum=1,
            max_train_samples=40,
            max_eval_samples=20,
        )
    else:
        results = train(
            epochs=args.epochs,
            batch_size=args.batch_size,
            grad_accum=args.grad_accum,
        )

    print("Test metrics:", results["test_metrics"])
    print(f"Saved fine-tuned model to {config.NER_MODEL_DIR}")
