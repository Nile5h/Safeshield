"""Evaluate the SafeShield message analyzer against a labeled CSV dataset."""

from pathlib import Path
import sys

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
EVAL_DATASET = DATA_DIR / "messages_eval.csv"
FALLBACK_DATASET = DATA_DIR / "messages.csv"
FAILURES_FILE = DATA_DIR / "failed_messages.csv"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analyzer.message_analyzer import analyze_message
from risk_engine import evaluate_message_risk


def _normalize_label(value: object) -> int:
    """Convert supported dataset labels to benign (0) or malicious (1)."""
    normalized = str(value).strip().lower()
    if normalized in {"0", "0.0", "ham", "benign"}:
        return 0
    if normalized in {
        "1",
        "1.0",
        "spam",
        "malicious",
        "suspicious",
        "smishing",
        "phishing",
        "scam",
    }:
        return 1

    try:
        numeric_label = float(normalized)
    except ValueError as error:
        raise ValueError(
            f"Unsupported label {value!r}; expected 0/1, ham/spam, or a nonzero malicious label."
        ) from error
    if numeric_label == 0:
        return 0
    if numeric_label.is_integer() and numeric_label > 0:
        return 1
    raise ValueError(
        f"Unsupported label {value!r}; expected 0/1, ham/spam, or a nonzero malicious label."
    )


def load_dataset() -> tuple[pd.DataFrame, Path]:
    """Load the evaluation dataset, falling back to the repository dataset."""
    dataset_path = EVAL_DATASET if EVAL_DATASET.exists() else FALLBACK_DATASET
    if not dataset_path.exists():
        raise FileNotFoundError(f"No message dataset found at {EVAL_DATASET} or {FALLBACK_DATASET}.")

    dataset = pd.read_csv(dataset_path)
    column_names = {str(column).strip().lower(): column for column in dataset.columns}
    text_column = column_names.get("text") or column_names.get("message")
    label_column = column_names.get("label") or column_names.get("category")
    if text_column is None or label_column is None:
        raise ValueError(f"{dataset_path} must contain a text/message column and a label column.")

    dataset = dataset[[text_column, label_column]].rename(
        columns={text_column: "text", label_column: "label"}
    ).copy()
    dataset["text"] = dataset["text"].fillna("").astype(str)
    dataset["true_label"] = dataset["label"].map(_normalize_label)
    dataset = dataset[dataset["text"].str.strip().ne("")].reset_index(drop=True)
    return dataset, dataset_path


def evaluate(dataset: pd.DataFrame) -> tuple[list[int], list[dict[str, object]]]:
    """Run the analyzer and risk engine for every message in the dataset."""
    predictions: list[int] = []
    failures: list[dict[str, object]] = []
    total_messages = len(dataset)
    print(f"Evaluating {total_messages} messages...", flush=True)

    for index, row in enumerate(dataset.itertuples(index=False), start=1):
        indicators = analyze_message(row.text)
        analysis = evaluate_message_risk(indicators, row.text)
        predicted_label = 0 if analysis.risk_level == "LOW" else 1
        predictions.append(predicted_label)

        if predicted_label != row.true_label:
            failures.append(
                {
                    "text": row.text,
                    "true_label": row.true_label,
                    "predicted_label": predicted_label,
                    "predicted_risk_score": analysis.risk_score,
                    "risk_level": analysis.risk_level,
                    "error_type": "false_positive" if predicted_label else "false_negative",
                    "reasons": " | ".join(analysis.reasons),
                    "indicators": " | ".join(analysis.detected_indicators),
                }
            )

        if index == total_messages or index % 100 == 0:
            print(f"Progress: {index}/{total_messages}", flush=True)

    return predictions, failures


def main() -> None:
    dataset, dataset_path = load_dataset()
    print(f"Dataset: {dataset_path}", flush=True)
    predictions, failures = evaluate(dataset)
    true_labels = dataset["true_label"].tolist()

    print(f"Messages evaluated: {len(true_labels)}")
    print(f"Accuracy: {accuracy_score(true_labels, predictions):.4f}")
    print(f"Precision: {precision_score(true_labels, predictions, zero_division=0):.4f}")
    print(f"Recall: {recall_score(true_labels, predictions, zero_division=0):.4f}")
    print(f"F1-Score: {f1_score(true_labels, predictions, zero_division=0):.4f}")

    failures_frame = pd.DataFrame(
        failures,
        columns=[
            "text",
            "true_label",
            "predicted_label",
            "predicted_risk_score",
            "risk_level",
            "error_type",
            "reasons",
            "indicators",
        ],
    )
    FAILURES_FILE.parent.mkdir(parents=True, exist_ok=True)
    failures_frame.to_csv(FAILURES_FILE, index=False)
    print(f"Misclassified messages: {len(failures)}")
    print(f"Failures saved to: {FAILURES_FILE}")


if __name__ == "__main__":
    main()