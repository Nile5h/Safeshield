"""Train SafeShield's binary message suspicion model."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ML_DIR = Path(__file__).resolve().parent
BASE_DIR = ML_DIR.parent
MESSAGES_FILE = BASE_DIR / "data" / "messages.csv"
SPAM_FILE = BASE_DIR / "data" / "spam.csv"
MODEL_FILE = ML_DIR / "models" / "message_model.joblib"


LABEL_MAP = {
    "0": "benign",
    "1": "suspicious",
    "ham": "benign",
    "spam": "suspicious",
    "benign": "benign",
}


def _normalize_label(value: object) -> str:
    val = str(value).strip().lower().replace(" ", "_")
    return LABEL_MAP.get(val, val)


def load_dataset() -> pd.DataFrame:
    messages = pd.read_csv(MESSAGES_FILE)
    column_names = {str(column).strip().lower(): column for column in messages.columns}
    text_column = column_names.get("text") or column_names.get("message")
    target_column = column_names.get("label") or column_names.get("category")
    if text_column is None or target_column is None:
        raise ValueError(
            f"{MESSAGES_FILE} must contain a text/message column and either a label or category column."
        )
    messages = messages[[text_column, target_column]].rename(
        columns={text_column: "text", target_column: "category"}
    )
    messages["text"] = messages["text"].fillna("").astype(str).str.normalize("NFKC").str.replace(r"\s+", " ", regex=True).str.strip()
    messages["category"] = messages["category"].fillna("unknown").map(_normalize_label)

    spam = pd.read_csv(SPAM_FILE, encoding="latin-1", usecols=[0, 1], names=["label", "text"], header=0)
    spam["text"] = spam["text"].fillna("").astype(str).str.normalize("NFKC").str.replace(r"\s+", " ", regex=True).str.strip()
    spam["category"] = spam["label"].fillna("unknown").map(_normalize_label)
    spam = spam[["text", "category"]]

    combined = pd.concat([messages[["text", "category"]], spam], ignore_index=True)
    print("Class distribution before preprocessing:")
    print(combined["category"].value_counts(dropna=False).to_string())
    combined = combined[(combined["text"] != "") & (combined["category"] != "unknown")]
    combined = combined.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print("\nClass distribution after preprocessing:")
    print(combined["category"].value_counts().to_string())
    for category, count in combined["category"].value_counts().items():
        if count < 20:
            print(f"WARNING: category '{category}' has only {count} examples; it is not a reliable standalone ML class.")
    combined["target"] = combined["category"].ne("benign").map({True: "suspicious", False: "benign"})
    return combined


def build_model() -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_df=0.98, strip_accents="unicode")),
        ("character", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), sublinear_tf=True, min_df=2, max_features=80000)),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced", random_state=42)),
    ])


def main() -> None:
    dataset = load_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        dataset["text"], dataset["target"], test_size=0.2, random_state=42, stratify=dataset["target"]
    )
    model = build_model()
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    print("\nEvaluation metrics (binary benign vs suspicious):")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, pos_label='suspicious', zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_test, predictions, pos_label='suspicious', zero_division=0):.4f}")
    print(f"F1-score: {f1_score(y_test, predictions, pos_label='suspicious', zero_division=0):.4f}")
    print(f"Macro F1: {f1_score(y_test, predictions, average='macro', zero_division=0):.4f}")
    print(f"Weighted F1: {f1_score(y_test, predictions, average='weighted', zero_division=0):.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions, zero_division=0))
    print("Confusion Matrix [benign, suspicious]:")
    print(confusion_matrix(y_test, predictions, labels=["benign", "suspicious"]))
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    print(f"\nModel saved to: {MODEL_FILE}")


if __name__ == "__main__":
    main()
