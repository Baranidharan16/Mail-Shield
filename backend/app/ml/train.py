"""
Trains both Phase 2 baseline models on the synthetic dataset and persists
them with full version metadata (Part: Model Management).

Run with:  python -m app.ml.train

This is intentionally a script, not something that runs at request time -
per the brief, "Do not silently replace a model." Re-training is an
explicit, auditable action that bumps MODEL_VERSION below.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.forensic.engine import run_forensic_analysis
from app.ml.dataset import DATASET_VERSION, generate_dataset
from app.ml.features import FEATURE_VERSION, build_feature_vector, feature_text_blob
from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, save_metadata

STRUCTURED_MODEL_VERSION = "1.0.0"
TEXT_MODEL_VERSION = "1.0.0"


def main(per_class: int = 30) -> None:
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    print(f"Generating synthetic dataset ({DATASET_VERSION}), {per_class} examples/class ...")
    examples = generate_dataset(per_class=per_class)
    print(f"Total examples: {len(examples)}")

    X_struct, X_text, y = [], [], []
    for ex in examples:
        result = run_forensic_analysis(ex.raw_bytes)
        fv = build_feature_vector(result)
        X_struct.append(fv.as_ordered_list())
        X_text.append(feature_text_blob(result))
        y.append(ex.label)

    # --- Structured model (Random Forest) -----------------------------------
    Xs_train, Xs_test, ys_train, ys_test = train_test_split(
        X_struct, y, test_size=0.25, random_state=42, stratify=y
    )
    rf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
    rf.fit(Xs_train, ys_train)
    struct_acc = rf.score(Xs_test, ys_test)
    print(f"Structured model held-out accuracy: {struct_acc:.3f}")

    struct_path_prefix = os.path.join(ARTIFACT_DIR, "structured_model")
    joblib.dump(rf, f"{struct_path_prefix}.joblib")
    save_metadata(struct_path_prefix, ModelMetadata(
        model_name="structured_random_forest",
        model_version=STRUCTURED_MODEL_VERSION,
        training_dataset_version=DATASET_VERSION,
        feature_version=FEATURE_VERSION,
        trained_at=datetime.now(timezone.utc).isoformat(),
        algorithm="RandomForestClassifier(n_estimators=200, max_depth=8)",
        classes=sorted(set(y)),
    ))

    # --- Text model (TF-IDF + Logistic Regression) --------------------------
    Xt_train, Xt_test, yt_train, yt_test = train_test_split(
        X_text, y, test_size=0.25, random_state=42, stratify=y
    )
    text_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=500, ngram_range=(1, 2), min_df=1)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    text_pipeline.fit(Xt_train, yt_train)
    text_acc = text_pipeline.score(Xt_test, yt_test)
    print(f"Text model held-out accuracy: {text_acc:.3f}")

    text_path_prefix = os.path.join(ARTIFACT_DIR, "text_model")
    joblib.dump(text_pipeline, f"{text_path_prefix}.joblib")
    save_metadata(text_path_prefix, ModelMetadata(
        model_name="text_tfidf_logreg",
        model_version=TEXT_MODEL_VERSION,
        training_dataset_version=DATASET_VERSION,
        feature_version=FEATURE_VERSION,
        trained_at=datetime.now(timezone.utc).isoformat(),
        algorithm="TfidfVectorizer(max_features=500, ngram_range=(1,2)) + LogisticRegression",
        classes=sorted(set(y)),
    ))

    print("Training complete. Artifacts written to", ARTIFACT_DIR)


if __name__ == "__main__":
    main()
