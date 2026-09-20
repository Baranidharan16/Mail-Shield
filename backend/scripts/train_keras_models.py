"""
Retrain the MailShield Keras models on a NEW / larger email dataset.

    cd backend
    pip install tensorflow keras pandas          # training machine only
    python scripts/train_keras_models.py --data path/to/emails1.csv path/to/emails2.csv
    python scripts/export_keras_lite.py          # -> models/*.npz used in production

Datasets
--------
Any CSV with an email-text column and a 0/1 (or text) label column works;
columns are auto-detected (text/body/Email Text/content + label/Email Type/
class/spam). Good public sources to combine with the original 7 corpora:

  * Kaggle "Phishing Email Dataset" (naserabdullahalam) – CEAS, Enron, Ling,
    Nazario, Nigerian Fraud, SpamAssassin (what v2 was trained on)
  * Kaggle "Phishing Emails" (subhajournal)            – ~18.6k labelled emails
  * HuggingFace "zefang-liu/phishing-email-dataset"      – ~18.7k emails
  * HuggingFace "cybersectony/PhishingEmailDetectionv2.0"
  * Your OWN recent phishing + legitimate mail exported from MailShield
    (most valuable: it matches what the app sees in real time).

Outputs (same architecture as v2, so the NumPy Keras-Lite runtime stays
compatible):
  models/Mailshield_phishing_model_v2.keras  + _metadata.json
  models/MailShield_NLP_v2.keras             + _metadata.json
The previous files are copied to models/backup_<timestamp>/ first.

The NLP model's 6 threat-pattern labels are produced by weak supervision
(MailShield's keyword scorer applied to each phishing email) because no
public corpus is annotated per threat pattern - this is recorded in the
metadata so the provenance stays honest.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parent.parent
MODELS = BACKEND / "models"
sys.path.insert(0, str(BACKEND))

TEXT_COLS = ["text", "body", "email text", "email_text", "content", "message", "email", "text_combined"]
SUBJECT_COLS = ["subject", "title"]
LABEL_COLS = ["label", "email type", "email_type", "class", "spam", "is_phishing", "phishing", "category"]
POSITIVE = {"1", "phishing", "phishing email", "spam", "fraud", "malicious", "true", "yes", "scam"}
NLP_CATEGORIES = ["credential_theft", "impersonation", "urgency", "financial_manipulation",
                  "threat_extortion", "suspicious_action"]


def _pick(cols, wanted):
    low = {c.lower().strip(): c for c in cols}
    return next((low[w] for w in wanted if w in low), None)


def load_datasets(paths):
    import pandas as pd
    frames = []
    for p in paths:
        df = pd.read_csv(p, encoding_errors="replace", on_bad_lines="skip", low_memory=False)
        tcol, lcol, scol = _pick(df.columns, TEXT_COLS), _pick(df.columns, LABEL_COLS), _pick(df.columns, SUBJECT_COLS)
        if not tcol or not lcol:
            raise SystemExit(f"{p}: could not find text/label columns in {list(df.columns)}")
        text = df[tcol].fillna("").astype(str)
        if scol and scol != tcol:
            text = df[scol].fillna("").astype(str) + "\n" + text
        y = df[lcol].astype(str).str.strip().str.lower().isin(POSITIVE).astype("int32")
        frames.append(pd.DataFrame({"text": text, "label": y, "source": Path(p).name}))
        print(f"  {Path(p).name}: {len(df):,} rows  (phishing={int(y.sum()):,})")
    df = pd.concat(frames, ignore_index=True)
    df["text"] = df["text"].map(lambda t: re.sub(r"\s+", " ", t)[:20000])
    df = df[df["text"].str.len() > 20].drop_duplicates("text").sample(frac=1.0, random_state=42)
    print(f"Total after cleaning/dedup: {len(df):,}  phishing={int(df.label.sum()):,}")
    return df


def build_model(keras, texts, n_out, max_tokens, seq_len, emb_dim, units):
    tv = keras.layers.TextVectorization(max_tokens=max_tokens, output_sequence_length=seq_len,
                                        standardize="lower_and_strip_punctuation", split="whitespace")
    tv.adapt(texts, batch_size=1024)
    model = keras.Sequential([
        keras.Input(shape=(1,), dtype="string"),
        tv,
        keras.layers.Embedding(max_tokens, emb_dim, mask_zero=True),
        keras.layers.Bidirectional(keras.layers.LSTM(units)),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation="relu"),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(n_out, activation="sigmoid"),
    ])
    return model


def best_threshold(y, p):
    from sklearn.metrics import f1_score
    grid = np.arange(0.05, 0.96, 0.01)
    scores = [f1_score(y, p >= t, zero_division=0) for t in grid]
    return float(grid[int(np.argmax(scores))])


def backup():
    dst = MODELS / f"backup_{time.strftime('%Y%m%d_%H%M%S')}"
    dst.mkdir(parents=True, exist_ok=True)
    for f in MODELS.glob("*v2*"):
        if f.is_file():
            shutil.copy2(f, dst / f.name)
    print(f"Backed up current models to {dst}")


def train_phishing(keras, tf, df, a):
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    tr, te = train_test_split(df, test_size=0.15, stratify=df.label, random_state=42)
    tr, va = train_test_split(tr, test_size=0.15, stratify=tr.label, random_state=42)
    m = build_model(keras, tf.constant(tr.text.values), 1, a.max_tokens, a.seq_len, 128, 64)
    m.compile(optimizer=keras.optimizers.Adam(1e-3), loss="binary_crossentropy",
              metrics=["accuracy", keras.metrics.AUC(name="auc")])
    m.fit(tf.constant(tr.text.values), tr.label.values, validation_data=(tf.constant(va.text.values), va.label.values),
          epochs=a.epochs, batch_size=a.batch_size,
          callbacks=[keras.callbacks.EarlyStopping(monitor="val_auc", mode="max", patience=2, restore_best_weights=True)])
    thr = best_threshold(va.label.values, m.predict(tf.constant(va.text.values), batch_size=512, verbose=0).ravel())
    p = m.predict(tf.constant(te.text.values), batch_size=512, verbose=0).ravel()
    yhat = p >= thr
    meta = {
        "model_name": "MailShield Phishing Detector", "version": "v2", "framework": "TensorFlow/Keras",
        "tensorflow_version": tf.__version__, "keras_version": keras.__version__,
        "max_tokens": a.max_tokens, "sequence_length": a.seq_len, "embedding_dim": 128, "lstm_units": 64,
        "best_threshold": round(thr, 2),
        "accuracy": accuracy_score(te.label, yhat), "precision": precision_score(te.label, yhat),
        "recall": recall_score(te.label, yhat), "f1": f1_score(te.label, yhat), "roc_auc": roc_auc_score(te.label, p),
        "train_samples": len(tr), "validation_samples": len(va), "test_samples": len(te),
        "label_mapping": {"0": "legitimate", "1": "phishing"},
        "source_datasets": sorted(df.source.unique().tolist()),
        "trained_at": time.strftime("%Y-%m-%d"),
    }
    m.save(MODELS / "Mailshield_phishing_model_v2.keras")
    (MODELS / "Mailshield_phishing_model_v2_metadata.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps({k: meta[k] for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "best_threshold")}, indent=2))


def weak_nlp_labels(df):
    """6 threat-pattern labels via MailShield's keyword scorer (weak supervision)."""
    from services.nlp_service import keyword_nlp_score
    order = {"credential_theft": "credential_request", "impersonation": "impersonation", "urgency": "urgency",
             "financial_manipulation": "financial_manipulation", "threat_extortion": "threat_language",
             "suspicious_action": "suspicious_action"}
    Y = np.zeros((len(df), 6), dtype="float32")
    for i, (t, lab) in enumerate(zip(df.text.values, df.label.values)):
        s = keyword_nlp_score(t).model_dump()
        # legitimate mail keeps weak positives only when the pattern is strong
        cut = 0.4 if lab == 1 else 0.6
        Y[i] = [1.0 if s[order[c]] >= cut else 0.0 for c in NLP_CATEGORIES]
    return Y


def train_nlp(keras, tf, df, a):
    from sklearn.metrics import f1_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    Y = weak_nlp_labels(df)
    Xtr, Xte, Ytr, Yte = train_test_split(df.text.values, Y, test_size=0.15, random_state=42)
    Xtr, Xva, Ytr, Yva = train_test_split(Xtr, Ytr, test_size=0.15, random_state=42)
    m = build_model(keras, tf.constant(Xtr), 6, 15000, 200, 96, 48)
    m.compile(optimizer=keras.optimizers.Adam(1e-3), loss="binary_crossentropy", metrics=[keras.metrics.AUC(name="auc", multi_label=True)])
    m.fit(tf.constant(Xtr), Ytr, validation_data=(tf.constant(Xva), Yva), epochs=a.epochs, batch_size=a.batch_size,
          callbacks=[keras.callbacks.EarlyStopping(monitor="val_auc", mode="max", patience=2, restore_best_weights=True)])
    pva = m.predict(tf.constant(Xva), batch_size=512, verbose=0)
    pte = m.predict(tf.constant(Xte), batch_size=512, verbose=0)
    thr, per = {}, []
    for j, c in enumerate(NLP_CATEGORIES):
        thr[c] = round(best_threshold(Yva[:, j], pva[:, j]), 2) if Yva[:, j].sum() else 0.5
        f1 = f1_score(Yte[:, j], pte[:, j] >= thr[c], zero_division=0)
        auc = roc_auc_score(Yte[:, j], pte[:, j]) if 0 < Yte[:, j].sum() < len(Yte) else None
        per.append({"category": c, "threshold": thr[c], "f1": f1, "roc_auc": auc, "positives_test": int(Yte[:, j].sum())})
    meta = {
        "model_name": "MailShield_NLP_v2", "model_type": "multi_label_text_classification", "framework": "TensorFlow/Keras",
        "threat_categories": NLP_CATEGORIES, "thresholds": thr, "vocabulary_size": 15000, "sequence_length": 200,
        "embedding_dimension": 96, "lstm_units": 48, "batch_size": a.batch_size, "epochs_requested": a.epochs,
        "test_samples": len(Xte), "macro_f1": float(np.mean([p["f1"] for p in per])), "per_category": per,
        "label_source": "weak supervision: MailShield keyword scorer on labelled phishing/legitimate emails",
        "source_datasets": sorted(df.source.unique().tolist()), "trained_at": time.strftime("%Y-%m-%d"),
    }
    m.save(MODELS / "MailShield_NLP_v2.keras")
    (MODELS / "MailShield_NLP_v2_metadata.json").write_text(json.dumps(meta, indent=2))
    print(json.dumps(per, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", nargs="+", required=True, help="one or more labelled email CSV files")
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--max-tokens", type=int, default=20000)
    ap.add_argument("--seq-len", type=int, default=300)
    ap.add_argument("--only", choices=["ml", "nlp"], help="train just one of the two models")
    ap.add_argument("--no-backup", action="store_true")
    a = ap.parse_args()

    import keras
    import tensorflow as tf
    print("Loading datasets...")
    df = load_datasets(a.data)
    if not a.no_backup:
        backup()
    if a.only in (None, "ml"):
        print("\n=== Training phishing detector (BiLSTM) ===")
        train_phishing(keras, tf, df, a)
    if a.only in (None, "nlp"):
        print("\n=== Training NLP threat-pattern model (BiLSTM, 6 labels) ===")
        train_nlp(keras, tf, df, a)
    print("\nDone. Now run:  python scripts/export_keras_lite.py   (creates the .npz files production uses)")


if __name__ == "__main__":
    main()
