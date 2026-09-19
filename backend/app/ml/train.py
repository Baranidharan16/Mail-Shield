"""
MailShield model training pipeline (v2 — real data).

    data validation -> cleaning/dedup -> feature engineering (the SAME forensic
    engine used in production) -> stratified train/val/test split ->
    training (class-imbalance aware) -> threshold selection on VALIDATION ->
    evaluation on untouched TEST -> versioned artifacts -> deployment.

Usage (from backend/):

    python -m app.ml.train --phish DIR [--phish DIR ...] --ham DIR [--ham DIR ...] \
                           [--hard-ham DIR] --version 2.0.0

Each DIR holds one raw RFC-822 message per file (.eml / .txt / no extension).
Artifacts are written to app/ml/artifacts/ (active) and
app/ml/artifacts/versions/<version>/ (immutable copy) together with a
metrics JSON so every deployed model is traceable to its evaluation.

Why the v1 models were inaccurate
---------------------------------
v1 was trained on 240 template-generated SYNTHETIC e-mails (30 per class,
8 classes) produced by app/ml/dataset.py. The models memorised template
wording, the 8 labels were not separable in real mail, and the fusion
engine then turned a hard label into a fixed score — so predictions on real
e-mail were close to arbitrary. v2 trains a binary THREAT / LEGITIMATE
model on real, publicly available corpora and outputs a calibrated
probability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from app.forensic.engine import run_forensic_analysis
from app.ml.features import FEATURE_NAMES, FEATURE_VERSION, build_feature_vector, feature_text_blob
from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, save_metadata
from app.ml.text_preprocess import normalize_batch

LABELS = ("LEGITIMATE", "PHISHING")
MAX_BYTES = 5 * 1024 * 1024

# The structured ML model only receives CONTENT / LINK / ATTACHMENT / LEXICAL-DOMAIN
# features. Header, authentication and routing features are deliberately
# excluded because in every public corpus available they encode *collection
# era / mailbox provider* rather than maliciousness (e.g. 2002 SpamAssassin
# ham predates DKIM/DMARC, mailing-list ham always carries list Return-Paths,
# Enron ham has no transport headers at all). Those signals are handled by the
# deterministic rule engine and the forensic agent instead — explicitly, with
# evidence — rather than being learned from confounded data.
ML_FEATURE_WHITELIST: List[str] = [
    "from_replyto_mismatch", "display_name_domain_impersonation", "exec_title_freemail",
    "any_domain_punycode", "any_domain_suspicious_tld", "any_domain_excessive_hyphenation",
    "max_domain_lookalike_similarity",
    "url_count", "any_url_ip_based", "any_url_shortened", "any_url_punycode", "any_url_suspicious_tld",
    "any_url_anchor_mismatch", "any_url_suspicious_query", "avg_url_risk_score", "max_url_risk_score", "link_density",
    "urgency_present", "fear_threat_present", "credential_request_present", "payment_request_present",
    "account_verification_present", "password_reset_pressure_present", "executive_impersonation_present",
    "invoice_payment_diversion_present", "suspicious_cta_present", "social_engineering_indicator_count",
    "social_engineering_max_confidence",
    "attachment_count", "has_executable_attachment", "has_macro_office_attachment", "has_archive_attachment",
    "has_html_attachment", "has_double_extension_attachment",
    "subject_caps_ratio", "subject_has_exclamation", "has_form_or_script_html",
]
EXCLUDED_FROM_ML: Dict[str, str] = {
    f: "header/routing/formatting artefact of the training corpora (handled by the rule engine)"
    for f in FEATURE_NAMES if f not in ML_FEATURE_WHITELIST
}
ML_FEATURES: List[str] = [f for f in FEATURE_NAMES if f not in EXCLUDED_FROM_ML]


# ── 1. data validation + cleaning ───────────────────────────────────────────
def _load_dir(path: str) -> List[bytes]:
    out = []
    for p in sorted(Path(path).rglob("*")):
        if not p.is_file() or p.suffix.lower() in {".json", ".md", ".yml"}:
            continue
        b = p.read_bytes()
        if 0 < len(b) <= MAX_BYTES:
            out.append(b)
    return out


def _extract(raws: List[bytes], label: str, group: str, seen: set) -> Tuple[list, list, list, list, int]:
    Xs, Xt, y, g = [], [], [], []
    rejected = 0
    for raw in raws:
        try:
            result = run_forensic_analysis(raw)
        except Exception:
            rejected += 1
            continue
        text = feature_text_blob(result)
        if len(text.strip()) < 20:          # nothing to learn from
            rejected += 1
            continue
        key = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
        if key in seen:                      # exact-duplicate removal => no train/test leakage
            rejected += 1
            continue
        seen.add(key)
        fv = build_feature_vector(result).values
        Xs.append([float(fv.get(n, 0.0)) for n in ML_FEATURES])
        Xt.append(text)
        y.append(1 if label == "PHISHING" else 0)
        g.append(group)
    return Xs, Xt, y, g, rejected


# ── 3. metrics ───────────────────────────────────────────────────────────────
def _metrics(y_true, proba, threshold) -> dict:
    y_true = np.asarray(y_true)
    pred = (np.asarray(proba) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 4),
        "n": int(len(y_true)),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, proba)), 4) if len(set(y_true)) > 1 else None,
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "false_negative_rate": round(float(fn / (fn + tp)) if (fn + tp) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def _choose_threshold(y_val, proba_val, max_fpr: float = 0.02) -> float:
    """Highest-F1 threshold whose validation FPR stays <= max_fpr (not accuracy)."""
    y_val = np.asarray(y_val)
    best_t, best_f1 = 0.5, -1.0
    for t in np.linspace(0.05, 0.95, 91):
        pred = (proba_val >= t).astype(int)
        fp = int(((pred == 1) & (y_val == 0)).sum())
        tn = int(((pred == 0) & (y_val == 0)).sum())
        fpr = fp / (fp + tn) if (fp + tn) else 0
        f1 = f1_score(y_val, pred, zero_division=0)
        if fpr <= max_fpr and f1 > best_f1:
            best_t, best_f1 = float(t), f1
    return best_t


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phish", action="append", required=True)
    ap.add_argument("--ham", action="append", required=True)
    ap.add_argument("--hard-ham", action="append", default=[], help="legitimate marketing/newsletter mail (hard negatives)")
    ap.add_argument("--text-ham", action="append", default=[],
                    help="legitimate mail with body text but no transport headers (e.g. Enron); used for content features only")
    ap.add_argument("--version", default="2.0.0")
    ap.add_argument("--dataset-name", default="phishing_pot+spamassassin_ham")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    seen: set = set()
    Xs, Xt, y, g = [], [], [], []
    report = {}
    for label, dirs, group in (("PHISHING", args.phish, "phish"), ("LEGITIMATE", args.ham, "ham"),
                               ("LEGITIMATE", args.hard_ham, "hard_ham")):
        for d in dirs:
            raws = _load_dir(d)
            a, b, c, e, rej = _extract(raws, label, group, seen)
            Xs += a; Xt += b; y += c; g += e
            report[d] = {"label": label, "files": len(raws), "kept": len(a), "rejected_or_duplicate": rej}
            print(f"[data] {d}: {len(raws)} files -> kept {len(a)} ({rej} rejected/duplicate)")

    Xs, y, g = np.asarray(Xs), np.asarray(y), np.asarray(g)
    idx = np.arange(len(y))
    strat = np.char.add(g.astype(str), y.astype(str))
    i_train, i_tmp = train_test_split(idx, test_size=0.30, random_state=args.seed, stratify=strat)
    i_val, i_test = train_test_split(i_tmp, test_size=0.50, random_state=args.seed, stratify=strat[i_tmp])
    T = lambda ii: [Xt[i] for i in ii]  # noqa: E731
    print(f"[split] train={len(i_train)} val={len(i_val)} test={len(i_test)}  phishing share={y.mean():.2%}")

    # header-less legitimate corpus (e.g. Enron): used by the text model and, since the structured
    # model only sees content features, by the structured model too
    Xt_extra, Xs_extra = [], []
    for d in args.text_ham:
        raws = _load_dir(d)
        a_, b, _, _, rej = _extract(raws, "LEGITIMATE", "text_ham", seen)
        Xt_extra += b
        Xs_extra += a_
        report[d] = {"label": "LEGITIMATE (text model only)", "files": len(raws), "kept": len(b), "rejected_or_duplicate": rej}
        print(f"[data] {d}: {len(raws)} files -> kept {len(b)} (text model only)")
    e_idx = np.arange(len(Xt_extra))
    if len(e_idx):
        e_train, e_tmp = train_test_split(e_idx, test_size=0.30, random_state=args.seed)
        e_val, e_test = train_test_split(e_tmp, test_size=0.50, random_state=args.seed)
    else:
        e_train = e_val = e_test = e_idx
    E = lambda ii: [Xt_extra[i] for i in ii]  # noqa: E731

    # ── structured model: RF (balanced) + isotonic calibration ─────────────
    rf = RandomForestClassifier(n_estimators=300, max_depth=14, min_samples_leaf=3,
                                class_weight="balanced", n_jobs=-1, random_state=args.seed)
    struct = CalibratedClassifierCV(rf, method="isotonic", cv=3)
    # Hard negatives (legitimate marketing/newsletters) are up-weighted: they are
    # the most common source of false positives in real mailboxes.
    w_train = np.where(g[i_train] == "hard_ham", 3.0, 1.0)
    XE = np.asarray(Xs_extra) if len(Xs_extra) else np.zeros((0, Xs.shape[1]))
    struct.fit(np.vstack([Xs[i_train], XE[e_train]]) if len(XE) else Xs[i_train],
               np.concatenate([y[i_train], np.zeros(len(e_train), dtype=int)]),
               sample_weight=np.concatenate([w_train, np.ones(len(e_train))]))
    ys_val = np.concatenate([y[i_val], np.zeros(len(e_val), dtype=int)])
    ys_test = np.concatenate([y[i_test], np.zeros(len(e_test), dtype=int)])
    s_val = struct.predict_proba(np.vstack([Xs[i_val], XE[e_val]]) if len(XE) else Xs[i_val])[:, 1]
    s_thr = _choose_threshold(ys_val, s_val)
    s_test = struct.predict_proba(np.vstack([Xs[i_test], XE[e_test]]) if len(XE) else Xs[i_test])[:, 1]
    s_test_business = s_test[len(i_test):]

    # ── text/NLP model: normalised TF-IDF word+bigram -> balanced LR ────────
    text = Pipeline([
        ("normalize", FunctionTransformer(normalize_batch)),
        ("tfidf", TfidfVectorizer(max_features=30000, ngram_range=(1, 2), min_df=3, max_df=0.9,
                                  sublinear_tf=True, strip_accents="unicode")),
        ("clf", LogisticRegression(max_iter=3000, C=2.0, class_weight="balanced")),
    ])
    yt_train = np.concatenate([y[i_train], np.zeros(len(e_train), dtype=int)])
    yt_val = np.concatenate([y[i_val], np.zeros(len(e_val), dtype=int)])
    yt_test = np.concatenate([y[i_test], np.zeros(len(e_test), dtype=int)])
    text.fit(T(i_train) + E(e_train), yt_train,
             clf__sample_weight=np.concatenate([w_train, np.ones(len(e_train))]))
    t_val = text.predict_proba(T(i_val) + E(e_val))[:, 1]
    t_thr = _choose_threshold(yt_val, t_val)
    t_test = text.predict_proba(T(i_test) + E(e_test))[:, 1]
    t_test_business = t_test[len(i_test):]

    hard = np.where(g[i_test] == "hard_ham")[0]
    metrics = {
        "dataset": args.dataset_name, "sources": report, "seed": args.seed,
        "split": {"train": int(len(i_train)), "validation": int(len(i_val)), "test": int(len(i_test)),
                  "text_only_ham": {"train": int(len(e_train)), "validation": int(len(e_val)), "test": int(len(e_test))}},
        "excluded_features": EXCLUDED_FROM_ML,
        "structured_model": {"test": _metrics(ys_test, s_test, s_thr),
                             "hard_ham_false_positive_rate": round(float((s_test[hard] >= s_thr).mean()), 4) if len(hard) else None,
                             "business_ham_false_positive_rate": round(float((s_test_business >= s_thr).mean()), 4) if len(s_test_business) else None},
        "text_model": {"test": _metrics(yt_test, t_test, t_thr),
                       "hard_ham_false_positive_rate": round(float((t_test[hard] >= t_thr).mean()), 4) if len(hard) else None,
                       "business_ham_false_positive_rate": round(float((t_test_business >= t_thr).mean()), 4) if len(t_test_business) else None},
    }
    print(json.dumps({k: metrics[k] for k in ("structured_model", "text_model")}, indent=2))

    # ── versioned artifacts ──────────────────────────────────────────────────
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    ds_version = f"{args.dataset_name}@{len(y)}"
    for name, model, thr, algo, feats in (
        ("structured_model", struct, s_thr,
         "CalibratedClassifierCV(RandomForestClassifier(n_estimators=300, max_depth=14, class_weight='balanced'), isotonic)",
         ML_FEATURES),
        ("text_model", text, t_thr,
         "normalize_text -> TfidfVectorizer(1-2gram, 30k) -> LogisticRegression(class_weight='balanced')", None),
    ):
        prefix = os.path.join(ARTIFACT_DIR, name)
        joblib.dump(model, f"{prefix}.joblib", compress=3)
        save_metadata(prefix, ModelMetadata(
            model_name=f"{name}_binary", model_version=args.version,
            training_dataset_version=ds_version, feature_version=FEATURE_VERSION,
            trained_at=now, algorithm=algo, classes=list(LABELS)))
        extra = {"threshold": thr, "features": feats}
        with open(f"{prefix}.extra.json", "w", encoding="utf-8") as fh:
            json.dump(extra, fh, indent=2)
    with open(os.path.join(ARTIFACT_DIR, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    vdir = os.path.join(ARTIFACT_DIR, "versions", args.version)
    os.makedirs(vdir, exist_ok=True)
    for f in os.listdir(ARTIFACT_DIR):
        fp = os.path.join(ARTIFACT_DIR, f)
        if os.path.isfile(fp):
            shutil.copy2(fp, vdir)
    print("Artifacts written to", ARTIFACT_DIR, "and", vdir)


if __name__ == "__main__":
    main()
