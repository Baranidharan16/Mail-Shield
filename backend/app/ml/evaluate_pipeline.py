"""
Evaluate the COMPLETE detection pipeline (forensic rules + ML + NLP + fusion,
exactly as used in production, without live threat-intel lookups) on folders
of labelled raw e-mails that were NOT used for training.

    python -m app.ml.evaluate_pipeline --phish DIR --legit DIR [--threshold 50]

Prints detection metrics for THREAT (score >= 50) and for "flagged"
(SUSPICIOUS or THREAT, score >= 25).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ai.fusion import fuse
from app.forensic.engine import run_forensic_analysis
from app.ml.features import build_feature_vector, feature_text_blob
from app.ml.structured_model import get_structured_model
from app.ml.text_model import get_text_model


def score(raw: bytes) -> float:
    r = run_forensic_analysis(raw)
    s = get_structured_model().predict(build_feature_vector(r))
    t = get_text_model().predict(feature_text_blob(r))
    return fuse(r, s, t).overall_risk_score


def _rates(pos, neg, cut):
    tp = sum(x >= cut for x in pos); fn = len(pos) - tp
    fp = sum(x >= cut for x in neg); tn = len(neg) - fp
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"cut": cut, "tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else 0.0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", required=True)
    ap.add_argument("--legit", required=True)
    a = ap.parse_args()
    load = lambda d: [p.read_bytes() for p in sorted(Path(d).glob("*")) if p.is_file() and p.stat().st_size < 5_000_000]  # noqa: E731
    pos = [score(b) for b in load(a.phish)]
    neg = [score(b) for b in load(a.legit)]
    print(json.dumps({"n_phish": len(pos), "n_legit": len(neg),
                      "threat_band (>=50)": _rates(pos, neg, 50), "flagged (>=25)": _rates(pos, neg, 25)}, indent=2))


if __name__ == "__main__":
    main()
