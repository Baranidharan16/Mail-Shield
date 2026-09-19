"""
Model B - NLP text classifier, v2.

normalize_text -> TF-IDF (word 1-2 grams) -> class-balanced LogisticRegression,
trained on real phishing / legitimate corpora (`python -m app.ml.train`).
The normalisation step is stored INSIDE the saved Pipeline, so inference
uses identical preprocessing.

Besides the overall threat probability it returns:
  * the message's own terms that pushed most towards "phishing"
  * the most suspicious sentences (each sentence scored by the same model),
so an e-mail is never labelled malicious because of one isolated word —
the whole-message probability must exceed the validated threshold.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional

import joblib
import numpy as np

from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, ModelPrediction, load_metadata
from app.ml.text_preprocess import normalize_text

_PATH_PREFIX = os.path.join(ARTIFACT_DIR, "text_model")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n{2,}|\r\n\r\n")


class TextModel:
    def __init__(self) -> None:
        self._pipeline = None
        self._metadata: Optional[ModelMetadata] = None
        self.threshold = 0.5
        self._load()

    def _load(self) -> None:
        model_path = f"{_PATH_PREFIX}.joblib"
        if not os.path.exists(model_path):
            return
        try:
            self._pipeline = joblib.load(model_path)
            self._metadata = load_metadata(_PATH_PREFIX)
            try:
                with open(f"{_PATH_PREFIX}.extra.json", "r", encoding="utf-8") as fh:
                    self.threshold = float(json.load(fh).get("threshold", 0.5))
            except Exception:
                pass
        except Exception:
            self._pipeline = None
            self._metadata = None

    @property
    def is_available(self) -> bool:
        return self._pipeline is not None and self._metadata is not None

    def predict(self, text: str) -> ModelPrediction:
        if not self.is_available:
            return ModelPrediction(
                available=False, model_metadata=None, predicted_label=None,
                note="Text model artifact not found - train via `python -m app.ml.train`. "
                     "Fusion engine will proceed without this component.",
            )
        if not text or not text.strip():
            return ModelPrediction(
                available=True, model_metadata=self._metadata, predicted_label=None,
                note="Message had no analyzable text content (empty subject/body).",
            )
        try:
            p = float(self._pipeline.predict_proba([text])[0][1])
            label = "PHISHING" if p >= self.threshold else "LEGITIMATE"
            return ModelPrediction(
                available=True, model_metadata=self._metadata, predicted_label=label,
                class_probabilities={"PHISHING": round(p, 4), "LEGITIMATE": round(1 - p, 4)},
                confidence=round(max(p, 1 - p), 4),
                top_features=self._top_terms(text) + self._suspicious_sentences(text),
                note=f"Whole-message threat probability vs validated threshold {self.threshold:.2f}. "
                     "Terms/sentences show what drove the score (approximate, per-instance).",
            )
        except Exception as exc:  # noqa: BLE001
            return ModelPrediction(
                available=False, model_metadata=self._metadata, predicted_label=None,
                note=f"Text model inference failed ({type(exc).__name__}); fusion proceeds without it.",
            )

    def _top_terms(self, text: str) -> List[Dict[str, object]]:
        try:
            vec = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]
            x = vec.transform([normalize_text(text)])
            names = vec.get_feature_names_out()
            coefs = clf.coef_[0]
            scored = [(names[i], float(x[0, i] * coefs[i])) for i in x.nonzero()[1]]
            scored.sort(key=lambda t: t[1], reverse=True)
            return [{"term": t, "contribution": round(s, 4)} for t, s in scored[:8] if s > 0]
        except Exception:
            return []

    def _suspicious_sentences(self, text: str) -> List[Dict[str, object]]:
        try:
            clean = re.sub(r"<[^>]+>", " ", text)
            sents = [s.strip() for s in _SENT_SPLIT.split(clean) if 25 <= len(s.strip()) <= 400][:60]
            if not sents:
                return []
            probs = self._pipeline.predict_proba(sents)[:, 1]
            ranked = sorted(zip(sents, probs), key=lambda t: t[1], reverse=True)
            return [{"sentence": " ".join(s.split())[:240], "phishing_probability": round(float(pr), 3)}
                    for s, pr in ranked[:3] if pr >= max(0.6, self.threshold)]
        except Exception:
            return []


_singleton: Optional[TextModel] = None


def get_text_model() -> TextModel:
    global _singleton
    if _singleton is None:
        _singleton = TextModel()
    return _singleton


def reset_text_model_cache() -> None:
    global _singleton
    _singleton = None
