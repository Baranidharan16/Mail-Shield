"""
Model B - text classifier.

Baseline: TF-IDF + Logistic Regression over subject+body text (per the
brief's suggested baseline). Chosen over a transformer for Phase 2
because it is fast, has no GPU/heavy-dependency requirement, and its
coefficients are directly interpretable per predicted class - which
transformers are not, without extra tooling. The interface is written so
a transformer-based model could be swapped in later without changing any
caller (`ModelProvider`-style contract).
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

import joblib
import numpy as np

from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, ModelPrediction, load_metadata

_PATH_PREFIX = os.path.join(ARTIFACT_DIR, "text_model")
_MODEL_NAME = "text_tfidf_logreg"


class TextModel:
    def __init__(self) -> None:
        self._pipeline = None
        self._metadata: Optional[ModelMetadata] = None
        self._load()

    def _load(self) -> None:
        model_path = f"{_PATH_PREFIX}.joblib"
        if os.path.exists(model_path):
            try:
                self._pipeline = joblib.load(model_path)
                self._metadata = load_metadata(_PATH_PREFIX)
            except Exception:
                self._pipeline = None
                self._metadata = None

    @property
    def is_available(self) -> bool:
        return self._pipeline is not None and self._metadata is not None

    def predict(self, text: str) -> ModelPrediction:
        if not self.is_available:
            return ModelPrediction(
                available=False,
                model_metadata=None,
                predicted_label=None,
                note="Text model artifact not found - train via `python -m app.ml.train`. "
                     "Fusion engine will proceed without this component.",
            )
        if not text or not text.strip():
            return ModelPrediction(
                available=True,
                model_metadata=self._metadata,
                predicted_label=None,
                note="Message had no analyzable text content (empty subject/body).",
            )

        try:
            proba = self._pipeline.predict_proba([text])[0]
            classes = list(self._pipeline.classes_)
            probs = {cls: float(p) for cls, p in zip(classes, proba)}
            predicted_label = classes[int(np.argmax(proba))]
            confidence = float(max(proba))

            top_features = self._top_terms_for_class(text, predicted_label)

            return ModelPrediction(
                available=True,
                model_metadata=self._metadata,
                predicted_label=predicted_label,
                class_probabilities=probs,
                confidence=confidence,
                top_features=top_features,
                note="Top terms are the message's own TF-IDF terms with the highest learned "
                     "coefficient for the predicted class - an approximate, per-instance interpretation.",
            )
        except Exception as exc:  # noqa: BLE001
            return ModelPrediction(
                available=False,
                model_metadata=self._metadata,
                predicted_label=None,
                note=f"Text model inference failed ({type(exc).__name__}); fusion proceeds without it.",
            )

    def _top_terms_for_class(self, text: str, predicted_label: str) -> List[Dict[str, object]]:
        try:
            vectorizer = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]
            x = vectorizer.transform([text])
            feature_names = np.array(vectorizer.get_feature_names_out())
            nonzero_idx = x.nonzero()[1]
            if len(nonzero_idx) == 0:
                return []
            class_idx = list(clf.classes_).index(predicted_label)
            coefs = clf.coef_[class_idx] if clf.coef_.shape[0] > 1 else clf.coef_[0]
            scored = [(feature_names[i], float(x[0, i] * coefs[i])) for i in nonzero_idx]
            scored.sort(key=lambda t: t[1], reverse=True)
            return [{"term": t, "contribution": round(s, 4)} for t, s in scored[:8] if s > 0]
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
