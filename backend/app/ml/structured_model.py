"""
Model A - structured (forensic-feature) classifier, v2.

Calibrated RandomForest over the documented feature vector from
app/ml/features.py, trained on real phishing / legitimate corpora by
`python -m app.ml.train`. Outputs a calibrated THREAT probability and the
decision threshold chosen on the validation split (stored in
structured_model.extra.json), so inference uses exactly the training-time
feature list and threshold.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

import joblib
import numpy as np

from app.ml.features import FEATURE_DOCS, FEATURE_NAMES, FeatureVector
from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, ModelPrediction, load_metadata

_PATH_PREFIX = os.path.join(ARTIFACT_DIR, "structured_model")


def _load_extra(prefix: str) -> dict:
    try:
        with open(f"{prefix}.extra.json", "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


class StructuredModel:
    def __init__(self) -> None:
        self._model = None
        self._metadata: Optional[ModelMetadata] = None
        self._features: List[str] = FEATURE_NAMES
        self.threshold: float = 0.5
        self._importances: Optional[np.ndarray] = None
        self._load()

    def _load(self) -> None:
        model_path = f"{_PATH_PREFIX}.joblib"
        if not os.path.exists(model_path):
            return
        try:
            self._model = joblib.load(model_path)
            self._metadata = load_metadata(_PATH_PREFIX)
            extra = _load_extra(_PATH_PREFIX)
            self._features = extra.get("features") or FEATURE_NAMES
            self.threshold = float(extra.get("threshold", 0.5))
            imps = []
            for cc in getattr(self._model, "calibrated_classifiers_", []):
                est = getattr(cc, "estimator", None)
                if est is not None and hasattr(est, "feature_importances_"):
                    imps.append(est.feature_importances_)
            if imps:
                self._importances = np.mean(imps, axis=0)
            elif hasattr(self._model, "feature_importances_"):
                self._importances = self._model.feature_importances_
        except Exception:
            self._model = None
            self._metadata = None

    @property
    def is_available(self) -> bool:
        return self._model is not None and self._metadata is not None

    def predict(self, feature_vector: FeatureVector) -> ModelPrediction:
        if not self.is_available:
            return ModelPrediction(
                available=False, model_metadata=None, predicted_label=None,
                note="Structured model artifact not found - train via `python -m app.ml.train`. "
                     "Fusion engine will proceed without this component.",
            )
        values = feature_vector.as_dict()
        row = [float(values.get(n, 0.0)) for n in self._features]
        try:
            p_threat = float(self._model.predict_proba(np.array([row]))[0][1])
            label = "PHISHING" if p_threat >= self.threshold else "LEGITIMATE"
            top: List[Dict[str, object]] = []
            if self._importances is not None:
                contrib = [(n, v, float(i)) for n, v, i in zip(self._features, row, self._importances) if v > 0]
                contrib.sort(key=lambda t: t[2], reverse=True)
                top = [{"feature": n, "value": round(v, 3), "importance": round(i, 4),
                        "meaning": FEATURE_DOCS.get(n, "")} for n, v, i in contrib[:8]]
            return ModelPrediction(
                available=True, model_metadata=self._metadata, predicted_label=label,
                class_probabilities={"PHISHING": round(p_threat, 4), "LEGITIMATE": round(1 - p_threat, 4)},
                confidence=round(max(p_threat, 1 - p_threat), 4),
                top_features=top,
                note=f"Calibrated threat probability; decision threshold {self.threshold:.2f} chosen on the "
                     "validation split (max F1 at <=2% false-positive rate). Feature list is the importance-"
                     "weighted set of this message's active features (approximate, not SHAP).",
            )
        except Exception as exc:  # noqa: BLE001
            return ModelPrediction(
                available=False, model_metadata=self._metadata, predicted_label=None,
                note=f"Structured model inference failed ({type(exc).__name__}); fusion proceeds without it.",
            )


_singleton: Optional[StructuredModel] = None


def get_structured_model() -> StructuredModel:
    global _singleton
    if _singleton is None:
        _singleton = StructuredModel()
    return _singleton


def reset_structured_model_cache() -> None:
    global _singleton
    _singleton = None
