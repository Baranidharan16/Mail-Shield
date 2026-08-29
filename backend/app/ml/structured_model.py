"""
Model A - structured feature classifier.

Baseline: RandomForestClassifier over the documented feature vector from
`app/ml/features.py`. Random Forest was chosen (per the brief's suggested
options) because it handles the mixed binary/continuous feature vector
well without scaling, and gives usable feature-importance-based
explanations for free - important for Part 4 (Explainable AI).
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

import joblib
import numpy as np

from app.ml.features import FEATURE_NAMES, FeatureVector
from app.ml.model_provider import ARTIFACT_DIR, ModelMetadata, ModelPrediction, load_metadata

_PATH_PREFIX = os.path.join(ARTIFACT_DIR, "structured_model")
_MODEL_NAME = "structured_random_forest"


class StructuredModel:
    def __init__(self) -> None:
        self._model = None
        self._metadata: Optional[ModelMetadata] = None
        self._load()

    def _load(self) -> None:
        model_path = f"{_PATH_PREFIX}.joblib"
        if os.path.exists(model_path):
            try:
                self._model = joblib.load(model_path)
                self._metadata = load_metadata(_PATH_PREFIX)
            except Exception:
                self._model = None
                self._metadata = None

    @property
    def is_available(self) -> bool:
        return self._model is not None and self._metadata is not None

    def predict(self, feature_vector: FeatureVector) -> ModelPrediction:
        if not self.is_available:
            return ModelPrediction(
                available=False,
                model_metadata=None,
                predicted_label=None,
                note="Structured model artifact not found - train via `python -m app.ml.train`. "
                     "Fusion engine will proceed without this component.",
            )

        x = np.array([feature_vector.as_ordered_list()])
        try:
            proba = self._model.predict_proba(x)[0]
            classes = list(self._model.classes_)
            probs = {cls: float(p) for cls, p in zip(classes, proba)}
            predicted_label = classes[int(np.argmax(proba))]
            confidence = float(max(proba))

            # Interpretable contribution: feature importances weighted by this
            # sample's own (nonzero) feature values - an approximate,
            # per-instance interpretation (clearly labeled as such), not a
            # precise SHAP-style decomposition.
            importances = getattr(self._model, "feature_importances_", None)
            top_features: List[Dict[str, object]] = []
            if importances is not None:
                contributions = []
                for name, val, imp in zip(FEATURE_NAMES, feature_vector.as_ordered_list(), importances):
                    if val > 0:
                        contributions.append((name, val, float(imp)))
                contributions.sort(key=lambda t: t[2], reverse=True)
                top_features = [
                    {"feature": name, "value": val, "importance": imp}
                    for name, val, imp in contributions[:8]
                ]

            return ModelPrediction(
                available=True,
                model_metadata=self._metadata,
                predicted_label=predicted_label,
                class_probabilities=probs,
                confidence=confidence,
                top_features=top_features,
                note="Feature importances are approximate per-instance interpretation, not exact SHAP values.",
            )
        except Exception as exc:  # noqa: BLE001
            return ModelPrediction(
                available=False,
                model_metadata=self._metadata,
                predicted_label=None,
                note=f"Structured model inference failed ({type(exc).__name__}); fusion proceeds without it.",
            )


_singleton: Optional[StructuredModel] = None


def get_structured_model() -> StructuredModel:
    global _singleton
    if _singleton is None:
        _singleton = StructuredModel()
    return _singleton


def reset_structured_model_cache() -> None:
    """Used by training scripts/tests after (re)writing the artifact to disk."""
    global _singleton
    _singleton = None
