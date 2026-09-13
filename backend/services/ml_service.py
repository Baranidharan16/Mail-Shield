"""
MailShield - ML Phishing Detection Model Service
Loads and executes inference on the trained MailShield Keras ML model.
"""
from __future__ import annotations

import os
import builtins
import logging
from pathlib import Path
from typing import Optional

# Ensure UTF-8 decoding for model internal vocabulary files on Windows
_orig_open = builtins.open
def _utf8_open(*args, **kwargs):
    mode = kwargs.get("mode", args[1] if len(args) > 1 else "")
    if "b" not in mode and kwargs.get("encoding") is None:
        kwargs["encoding"] = "utf-8"
    return _orig_open(*args, **kwargs)

builtins.open = _utf8_open

os.environ["PYTHONUTF8"] = "1"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

# keras and tensorflow are loaded lazily inside MLService.load()
# so the backend starts successfully even without TF/Keras installed.

from schemas.analysis import MLAnalysisResult

logger = logging.getLogger("mailshield.ml_service")


class MLService:
    def __init__(self, model_path: Optional[str] = None):
        if model_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            model_path = str(base_dir / "models" / "mailshield_ml.keras")
        self.model_path = model_path
        self.model = None
        self._is_loaded = False

    def load(self) -> None:
        """Loads the Keras ML model into memory once."""
        if not Path(self.model_path).exists():
            logger.error("ML model file not found at: %s", self.model_path)
            raise FileNotFoundError(f"ML model file not found at {self.model_path}")

        try:
            import keras as _keras  # lazy import — TF/Keras not required at startup
            logger.info("Loading MailShield ML model from: %s", self.model_path)
            self.model = _keras.models.load_model(self.model_path)
            self._is_loaded = True
            logger.info("MailShield ML model successfully loaded into memory.")
        except ImportError:
            logger.error("Keras is not installed. ML predictions will be unavailable.")
            raise

    def is_loaded(self) -> bool:
        return self._is_loaded and self.model is not None

    def predict(self, text: str) -> MLAnalysisResult:
        """Runs phishing classification on clean email text.
        
        The model contains a built-in TextVectorization layer expecting string inputs.
        """
        if not self._is_loaded or self.model is None:
            raise RuntimeError("ML model has not been loaded. Check startup logs.")

        if not text or not text.strip():
            text = "Empty email body"

        import tensorflow as tf  # lazy import
        # Model expects a 1D tensor of strings: shape (batch_size,)
        input_tensor = tf.constant([text], dtype=tf.string)
        raw_pred = self.model.predict(input_tensor, verbose=0)
        
        # Raw prediction is shape (1, 1) with sigmoid output [0.0 - 1.0]
        prob = float(raw_pred[0][0])
        prob = max(0.0, min(1.0, prob))

        prediction = "phishing" if prob >= 0.50 else "legitimate"
        confidence = prob if prob >= 0.50 else (1.0 - prob)

        return MLAnalysisResult(
            prediction=prediction,
            phishing_probability=round(prob, 4),
            confidence=round(confidence, 4),
        )


# Global singleton
_ml_service: Optional[MLService] = None


def get_ml_service() -> MLService:
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService()
    return _ml_service
