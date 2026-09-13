"""
MailShield - NLP Threat-Pattern Classifier Service
Loads and executes multi-label threat pattern inference on the trained MailShield NLP model.
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

# keras and tensorflow are loaded lazily inside NLPService.load()
# so the backend starts successfully even without TF/Keras installed.

from schemas.analysis import NLPAnalysisResult

logger = logging.getLogger("mailshield.nlp_service")

# The 6 threat pattern labels in order of the MailShield threat model
THREAT_LABELS = [
    "urgency",
    "credential_request",
    "financial_manipulation",
    "impersonation",
    "threat_language",
    "suspicious_action",
]


class NLPService:
    def __init__(self, model_path: Optional[str] = None):
        if model_path is None:
            base_dir = Path(__file__).resolve().parent.parent
            model_path = str(base_dir / "models" / "mailshield_nlp.keras")
        self.model_path = model_path
        self.model = None
        self._is_loaded = False

    def load(self) -> None:
        """Loads the Keras NLP threat pattern model into memory once."""
        if not Path(self.model_path).exists():
            logger.error("NLP model file not found at: %s", self.model_path)
            raise FileNotFoundError(f"NLP model file not found at {self.model_path}")

        try:
            import keras as _keras  # lazy import — TF/Keras not required at startup
            logger.info("Loading MailShield NLP model from: %s", self.model_path)
            self.model = _keras.models.load_model(self.model_path)
            self._is_loaded = True
            logger.info("MailShield NLP model successfully loaded into memory.")
        except ImportError:
            logger.error("Keras is not installed. NLP predictions will be unavailable.")
            raise

    def is_loaded(self) -> bool:
        return self._is_loaded and self.model is not None

    def predict(self, text: str) -> NLPAnalysisResult:
        """Runs multi-label threat pattern inference on email text."""
        if not self._is_loaded or self.model is None:
            raise RuntimeError("NLP model has not been loaded. Check startup logs.")

        if not text or not text.strip():
            text = "Empty email body"

        import tensorflow as tf  # lazy import
        # Model expects a 1D tensor of strings: shape (batch_size,)
        input_tensor = tf.constant([text], dtype=tf.string)
        raw_pred = self.model.predict(input_tensor, verbose=0)

        # Raw prediction is shape (1, 6) with sigmoid values [0.0 - 1.0]
        preds = raw_pred[0]

        # Extract values for the 6 labels
        urgency = float(preds[0])
        credential_request = float(preds[1])
        financial_manipulation = float(preds[2])
        impersonation = float(preds[3])
        threat_language = float(preds[4])
        suspicious_action = float(preds[5])

        return NLPAnalysisResult(
            urgency=round(max(0.0, min(1.0, urgency)), 4),
            credential_request=round(max(0.0, min(1.0, credential_request)), 4),
            financial_manipulation=round(max(0.0, min(1.0, financial_manipulation)), 4),
            impersonation=round(max(0.0, min(1.0, impersonation)), 4),
            threat_language=round(max(0.0, min(1.0, threat_language)), 4),
            suspicious_action=round(max(0.0, min(1.0, suspicious_action)), 4),
        )


# Global singleton
_nlp_service: Optional[NLPService] = None


def get_nlp_service() -> NLPService:
    global _nlp_service
    if _nlp_service is None:
        _nlp_service = NLPService()
    return _nlp_service
