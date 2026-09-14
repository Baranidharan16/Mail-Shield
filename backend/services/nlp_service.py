"""
MailShield - NLP Threat-Pattern Classifier Service
Loads and executes multi-label threat pattern inference on the trained MailShield NLP model.

Architecture: TextVectorization → Embedding → BiLSTM → Dense(64) → Dense(6, sigmoid)
Input : tf.constant([raw_text_string], dtype=tf.string)   # shape (1,)
Output: shape (1, 6) — sigmoid probabilities for 6 threat categories

Labels (in order):
  0 urgency               — time-pressure / urgency language
  1 credential_request    — request for passwords / credentials
  2 financial_manipulation— financial lure / manipulation
  3 impersonation         — impersonating a known entity
  4 threat_language       — threatening consequences
  5 suspicious_action     — suspicious call-to-action (click link, download, etc.)

NOTE ON WINDOWS / CODEC:
  PYTHONUTF8=1 is set at the very top of main.py before any import so that Keras
  reads internal vocabulary files with UTF-8 rather than the Windows cp1252 codec.
  The builtins.open monkey-patch that used to live here has been removed because
  Keras 3.x on Python 3.13 bypasses builtins.open for zip-member I/O.
"""
from __future__ import annotations

import logging
import traceback
from pathlib import Path
from typing import Optional

from schemas.analysis import NLPAnalysisResult

logger = logging.getLogger("mailshield.nlp_service")

# The 6 threat pattern labels in order of the MailShield NLP model outputs
THREAT_LABELS = [
    "urgency",
    "credential_request",
    "financial_manipulation",
    "impersonation",
    "threat_language",
    "suspicious_action",
]


class NLPService:
    def __init__(self, model_path: Optional[str] = None, metadata_path: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent.parent

        if model_path is None:
            v2_path = base_dir / "models" / "MailShield_NLP_v2.keras"
            if v2_path.exists():
                model_path = str(v2_path)
            else:
                model_path = str(base_dir / "models" / "mailshield_nlp.keras")
        self.model_path = model_path

        if metadata_path is None:
            v2_meta = base_dir / "models" / "MailShield_NLP_v2_metadata.json"
            if v2_meta.exists():
                metadata_path = str(v2_meta)
        self.metadata_path = metadata_path

        self.threat_categories = [
            "credential_theft",
            "impersonation",
            "urgency",
            "financial_manipulation",
            "threat_extortion",
            "suspicious_action",
        ]
        self.thresholds = {
            "credential_theft": 0.14,
            "impersonation": 0.49,
            "urgency": 0.40,
            "financial_manipulation": 0.64,
            "threat_extortion": 0.33,
            "suspicious_action": 0.47,
        }
        self.model_name = Path(self.model_path).name
        self._load_metadata()

        self.model = None
        self._is_loaded = False
        self._load_error: Optional[str] = None  # preserved for /health/ml

    def _load_metadata(self) -> None:
        """Loads categories and thresholds from metadata JSON if available."""
        if self.metadata_path and Path(self.metadata_path).exists():
            try:
                import json
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "threat_categories" in data:
                        self.threat_categories = list(data["threat_categories"])
                    if "thresholds" in data:
                        self.thresholds = {k: float(v) for k, v in data["thresholds"].items()}
                    if "model_name" in data:
                        self.model_name = str(data["model_name"])
                    logger.info("Loaded NLP metadata for %s: categories=%s", self.model_name, self.threat_categories)
            except Exception as e:
                logger.warning("Could not read NLP metadata from %s: %s", self.metadata_path, e)

    def load(self) -> None:
        """Loads the Keras NLP threat pattern model into memory once.

        Raises FileNotFoundError if the model file is missing.
        Raises (and logs with full traceback) any Keras/TF loading exception.
        """
        if not Path(self.model_path).exists():
            msg = f"NLP model file not found at {self.model_path}"
            logger.error(msg)
            self._load_error = msg
            raise FileNotFoundError(msg)

        try:
            import mailshield_codec_fix  # noqa: F401
            import keras as _keras  # lazy import — TF/Keras not required at startup
            logger.info("Loading MailShield NLP model from: %s", self.model_path)
            self.model = _keras.models.load_model(self.model_path)
            self._is_loaded = True
            self._load_error = None
            logger.info("MailShield NLP model %s loaded successfully into memory.", self.model_name)
        except ImportError:
            self._load_error = "Keras is not installed."
            logger.error("Keras is not installed. NLP predictions will be unavailable.")
            raise
        except Exception:
            # Preserve the FULL traceback in logs so the original Keras error is
            # always visible in development mode — never silently swallowed.
            tb = traceback.format_exc()
            self._load_error = tb
            logger.error(
                "Failed to load NLP model from %s.\n"
                "Full traceback:\n%s",
                self.model_path,
                tb,
            )
            raise

    def is_loaded(self) -> bool:
        return self._is_loaded and self.model is not None

    def predict(self, text: str) -> NLPAnalysisResult:
        """Runs multi-label threat pattern inference on email text.

        The model accepts raw string inputs via its built-in TextVectorization layer.
        No external tokenizer or vectorizer is required.
        """
        if not self._is_loaded or self.model is None:
            raise RuntimeError(
                "NLP model has not been loaded. Check startup logs for the exact Keras error."
            )

        if not text or not text.strip():
            text = "Empty email body"

        import tensorflow as tf  # lazy import
        # Model expects a 1-D tensor of strings: shape (batch_size,) = (1,)
        input_tensor = tf.constant([text], dtype=tf.string)
        raw_pred = self.model.predict(input_tensor, verbose=0)

        # Raw prediction is shape (1, 6) with sigmoid values [0.0 – 1.0]
        preds = raw_pred[0]

        def _clip(v: float) -> float:
            return round(max(0.0, min(1.0, float(v))), 4)

        # Map predictions based on dynamically configured category order
        cat_map = {cat: float(p) for cat, p in zip(self.threat_categories, preds)}

        urgency = cat_map.get("urgency", float(preds[2]) if len(preds) > 2 else 0.0)
        credential_request = (
            cat_map.get("credential_theft")
            or cat_map.get("credential_request")
            or (float(preds[0]) if len(preds) > 0 else 0.0)
        )
        financial_manipulation = cat_map.get(
            "financial_manipulation", float(preds[3]) if len(preds) > 3 else 0.0
        )
        impersonation = cat_map.get(
            "impersonation", float(preds[1]) if len(preds) > 1 else 0.0
        )
        threat_language = (
            cat_map.get("threat_extortion")
            or cat_map.get("threat_language")
            or (float(preds[4]) if len(preds) > 4 else 0.0)
        )
        suspicious_action = cat_map.get(
            "suspicious_action", float(preds[5]) if len(preds) > 5 else 0.0
        )

        return NLPAnalysisResult(
            urgency=_clip(urgency),
            credential_request=_clip(credential_request),
            financial_manipulation=_clip(financial_manipulation),
            impersonation=_clip(impersonation),
            threat_language=_clip(threat_language),
            suspicious_action=_clip(suspicious_action),
        )


# Global singleton
_nlp_service: Optional[NLPService] = None


def get_nlp_service() -> NLPService:
    global _nlp_service
    if _nlp_service is None:
        _nlp_service = NLPService()
    return _nlp_service
