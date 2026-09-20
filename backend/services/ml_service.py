"""
MailShield - ML Phishing Detection Model Service
Loads and executes inference on the trained MailShield Keras ML model (v2).

Architecture: TextVectorization(300) → Embedding(128) → BiLSTM → Dense(64) → Dense(1, sigmoid)
Input : tf.constant([raw_text_string], dtype=tf.string)   # shape (1,)
Output: shape (1, 1) — sigmoid probability [0.0 = legitimate, 1.0 = phishing]

Decision threshold: Dynamically loaded from Mailshield_phishing_model_v2_metadata.json (best_threshold: 0.35)
"""
from __future__ import annotations

import json
import logging
import traceback
from pathlib import Path
from typing import Optional

from schemas.analysis import MLAnalysisResult

logger = logging.getLogger("mailshield.ml_service")


class MLService:
    def __init__(
        self,
        model_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
    ):
        base_dir = Path(__file__).resolve().parent.parent

        if model_path is None:
            # Default to Mailshield_phishing_model_v2.keras if present, otherwise mailshield_ml.keras
            v2_path = base_dir / "models" / "Mailshield_phishing_model_v2.keras"
            if v2_path.exists():
                model_path = str(v2_path)
            else:
                model_path = str(base_dir / "models" / "mailshield_ml.keras")
        self.model_path = model_path

        if metadata_path is None:
            metadata_path = str(base_dir / "models" / "Mailshield_phishing_model_v2_metadata.json")
        self.metadata_path = metadata_path

        self.threshold: float = 0.35  # Default threshold from v2 metadata
        self._load_metadata()

        self.model = None
        self._is_loaded = False
        self._backend = "keras"
        self._load_error: Optional[str] = None  # preserved for /health/ml

    def _load_metadata(self) -> None:
        """Loads best threshold from metadata JSON if available."""
        meta_p = Path(self.metadata_path)
        if meta_p.exists():
            try:
                with open(meta_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "best_threshold" in data:
                        self.threshold = float(data["best_threshold"])
                        logger.info(
                            "Configured ML phishing threshold from metadata: %.4f",
                            self.threshold,
                        )
            except Exception as e:
                logger.warning(
                    "Could not read ML metadata from %s: %s. Using default threshold %.2f",
                    self.metadata_path,
                    e,
                    self.threshold,
                )

    def load(self) -> None:
        """Loads the Keras ML model into memory once.

        Raises FileNotFoundError if the model file is missing.
        Raises (and logs with full traceback) any Keras/TF loading exception.
        """
        # Preferred: TensorFlow-free Keras-Lite export of the SAME trained model
        # (identical predictions, ~40 MB RAM instead of >500 MB for TensorFlow).
        lite_path = Path(self.model_path).with_suffix(".npz")
        if lite_path.exists():
            try:
                from services.keras_lite import load_lite_model
                self.model = load_lite_model(str(lite_path))
                self._backend = "keras-lite"
                self._is_loaded = True
                self._load_error = None
                logger.info("MailShield ML model loaded (Keras-Lite, no TensorFlow): %s", lite_path.name)
                return
            except Exception:
                logger.exception("Keras-Lite ML export could not be loaded; trying full Keras.")

        if not Path(self.model_path).exists():
            msg = f"ML model file not found at {self.model_path}"
            logger.error(msg)
            self._load_error = msg
            raise FileNotFoundError(msg)

        try:
            import keras as _keras  # lazy import — TF/Keras not required at startup
            logger.info("Loading MailShield ML model from: %s", self.model_path)
            self.model = _keras.models.load_model(self.model_path)
            self._is_loaded = True
            self._load_error = None
            logger.info(
                "MailShield ML model loaded successfully into memory (threshold=%.4f).",
                self.threshold,
            )
        except ImportError:
            self._load_error = "Keras is not installed."
            logger.error("Keras is not installed. ML predictions will be unavailable.")
            raise
        except Exception:
            tb = traceback.format_exc()
            self._load_error = tb
            logger.error(
                "Failed to load ML model from %s.\nFull traceback:\n%s",
                self.model_path,
                tb,
            )
            raise

    def is_loaded(self) -> bool:
        return self._is_loaded and self.model is not None

    def predict(self, text: str) -> MLAnalysisResult:
        """Runs phishing classification on raw email text (subject + body).

        The model contains a built-in TextVectorization layer that accepts raw
        string inputs — no external tokenizer or preprocessing required.
        Uses best_threshold from metadata (0.35).
        Returns actual probability and confidence.
        Never generates fake/default results on failure; logs and raises the actual error.
        """
        if not self._is_loaded or self.model is None:
            raise RuntimeError(
                "ML model has not been loaded. Check startup logs for the exact Keras error."
            )

        if text is None:
            text = ""

        try:
            if self._backend == "keras-lite":
                prob = float(self.model.predict_proba(text)[0])
            else:
                import tensorflow as tf
                # Model expects a 1-D tensor of strings: shape (batch_size,) = (1,)
                input_tensor = tf.constant([text], dtype=tf.string)
                raw_pred = self.model.predict(input_tensor, verbose=0)
                # Raw prediction is shape (1, 1) with sigmoid output [0.0 – 1.0]
                prob = float(raw_pred[0][0])
            prob = max(0.0, min(1.0, prob))

            prediction = "phishing" if prob >= self.threshold else "legitimate"
            confidence = prob if prob >= self.threshold else (1.0 - prob)

            return MLAnalysisResult(
                prediction=prediction,
                phishing_probability=round(prob, 4),
                confidence=round(confidence, 4),
            )
        except Exception as exc:
            logger.error("ML model inference failed: %s", exc, exc_info=True)
            raise RuntimeError(f"ML model inference failed: {exc}") from exc


# Global singleton
_ml_service: Optional[MLService] = None


def get_ml_service() -> MLService:
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService()
    return _ml_service

