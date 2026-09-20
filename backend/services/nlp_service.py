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

# ---------------------------------------------------------------------------
# KeywordNLPScorer — pure-Python fallback when the numpy model is not loaded.
# Works on Render's 512 MB free tier with zero extra dependencies.
# Uses weighted phrase matching to approximate the trained model's 6 outputs.
# ---------------------------------------------------------------------------
class KeywordNLPScorer:
    """Zero-dependency keyword scorer for the 6 MailShield NLP threat categories.

    Each entry is (phrase, weight). Score is clamped to [0, 1] so multiple
    hits don't overflow.
    """

    _PATTERNS: "dict[str, list[tuple[str, float]]]" = {
        "urgency": [
            ("urgent", 0.30), ("urgently", 0.30), ("immediately", 0.30),
            ("act now", 0.35), ("act immediately", 0.35),
            ("within 24 hours", 0.35), ("within 48 hours", 0.30),
            ("time sensitive", 0.25), ("time-sensitive", 0.25),
            ("asap", 0.25), ("as soon as possible", 0.20),
            ("final notice", 0.30), ("last chance", 0.25),
            ("immediate action", 0.30), ("immediate action required", 0.35),
            ("respond immediately", 0.35), ("deadline", 0.15),
            ("do not delay", 0.25), ("action required", 0.25),
            ("response required", 0.20), ("expires today", 0.30),
            ("will be closed", 0.25), ("must verify", 0.25),
        ],
        "credential_request": [
            ("verify your password", 0.40), ("confirm your password", 0.40),
            ("enter your password", 0.40), ("re-enter your password", 0.40),
            ("update your password", 0.35), ("reset your password", 0.30),
            ("verify your account", 0.35), ("confirm your account", 0.35),
            ("verify your identity", 0.35), ("verify your credentials", 0.40),
            ("confirm your credentials", 0.40), ("login to verify", 0.35),
            ("click here to verify", 0.35), ("click here to login", 0.35),
            ("validate your account", 0.35), ("validate your mailbox", 0.35),
            ("send your password", 0.40), ("provide your password", 0.40),
            ("enter your otp", 0.35), ("enter your pin", 0.35),
            ("reply with your password", 0.40),
            ("account verification required", 0.35),
            ("keep your current password", 0.35),
            ("two-factor", 0.15), ("2fa code", 0.25),
        ],
        "financial_manipulation": [
            ("wire transfer", 0.40), ("wire the funds", 0.40),
            ("wire the money", 0.40), ("process a payment", 0.35),
            ("send bitcoin", 0.40), ("send btc", 0.40),
            ("bitcoin wallet", 0.40), ("crypto address", 0.40),
            ("wallet address", 0.40), ("transfer funds", 0.35),
            ("updated bank details", 0.35), ("new bank account", 0.35),
            ("beneficiary details", 0.35), ("change the beneficiary", 0.35),
            ("overdue invoice", 0.30), ("tax refund", 0.25),
            ("customs fee", 0.25), ("delivery fee", 0.20),
            ("apple gift card", 0.40), ("amazon gift card", 0.40),
            ("google play card", 0.40), ("gift card", 0.35),
            ("send money", 0.25), ("urgent payment", 0.30),
        ],
        "impersonation": [
            ("are you available", 0.35), ("are you at your desk", 0.35),
            ("i need you to handle", 0.35), ("keep this confidential", 0.35),
            ("keep this between us", 0.35), ("strictly confidential", 0.30),
            ("can you do me a favour", 0.35), ("can you do me a favor", 0.35),
            ("i'm in a meeting", 0.30), ("i am in a meeting", 0.30),
            ("cannot take calls", 0.30), ("can't take calls", 0.30),
            ("microsoft security", 0.25), ("google security", 0.25),
            ("apple support", 0.25), ("paypal support", 0.25),
            ("bank security", 0.25), ("support team", 0.10),
            ("security team", 0.10), ("it department", 0.10),
            ("on behalf of", 0.15), ("from the desk of", 0.20),
        ],
        "threat_language": [
            ("your account will be suspended", 0.35),
            ("account has been suspended", 0.35),
            ("account will be terminated", 0.35),
            ("account will be closed", 0.35),
            ("account will be blocked", 0.35),
            ("account has been compromised", 0.35),
            ("account has been hacked", 0.35),
            ("unauthorized access", 0.30), ("unauthorized login", 0.30),
            ("security breach", 0.30), ("data breach", 0.25),
            ("will face legal action", 0.40), ("legal consequences", 0.35),
            ("report to authorities", 0.35), ("expose your", 0.35),
            ("release the video", 0.40), ("release the photos", 0.40),
            ("blackmail", 0.40), ("extortion", 0.40), ("ransom", 0.40),
            ("hacked your device", 0.40), ("hacked your computer", 0.40),
            ("recorded you", 0.35), ("failure to comply", 0.35),
            ("consequences", 0.15), ("failure to", 0.20),
        ],
        "suspicious_action": [
            ("click the link", 0.35), ("click here", 0.25),
            ("click below", 0.30), ("download the attachment", 0.35),
            ("open the attachment", 0.35), ("open the file", 0.30),
            ("enable macros", 0.40), ("enable editing", 0.35),
            ("enable content", 0.35), ("view document online", 0.30),
            ("login here", 0.30), ("sign in here", 0.30),
            ("complete the form", 0.25), ("claim your", 0.25),
            ("claim now", 0.25), ("congratulations you", 0.30),
            ("you have been selected", 0.30), ("you have won", 0.30),
            ("free prize", 0.25), ("bit.ly", 0.20), ("tinyurl", 0.20),
            ("confirm here", 0.25), ("verify here", 0.25),
        ],
    }

    def score(self, text: str) -> NLPAnalysisResult:
        """Score text against 6 threat categories using weighted keyword matching."""
        t = (text or "").lower()
        results: "dict[str, float]" = {}
        for category, phrases in self._PATTERNS.items():
            raw = sum(w for phrase, w in phrases if phrase in t)
            # sigmoid-like clamp so multiple hits don't overflow past 1.0
            results[category] = round(min(1.0, raw / (raw + 0.4)) if raw > 0 else 0.0, 4)
        return NLPAnalysisResult(
            urgency=results["urgency"],
            credential_request=results["credential_request"],
            financial_manipulation=results["financial_manipulation"],
            impersonation=results["impersonation"],
            threat_language=results["threat_language"],
            suspicious_action=results["suspicious_action"],
        )


# Module-level singleton — instantiated once, always available
_keyword_scorer = KeywordNLPScorer()


def keyword_nlp_score(text: str) -> NLPAnalysisResult:
    """Convenience wrapper: keyword-based NLP scoring with zero dependencies."""
    return _keyword_scorer.score(text)


class NLPService:
    def __init__(self, model_path: Optional[str] = None, metadata_path: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent.parent

        if model_path is None:
            v2_path = base_dir / "models" / "MailShield_NLP_v2.keras"
            # Production images ship only the TensorFlow-free .npz export (the .keras
            # file is excluded by .dockerignore), so accept either file.
            if v2_path.exists() or v2_path.with_suffix(".npz").exists():
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
        self._backend = "keras"
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
                logger.info("MailShield NLP model loaded (Keras-Lite, no TensorFlow): %s", lite_path.name)
                return
            except Exception:
                logger.exception("Keras-Lite NLP export could not be loaded; trying full Keras.")

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
        if not self._is_loaded or self.model is None:
            try:
                self.load()
            except Exception as e:
                logger.debug("NLP model auto-load deferred: %s", e)
        return self._is_loaded and self.model is not None

    def predict(self, text: str) -> NLPAnalysisResult:
        """Runs multi-label threat pattern inference on email text.

        The model accepts raw string inputs via its built-in TextVectorization layer.
        No external tokenizer or vectorizer is required.
        """
        if not self._is_loaded or self.model is None:
            try:
                self.load()
            except Exception as e:
                logger.debug("NLP model auto-load in predict: %s", e)

        if not self._is_loaded or self.model is None:
            logger.info("NLP model unavailable; falling back to keyword_nlp_score")
            return keyword_nlp_score(text)

        if not text or not text.strip():
            text = "Empty email body"

        try:
            if self._backend == "keras-lite":
                preds = self.model.predict_proba(text)
            else:
                import tensorflow as tf  # lazy import
                input_tensor = tf.constant([text], dtype=tf.string)
                preds = self.model.predict(input_tensor, verbose=0)[0]
        except Exception as exc:
            logger.warning("NLP prediction error with %s: %s; falling back to keyword score", self._backend, exc)
            return keyword_nlp_score(text)

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
        try:
            _nlp_service.load()
        except Exception as exc:
            logger.debug("Initial NLP load deferred: %s", exc)
    return _nlp_service
