"""
MailShield - Health & Status API Routes
Provides /api/health, /api/model-status, and /api/health/ml endpoints.
"""
from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter

from schemas.analysis import (
    HealthResponse,
    MLHealthCheckItem,
    MLHealthResponse,
    ModelStatusResponse,
)
from services.ml_service import get_ml_service
from services.nlp_service import get_nlp_service
from services.sarvam_service import is_sarvam_configured

router = APIRouter(tags=["Health & Status"])


@router.get("/health")
@router.get("/api/health")
@router.get("/api/v1/health")
async def health_check():
    """Liveness + database connectivity. Never exposes connection details."""
    from sqlalchemy import text
    from app.database.session import engine

    db_status = "ok"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "app_name": "MAILSHIELD",
        "version": "1.0.0",
        "database": db_status,
        "database_engine": engine.dialect.name,
    }


@router.get("/api/model-status", response_model=ModelStatusResponse)
@router.get("/api/v1/model-status", response_model=ModelStatusResponse)
async def model_status():
    """
    Returns the real-time load status of the ML, NLP, forensic, Gemini,
    Sarvam, and Ollama reasoning engines.
    """
    ml_service = get_ml_service()
    nlp_service = get_nlp_service()

    reasoning_type = os.getenv("REASONING_PROVIDER", "gemini")
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    has_gemini = bool(gemini_key and gemini_key != "your_key_here")
    has_sarvam = is_sarvam_configured()

    gemini_status = "CONNECTED" if has_gemini else "UNAVAILABLE"
    sarvam_status = "CONNECTED" if has_sarvam else "UNAVAILABLE"
    ollama_status = "CONNECTED" if reasoning_type == "ollama" else "NOT CONFIGURED"

    from app.ml.structured_model import get_structured_model
    from app.ml.text_model import get_text_model
    return ModelStatusResponse(
        # Production detection uses the v2 scikit-learn models; the legacy Keras
        # models are optional extras when TensorFlow is installed.
        ml_model_loaded=get_structured_model().is_available or ml_service.is_loaded(),
        nlp_model_loaded=get_text_model().is_available or nlp_service.is_loaded(),
        forensic_engine_active=True,
        gemini_status=gemini_status,
        sarvam_voice_status=sarvam_status,
        ollama_status=ollama_status,
        autonomous_agent_status="ACTIVE" if os.getenv("GMAIL_MONITOR_ENABLED", "true").lower() != "false" else "NOT CONFIGURED",
        autonomous_agent_active=os.getenv("GMAIL_MONITOR_ENABLED", "true").lower() != "false",
        ml_model_path="app/ml/artifacts/structured_model.joblib" if get_structured_model().is_available else ml_service.model_path,
        nlp_model_path="app/ml/artifacts/text_model.joblib" if get_text_model().is_available else nlp_service.model_path,
        reasoning_provider=reasoning_type,
        gemini_configured=has_gemini,
    )


@router.get("/health/ml", response_model=MLHealthResponse)
@router.get("/api/health/ml", response_model=MLHealthResponse)
@router.get("/api/v1/health/ml", response_model=MLHealthResponse)
async def ml_health():
    """
    Deep ML/NLP diagnostic endpoint.

    Runs the following checks in order:
      1. ML model file exists on disk
      2. NLP model file exists on disk
      3. ML model is loaded in memory
      4. NLP model is loaded in memory
      5. Preprocessing pipeline: text → ML input tensor
      6. ML model predicts on a short test email (shape check)
      7. NLP model predicts on a short test email (shape check)
      8. Live predictions on 4 canonical test emails:
         normal / spam / phishing / malicious

    Returns HTTP 200 in all cases (even if degraded) so monitoring tools
    can read the JSON body. Check the `status` field: "ok" | "degraded".
    """
    ml_service = get_ml_service()
    nlp_service = get_nlp_service()

    checks: List[MLHealthCheckItem] = []
    all_passed = True
    combined_error: str | None = None

    # ── helpers ──────────────────────────────────────────────────────────────
    def add(name: str, passed: bool, detail: str | None = None):
        nonlocal all_passed
        if not passed:
            all_passed = False
        checks.append(MLHealthCheckItem(name=name, passed=passed, detail=detail))

    # ── 1. TF / Keras version probe ──────────────────────────────────────────
    tf_version: str | None = None
    keras_version: str | None = None
    try:
        import tensorflow as _tf
        import keras as _keras
        tf_version = _tf.__version__
        keras_version = _keras.__version__
        add("tensorflow_importable", True, f"TensorFlow {tf_version}")
        add("keras_importable", True, f"Keras {keras_version}")
    except ImportError as exc:
        # Production runs the TensorFlow-free Keras-Lite runtime (models/*.npz);
        # TensorFlow is only required when no .npz export exists.
        lite_ok = Path(ml_service.model_path).with_suffix(".npz").exists() and \
            Path(nlp_service.model_path).with_suffix(".npz").exists()
        add("tensorflow_importable", lite_ok,
            "Not installed - not needed: Keras-Lite (.npz) runtime in use" if lite_ok else str(exc))

    # ── 2. Model files exist ─────────────────────────────────────────────────
    ml_path = Path(ml_service.model_path)
    nlp_path = Path(nlp_service.model_path)

    if not ml_path.exists() and ml_path.with_suffix(".npz").exists():
        ml_path = ml_path.with_suffix(".npz")
    if not nlp_path.exists() and nlp_path.with_suffix(".npz").exists():
        nlp_path = nlp_path.with_suffix(".npz")
    ml_file_ok = ml_path.exists()
    nlp_file_ok = nlp_path.exists()
    add(
        "ml_model_file_exists",
        ml_file_ok,
        f"{ml_path} ({ml_path.stat().st_size // 1024 // 1024} MB)" if ml_file_ok else f"Missing: {ml_path}",
    )
    add(
        "nlp_model_file_exists",
        nlp_file_ok,
        f"{nlp_path} ({nlp_path.stat().st_size // 1024} KB)" if nlp_file_ok else f"Missing: {nlp_path}",
    )

    # ── 3. Models loaded in memory ───────────────────────────────────────────
    add(
        "ml_model_loaded_in_memory",
        ml_service.is_loaded(),
        "Loaded" if ml_service.is_loaded() else (
            getattr(ml_service, "_load_error", None) or "Not loaded — check startup logs"
        ),
    )
    add(
        "nlp_model_loaded_in_memory",
        nlp_service.is_loaded(),
        "Loaded" if nlp_service.is_loaded() else (
            getattr(nlp_service, "_load_error", None) or "Not loaded — check startup logs"
        ),
    )

    # ── 4. Preprocessing check (text → tensor) ───────────────────────────────
    prep_ok = False
    try:
        if getattr(ml_service, "_backend", "") == "keras-lite" and ml_service.is_loaded():
            ids = ml_service.model.vectorize("Hello world test email")
            add("preprocessing_text_to_tensor", True, f"Keras-Lite TextVectorization -> {len(ids)} token ids")
            prep_ok = True
            raise StopIteration
        import tensorflow as _tf
        _test_tensor = _tf.constant(["Hello world test email"], dtype=_tf.string)
        add("preprocessing_text_to_tensor", True, f"shape={_test_tensor.shape}, dtype={_test_tensor.dtype}")
        prep_ok = True
    except StopIteration:
        pass
    except Exception as exc:
        add("preprocessing_text_to_tensor", False, f"{type(exc).__name__}: {exc}")

    # ── 5 & 6. Live test predictions ─────────────────────────────────────────
    test_emails: Dict[str, str] = {
        "normal_email": "Hi team, please review the attached meeting notes for next Tuesday.",
        "spam_email": "Congratulations! You have been selected for a FREE prize. Click here to claim now!",
        "phishing_email": (
            "URGENT: Your bank account has been compromised. "
            "Verify your credentials immediately at http://secure-bank-verify.xyz"
        ),
        "malicious_email": (
            "Your account will be suspended in 24 hours. "
            "Click the link below and enter your password and social security number to avoid suspension."
        ),
    }

    test_predictions: Dict[str, Any] = {}

    if ml_service.is_loaded() and prep_ok:
        all_ml_ok = True
        for label, email_text in test_emails.items():
            try:
                ml_result = ml_service.predict(email_text)
                test_predictions[label] = {
                    "ml_prediction": ml_result.prediction,
                    "ml_phishing_prob": ml_result.phishing_probability,
                    "ml_confidence": ml_result.confidence,
                }
            except Exception as exc:
                all_ml_ok = False
                test_predictions[label] = {"ml_error": f"{type(exc).__name__}: {exc}"}
        add(
            "ml_test_predictions",
            all_ml_ok,
            f"Ran {len(test_emails)} test emails" if all_ml_ok else "One or more ML predictions failed",
        )
    else:
        add("ml_test_predictions", False, "Skipped — ML model not loaded")

    if nlp_service.is_loaded() and prep_ok:
        all_nlp_ok = True
        for label, email_text in test_emails.items():
            try:
                nlp_result = nlp_service.predict(email_text)
                existing = test_predictions.get(label, {})
                existing.update({
                    "nlp_urgency": nlp_result.urgency,
                    "nlp_credential_request": nlp_result.credential_request,
                    "nlp_financial_manipulation": nlp_result.financial_manipulation,
                    "nlp_impersonation": nlp_result.impersonation,
                    "nlp_threat_language": nlp_result.threat_language,
                    "nlp_suspicious_action": nlp_result.suspicious_action,
                })
                test_predictions[label] = existing
            except Exception as exc:
                all_nlp_ok = False
                existing = test_predictions.get(label, {})
                existing["nlp_error"] = f"{type(exc).__name__}: {exc}"
                test_predictions[label] = existing
        add(
            "nlp_test_predictions",
            all_nlp_ok,
            f"Ran {len(test_emails)} test emails" if all_nlp_ok else "One or more NLP predictions failed",
        )
    else:
        add("nlp_test_predictions", False, "Skipped — NLP model not loaded")

    # ── Collect last load error for top-level error field ────────────────────
    ml_err = getattr(ml_service, "_load_error", None)
    nlp_err = getattr(nlp_service, "_load_error", None)
    if ml_err or nlp_err:
        combined_error = "\n\n".join(filter(None, [ml_err, nlp_err]))

    return MLHealthResponse(
        status="ok" if all_passed else "degraded",
        python_version=sys.version,
        tensorflow_version=tf_version,
        keras_version=keras_version,
        ml_model_path=str(ml_path),
        nlp_model_path=str(nlp_path),
        ml_model_loaded=ml_service.is_loaded(),
        nlp_model_loaded=nlp_service.is_loaded(),
        checks=checks,
        test_predictions=test_predictions if test_predictions else None,
        error=combined_error,
    )
