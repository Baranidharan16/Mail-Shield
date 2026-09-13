"""
MailShield - Health & Status API Routes
Provides /api/health and /api/model-status endpoints.
"""
from __future__ import annotations

import os
from fastapi import APIRouter

from schemas.analysis import HealthResponse, ModelStatusResponse
from services.ml_service import get_ml_service
from services.nlp_service import get_nlp_service
from services.sarvam_service import is_sarvam_configured

router = APIRouter(tags=["Health & Status"])


@router.get("/health", response_model=HealthResponse)
@router.get("/api/health", response_model=HealthResponse)
@router.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Returns application health status."""
    return HealthResponse(
        status="ok",
        app_name="MAILSHIELD",
        version="1.0.0",
    )


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

    return ModelStatusResponse(
        ml_model_loaded=ml_service.is_loaded(),
        nlp_model_loaded=nlp_service.is_loaded(),
        forensic_engine_active=True,
        gemini_status=gemini_status,
        sarvam_voice_status=sarvam_status,
        ollama_status=ollama_status,
        autonomous_agent_status="NOT CONFIGURED",
        autonomous_agent_active=False,
        ml_model_path=ml_service.model_path,
        nlp_model_path=nlp_service.model_path,
        reasoning_provider=reasoning_type,
        gemini_configured=has_gemini,
    )

