"""
MailShield - AI Assistant & Multilingual Voice API Routes
Provides /api/assistant/chat, /api/assistant/transcribe, /api/assistant/speak, and /api/assistant/voice.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from schemas.analysis import (
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantSpeakRequest,
    AssistantSpeakResponse,
    AssistantTranscribeResponse,
    AssistantVoiceResponse,
)
from services.gemini_service import get_reasoning_provider
from services.sarvam_service import synthesize_speech, transcribe_speech

logger = logging.getLogger("mailshield.routes.assistant")

router = APIRouter(prefix="/api/assistant", tags=["Assistant & Voice"])


@router.post("/chat", response_model=AssistantChatResponse)
async def assistant_chat(body: AssistantChatRequest):
    """
    Forensic reasoning Q&A grounded strictly in the active email investigation evidence.
    Supports queries across 22 Indian languages and English.
    """
    try:
        provider = get_reasoning_provider()
        result = await provider.answer_investigation_question(
            question=body.question,
            context=body.context,
            history=body.history,
            language_code=body.language or "en-IN",
        )
        return AssistantChatResponse(
            answer=result.get("answer", "Analysis completed."),
            engine=result.get("engine", "mailshield_ai"),
            language=result.get("language", body.language or "en-IN"),
            sources=result.get("sources", []),
        )
    except Exception as exc:
        logger.exception("Assistant chat failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Assistant chat error: {str(exc)}")


@router.post("/transcribe", response_model=AssistantTranscribeResponse)
async def assistant_transcribe(
    file: UploadFile = File(...),
    language_code: Optional[str] = Form(None),
):
    """
    Transcribes spoken voice audio to text using Sarvam AI STT (Saaras).
    Supports 22 Indian languages with automatic speech detection.
    """
    audio_bytes = await file.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Audio file is empty.")

    result = await transcribe_speech(
        audio_bytes=audio_bytes,
        filename=file.filename or "audio.wav",
        content_type=file.content_type or "audio/wav",
        language_code=language_code,
    )
    if "error" in result and not result.get("transcript"):
        raise HTTPException(status_code=502, detail=result["error"])

    return AssistantTranscribeResponse(
        transcript=result.get("transcript", ""),
        language_code=result.get("language_code", "en-IN"),
        language_name=result.get("language_name", "English"),
        confidence=result.get("confidence", 1.0),
        engine=result.get("engine", "sarvam:saaras:v3"),
    )


@router.post("/speak", response_model=AssistantSpeakResponse)
async def assistant_speak(body: AssistantSpeakRequest):
    """
    Synthesizes forensic response text to speech using Sarvam AI TTS (Bulbul).
    Returns base64-encoded WAV audio.
    """
    result = await synthesize_speech(
        text=body.text,
        voice=body.voice or "priya",
        language=body.language or "en-IN",
    )
    if "error" in result and not result.get("audio_base64"):
        raise HTTPException(status_code=502, detail=result["error"])

    return AssistantSpeakResponse(
        audio_base64=result.get("audio_base64", ""),
        format=result.get("format", "wav"),
        engine=result.get("engine", "sarvam:bulbul:v3"),
        language_code=result.get("language_code", body.language or "en-IN"),
        language_name=result.get("language_name", "English"),
        speaker=result.get("speaker", body.voice or "priya"),
    )


@router.post("/voice", response_model=AssistantVoiceResponse)
async def assistant_voice(
    file: UploadFile = File(...),
    context_json: Optional[str] = Form(None),
    language_code: Optional[str] = Form(None),
):
    """
    End-to-end voice query pipeline:
    User Audio -> Sarvam STT -> Gemini Reasoning -> Sarvam TTS -> Audio Response
    """
    audio_bytes = await file.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Voice audio is empty.")

    # 1. Transcribe speech using Sarvam STT
    stt_res = await transcribe_speech(
        audio_bytes=audio_bytes,
        filename=file.filename or "recording.wav",
        content_type=file.content_type or "audio/wav",
        language_code=language_code,
    )
    transcript = stt_res.get("transcript", "").strip()
    if not transcript:
        transcript = "What is the overall risk assessment of this email?"

    detected_lang = stt_res.get("language_code") or (language_code or "en-IN")

    # 2. Parse context
    parsed_context = None
    if context_json:
        try:
            parsed_context = json.loads(context_json)
        except Exception:
            parsed_context = None

    # 3. Generate reasoning answer
    provider = get_reasoning_provider()
    chat_res = await provider.answer_investigation_question(
        question=transcript,
        context=parsed_context,
        history=[],
        language_code=detected_lang,
    )
    answer_text = chat_res.get("answer", "Analysis completed.")

    # 4. Synthesize speech answer via Sarvam TTS
    tts_res = await synthesize_speech(
        text=answer_text,
        voice="priya",
        language=detected_lang,
    )

    return AssistantVoiceResponse(
        transcript=transcript,
        answer=answer_text,
        audio_base64=tts_res.get("audio_base64", ""),
        format="wav",
        language_code=detected_lang,
        language_name=stt_res.get("language_name", "Indian Language"),
        engine=f"{chat_res.get('engine', 'gemini')} + {tts_res.get('engine', 'sarvam')}",
    )
