"""
Forensic AI Agent — Sarvam AI Multilingual Voice Engine (22 Indian Languages).

Provides:
1. Speech-to-Text (STT) via Sarvam `saaras:v3` — user speaks about forensic details
   in any of 22 Indian languages; transcribes to text and detects the language.
2. Text-to-Speech (TTS) via Sarvam `bulbul:v3` — narrates forensic responses in the
   user's native language with natural synthesized voice.
"""
from __future__ import annotations

import base64
import logging
import re
from typing import Any, Dict, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("forensic_platform")
settings = get_settings()

SARVAM_TTS_URL = "https://api.sarvam.ai/text-to-speech"
SARVAM_STT_URL = "https://api.sarvam.ai/speech-to-text"

# 22 Official Indian Languages + English
INDIAN_LANGUAGES: Dict[str, str] = {
    "en-IN": "English (India)",
    "hi-IN": "Hindi (हिन्दी)",
    "ta-IN": "Tamil (தமிழ்)",
    "te-IN": "Telugu (తెలుగు)",
    "kn-IN": "Kannada (ಕನ್ನಡ)",
    "ml-IN": "Malayalam (മലയാളം)",
    "mr-IN": "Marathi (मराठी)",
    "bn-IN": "Bengali (বাংলা)",
    "gu-IN": "Gujarati (ગુજરાતી)",
    "pa-IN": "Punjabi (ਪੰਜਾਬੀ)",
    "or-IN": "Odia (ଓଡ଼ିଆ)",
    "as-IN": "Assamese (অসমীয়া)",
    "ur-IN": "Urdu (اردو)",
    "sa-IN": "Sanskrit (संस्कृतम्)",
    "mai-IN": "Maithili (मैथिली)",
    "ne-IN": "Nepali (नेपाली)",
    "kok-IN": "Konkani (कोंकणी)",
    "ks-IN": "Kashmiri (کٲشُر)",
    "sd-IN": "Sindhi (سنڌي)",
    "sat-IN": "Santali (ᱥᱟᱱᱛᱟᱲᱤ)",
    "brx-IN": "Bodo (बड़ो)",
    "doi-IN": "Dogri (डोगरी)",
}

_DEFAULT_SPEAKER = "priya"
_DEFAULT_LANG = "en-IN"


# ── Text-to-Speech (TTS) ────────────────────────────────────────────────────────
async def synthesize_speech(
    text: str,
    voice: str = _DEFAULT_SPEAKER,
    language: str = _DEFAULT_LANG,
) -> Dict[str, Any]:
    """
    Send text to Sarvam TTS (bulbul:v3) and return base64-encoded WAV audio.
    Supports all 22 Indian languages.
    """
    api_key = settings.SARVAM_API_KEY
    if not api_key:
        return _fallback_tts("Sarvam API key not configured. Please set SARVAM_API_KEY in .env")

    # Normalize language code
    lang_code = language if language in INDIAN_LANGUAGES else "en-IN"
    # Clean text of markdown formatting for natural reading
    clean_text = _strip_markdown(text)[:500]

    # Valid speakers for bulbul:v3: priya, aditya, ritu, ashutosh, neha, rahul, pooja, rohan, simran, kavya, amit, dev
    valid_speakers = {"priya", "aditya", "ritu", "ashutosh", "neha", "rahul", "pooja", "rohan", "simran", "kavya", "amit", "dev"}
    speaker_name = voice if voice in valid_speakers else _DEFAULT_SPEAKER

    payload = {
        "inputs": [clean_text],
        "target_language_code": lang_code,
        "speaker": speaker_name,
        "pitch": 0,
        "pace": 1.0,
        "loudness": 1.5,
        "speech_sample_rate": 22050,
        "enable_preprocessing": True,
        "model": "bulbul:v3",
    }

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.post(
                SARVAM_TTS_URL,
                headers={
                    "api-subscription-key": api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        audios = data.get("audios") or []
        if not audios:
            return _fallback_tts("Sarvam returned empty audio array.")

        return {
            "audio_base64": audios[0],
            "format": "wav",
            "engine": "sarvam:bulbul:v3",
            "language_code": lang_code,
            "language_name": INDIAN_LANGUAGES.get(lang_code, "Indian Language"),
            "speaker": speaker_name,
            "text_used": clean_text,
        }

    except httpx.HTTPStatusError as exc:
        logger.warning("Sarvam TTS HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
        return _fallback_tts(f"Sarvam TTS error {exc.response.status_code}")
    except Exception as exc:
        logger.warning("Sarvam TTS exception: %s", exc)
        return _fallback_tts(str(exc))


# ── Speech-to-Text (STT) ────────────────────────────────────────────────────────
async def transcribe_speech(
    audio_bytes: bytes,
    filename: str = "audio.wav",
    content_type: str = "audio/wav",
    language_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Transcribe speech to text using Sarvam STT (saaras:v3).
    Automatically detects spoken language across all 22 Indian languages.
    """
    api_key = settings.SARVAM_API_KEY
    if not api_key:
        return _fallback_stt("Sarvam API key not configured.")

    files = {
        "file": (filename, audio_bytes, content_type or "audio/wav"),
    }
    data: Dict[str, str] = {
        "model": "saaras:v3",
    }
    if language_code and language_code in INDIAN_LANGUAGES:
        data["language_code"] = language_code

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                SARVAM_STT_URL,
                headers={"api-subscription-key": api_key},
                files=files,
                data=data,
            )
            resp.raise_for_status()
            result = resp.json()

        transcript = result.get("transcript", "").strip()
        detected_code = result.get("language_code") or "en-IN"
        prob = result.get("language_probability") or 1.0

        return {
            "transcript": transcript,
            "language_code": detected_code,
            "language_name": INDIAN_LANGUAGES.get(detected_code, detected_code),
            "confidence": float(prob),
            "engine": "sarvam:saaras:v3",
        }

    except httpx.HTTPStatusError as exc:
        logger.warning("Sarvam STT HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
        return _fallback_stt(f"Sarvam STT error {exc.response.status_code}")
    except Exception as exc:
        logger.warning("Sarvam STT exception: %s", exc)
        return _fallback_stt(str(exc))


# ── Helpers ────────────────────────────────────────────────────────────────────
def _strip_markdown(text: str) -> str:
    """Remove markdown syntax so TTS sounds natural."""
    text = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", text)
    text = re.sub(r"`{1,3}(.+?)`{1,3}", r"\1", text, flags=re.DOTALL)
    text = re.sub(r"#+\s*", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"^[-*•]\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{2,}", ". ", text)
    text = re.sub(r"\n", " ", text)
    return text.strip()


def _fallback_tts(reason: str) -> Dict[str, Any]:
    return {
        "audio_base64": None,
        "format": None,
        "engine": "fallback",
        "error": reason,
    }


def _fallback_stt(reason: str) -> Dict[str, Any]:
    return {
        "transcript": "",
        "language_code": "en-IN",
        "language_name": "English",
        "confidence": 0.0,
        "engine": "fallback",
        "error": reason,
    }
