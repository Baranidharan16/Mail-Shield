"""
MailShield - Sarvam AI Multilingual Voice Service
Provides Speech-to-Text (STT) and Text-to-Speech (TTS) integration with Sarvam AI for 22 Indian languages.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("mailshield.sarvam_service")

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


def get_sarvam_api_key() -> str:
    return os.getenv("SARVAM_API_KEY", "").strip()


def is_sarvam_configured() -> bool:
    key = get_sarvam_api_key()
    return bool(key and key != "your_key_here")


def _strip_markdown(text: str) -> str:
    """Removes bold, headers, code, bullet characters for clear speech readout."""
    cleaned = re.sub(r"[*_#`~>\[\]]", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


async def synthesize_speech(
    text: str,
    voice: str = _DEFAULT_SPEAKER,
    language: str = _DEFAULT_LANG,
) -> Dict[str, Any]:
    """
    Synthesize text into speech audio using Sarvam TTS (bulbul:v3).
    Returns base64-encoded WAV audio.
    """
    api_key = get_sarvam_api_key()
    if not api_key:
        return {
            "audio_base64": "",
            "format": "wav",
            "engine": "offline_fallback",
            "language_code": language,
            "language_name": INDIAN_LANGUAGES.get(language, "English"),
            "speaker": voice,
            "error": "SARVAM_API_KEY is not configured.",
        }

    lang_code = language if language in INDIAN_LANGUAGES else _DEFAULT_LANG
    clean_text = _strip_markdown(text)[:600]
    if not clean_text:
        clean_text = "No text provided for speech synthesis."

    payload = {
        "inputs": [clean_text],
        "target_language_code": lang_code,
        "speaker": voice or _DEFAULT_SPEAKER,
        "pitch": 0,
        "pace": 1.0,
        "loudness": 1.5,
        "speech_sample_rate": 22050,
        "enable_preprocessing": True,
        "model": "bulbul:v3",
    }

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
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
            return {
                "audio_base64": "",
                "format": "wav",
                "engine": "sarvam:bulbul:v3",
                "language_code": lang_code,
                "language_name": INDIAN_LANGUAGES.get(lang_code, "Indian Language"),
                "speaker": voice,
                "error": "Sarvam returned empty audio data.",
            }

        return {
            "audio_base64": audios[0],
            "format": "wav",
            "engine": "sarvam:bulbul:v3",
            "language_code": lang_code,
            "language_name": INDIAN_LANGUAGES.get(lang_code, "Indian Language"),
            "speaker": voice or _DEFAULT_SPEAKER,
            "text_used": clean_text,
        }

    except httpx.HTTPStatusError as exc:
        logger.warning("Sarvam TTS HTTP error %s: %s", exc.response.status_code, exc.response.text[:200])
        return {
            "audio_base64": "",
            "format": "wav",
            "engine": "sarvam:bulbul:v3",
            "language_code": lang_code,
            "language_name": INDIAN_LANGUAGES.get(lang_code, "Indian Language"),
            "speaker": voice,
            "error": f"Sarvam TTS HTTP error: {exc.response.status_code}",
        }
    except Exception as exc:
        logger.warning("Sarvam TTS exception: %s", exc)
        return {
            "audio_base64": "",
            "format": "wav",
            "engine": "sarvam:bulbul:v3",
            "language_code": lang_code,
            "language_name": INDIAN_LANGUAGES.get(lang_code, "Indian Language"),
            "speaker": voice,
            "error": str(exc),
        }


async def transcribe_speech(
    audio_bytes: bytes,
    filename: str = "audio.wav",
    content_type: str = "audio/wav",
    language_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Transcribe spoken voice audio using Sarvam STT (saaras:v3).
    Supports all 22 Indian languages with automatic language detection.
    """
    api_key = get_sarvam_api_key()
    if not api_key:
        return {
            "transcript": "",
            "language_code": "en-IN",
            "language_name": "English",
            "confidence": 0.0,
            "engine": "offline_fallback",
            "error": "SARVAM_API_KEY is not configured.",
        }

    files = {
        "file": (filename, audio_bytes, content_type or "audio/wav"),
    }
    form_data: Dict[str, str] = {
        "model": "saaras:v3",
    }
    if language_code and language_code in INDIAN_LANGUAGES:
        form_data["language_code"] = language_code

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                SARVAM_STT_URL,
                headers={"api-subscription-key": api_key},
                files=files,
                data=form_data,
            )
            resp.raise_for_status()
            result = resp.json()

        transcript = result.get("transcript", "").strip()
        detected_code = result.get("language_code") or (language_code or "en-IN")
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
        return {
            "transcript": "",
            "language_code": language_code or "en-IN",
            "language_name": INDIAN_LANGUAGES.get(language_code or "en-IN", "English"),
            "confidence": 0.0,
            "engine": "sarvam:saaras:v3",
            "error": f"Sarvam STT HTTP error: {exc.response.status_code}",
        }
    except Exception as exc:
        logger.warning("Sarvam STT exception: %s", exc)
        return {
            "transcript": "",
            "language_code": language_code or "en-IN",
            "language_name": INDIAN_LANGUAGES.get(language_code or "en-IN", "English"),
            "confidence": 0.0,
            "engine": "sarvam:saaras:v3",
            "error": str(exc),
        }
