"""
Application configuration.

All configurable values are read from environment variables (with sane
local-development defaults) so that no secrets are ever hard-coded in
source control, per project SECURITY requirements.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Annotated, List

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_DEFAULT_JWT_SECRET = "mailshield-insecure-dev-secret-key-change-in-production-2026"


def _parse_list(value):
    """Accept either a JSON list ('["a","b"]') or a comma-separated string ('a,b')."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("["):
        return [str(v).strip() for v in json.loads(text) if str(v).strip()]
    return [part.strip() for part in text.split(",") if part.strip()]


_BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    # Always read backend/.env regardless of the current working directory
    # (real environment variables still take precedence).
    model_config = SettingsConfigDict(env_file=str(_BACKEND_DIR / ".env"), extra="ignore")

    # --- General -----------------------------------------------------
    APP_NAME: str = "MailShield — AI Email Forensic Intelligence Platform"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = True

    # --- Database ------------------------------------------------------
    # Production: postgresql+psycopg2://user:pass@host:5432/dbname
    # Development/sandbox: sqlite:///./forensics.db
    DATABASE_URL: str = "sqlite:///./forensics.db"

    # --- CORS ------------------------------------------------------------
    # Accepts JSON ('["https://a.com"]') or comma-separated ('https://a.com,https://b.com').
    # Only these exact origins may make credentialed (cookie) requests.
    CORS_ORIGINS: Annotated[List[str], NoDecode] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    # Set this to your Vercel / production frontend URL to add it to CORS
    FRONTEND_URL: str = ""

    # --- File upload -----------------------------------------------------
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [".eml"]
    UPLOAD_STORAGE_DIR: str = "./storage/evidence"

    # --- Trusted organization domain (optional, for domain-mismatch checks)
    TRUSTED_ORG_DOMAINS: List[str] = []

    # --- Rate limiting -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 600  # 10 req/s — safe for local/demo use

    # --- Simple API-key authentication -------------------------------------
    AUTH_ENABLED: bool = False
    API_KEYS: dict[str, str] = {}

    # --- Phase 2: threat intelligence -------------------------------------
    THREAT_INTEL_DOMAIN_PROVIDER: str = "local"
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 6 * 60 * 60

    # --- Phase 2: data privacy / AI ---------------------------------------
    LOCAL_ONLY_MODE: bool = False

    # --- Gemini AI API key (for MailShield AI Chatbot) ---------------------
    GEMINI_API_KEY: str = ""

    # --- Sarvam AI API key (for MailShield AI Assistant — voice STT & TTS) ---
    SARVAM_API_KEY: str = ""

    # --- Phase 2: demo mode -------------------------------------------------
    DEMO_MODE_ENABLED: bool = True

    # --- JWT Authentication ------------------------------------------------
    # JWT_SECRET_KEY MUST be set (>= 32 random chars) outside development.
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    JWT_SECRET_KEY: str = _INSECURE_DEFAULT_JWT_SECRET
    JWT_ALGORITHM: str = "HS256"
    # Short-lived access token (sent as Authorization: Bearer, kept in memory by the SPA)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    # Long-lived refresh session (httpOnly cookie, stored hashed in user_sessions)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30          # "Remember me" sessions
    SESSION_TOKEN_EXPIRE_HOURS: int = 12         # sessions without "Remember me"
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    # Refresh-cookie settings. For a frontend and backend on DIFFERENT sites
    # (e.g. Vercel + Render) set COOKIE_SAMESITE=none and COOKIE_SECURE=true.
    REFRESH_COOKIE_NAME: str = "ms_refresh"
    COOKIE_SECURE: bool | None = None            # None -> auto (True when APP_ENV=production)
    COOKIE_SAMESITE: str = "lax"                 # lax | strict | none
    COOKIE_DOMAIN: str | None = None

    # Brute-force protection for /login
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # --- Google OAuth 2.0 & Gmail Integration ------------------------------
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    # Redirect URI must match exactly what is registered in Google Cloud Console
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    GOOGLE_API_KEY: str = ""

    # Gmail OAuth 2.0 scopes — gmail.readonly is required for inbox forensics
    GMAIL_SCOPES: List[str] = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
    ]

    # --- Fernet symmetric encryption for OAuth tokens at rest ---------------
    # Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Leave empty to use a dev-only insecure fallback (NOT for production).
    FERNET_KEY: str = ""

    # --- Heavy TensorFlow models (disable on small instances, e.g. Render free 512 MB) ---
    LOAD_ML_MODELS: bool = True

    # --- Real-time Gmail monitoring -------------------------------------------
    GMAIL_MONITOR_ENABLED: bool = True          # background poller on/off (server-wide)
    GMAIL_POLL_INTERVAL_SECONDS: int = 60
    GMAIL_MAX_PER_CYCLE: int = 10               # per user per cycle (rate/cost guard)
    GMAIL_LOOKBACK_DAYS: int = 2                # first run only looks at recent mail
    GMAIL_AUTO_QUARANTINE: bool = False         # never modify mailbox unless explicitly enabled

    # --- Privacy / retention ----------------------------------------------------
    DATA_RETENTION_DAYS: int = 90               # investigations older than this are purged (0 = keep)

    # --- Scoring engine config file -----------------------------------------
    SCORING_CONFIG_PATH: str = "app/forensic/scoring_weights.json"

    # --- Hyperledger Fabric Network -----------------------------------------
    FABRIC_NETWORK: str = "local-dev"
    FABRIC_CHANNEL: str = "forensicschannel"
    FABRIC_CHAINCODE: str = "evidence_cc"
    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_PEER_ENDPOINT: str = "localhost:7051"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, v):
        return [o.rstrip("/") for o in _parse_list(v)]

    @field_validator("COOKIE_SAMESITE")
    @classmethod
    def _check_samesite(cls, v: str) -> str:
        v = (v or "lax").lower()
        if v not in {"lax", "strict", "none"}:
            raise ValueError("COOKIE_SAMESITE must be lax, strict or none")
        return v

    @model_validator(mode="after")
    def _finalize(self):
        if self.FRONTEND_URL:
            origin = self.FRONTEND_URL.rstrip("/")
            if origin not in self.CORS_ORIGINS:
                self.CORS_ORIGINS.append(origin)
        if self.COOKIE_SECURE is None:
            self.COOKIE_SECURE = self.is_production or self.COOKIE_SAMESITE == "none"
        if self.is_production and self.DATABASE_URL.startswith("sqlite"):
            raise ValueError(
                "APP_ENV=production requires a persistent cloud database. Set DATABASE_URL to your "
                "PostgreSQL connection string (SQLite files are wiped on every Render restart/deploy)."
            )
        weak_secret = (
            self.JWT_SECRET_KEY == _INSECURE_DEFAULT_JWT_SECRET or len(self.JWT_SECRET_KEY) < 32
        )
        if weak_secret:
            if self.is_production:
                raise ValueError(
                    "JWT_SECRET_KEY is missing or too weak. Set a random value of at least 32 "
                    "characters in the backend environment before starting in production."
                )
            logging.getLogger("mailshield.config").warning(
                "JWT_SECRET_KEY is weak/default — acceptable for local development only."
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
