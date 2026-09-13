"""
Application configuration.

All configurable values are read from environment variables (with sane
local-development defaults) so that no secrets are ever hard-coded in
source control, per project SECURITY requirements.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

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
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
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
    JWT_SECRET_KEY: str = "mailshield-insecure-dev-secret-key-change-in-production-2026"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

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

    # --- Scoring engine config file -----------------------------------------
    SCORING_CONFIG_PATH: str = "app/forensic/scoring_weights.json"

    # --- Hyperledger Fabric Network -----------------------------------------
    FABRIC_NETWORK: str = "local-dev"
    FABRIC_CHANNEL: str = "forensicschannel"
    FABRIC_CHAINCODE: str = "evidence_cc"
    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_PEER_ENDPOINT: str = "localhost:7051"


@lru_cache
def get_settings() -> Settings:
    return Settings()
