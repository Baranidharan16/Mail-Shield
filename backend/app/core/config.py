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
    # Production target is PostgreSQL (see docker-compose.yml). For local
    # sandboxed development/testing where a Postgres server is not
    # available, DATABASE_URL can be pointed at SQLite instead - the
    # schema/ORM layer is portable across both via SQLAlchemy.
    DATABASE_URL: str = "sqlite:///./forensics.db"

    # --- CORS ------------------------------------------------------------
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # --- File upload -----------------------------------------------------
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [".eml"]
    UPLOAD_STORAGE_DIR: str = "./storage/evidence"

    # --- Trusted organization domain (optional, for domain-mismatch checks)
    TRUSTED_ORG_DOMAINS: List[str] = []

    # --- Rate limiting -----------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 30

    # --- Simple API-key authentication -------------------------------------
    # Phase 1 keeps auth simple per the project brief ("keep simple in Phase 1
    # but design the architecture so role-based authentication can be added
    # later"). When AUTH_ENABLED is true, every request (except /health and
    # API docs) must carry a valid `X-API-Key` header matching one of
    # API_KEYS. Each key maps to a caller identity used to populate
    # investigations.created_by, which is already wired for future RBAC.
    AUTH_ENABLED: bool = False
    API_KEYS: dict[str, str] = {}  # {api_key: caller_identity}

    # --- Phase 2: threat intelligence -------------------------------------
    THREAT_INTEL_DOMAIN_PROVIDER: str = "local"  # "local" (offline heuristic, default) or "dns" (best-effort real DNS)
    THREAT_INTEL_CACHE_TTL_SECONDS: int = 6 * 60 * 60

    # --- Phase 2: data privacy / AI ---------------------------------------
    # When true (default), no email content is ever sent to an external LLM
    # or AI API - all "AI" analysis (ML models, fusion, agent, narrative) is
    # local/deterministic. Phase 1/2 of this platform do not call any
    # external LLM at all, so this flag is enforced trivially today, but is
    # wired through explicitly so a future external-LLM integration cannot
    # silently bypass it.
    LOCAL_ONLY_MODE: bool = False

    # --- Gemini AI API key (for MailShield AI Chatbot) ---------------------
    # Keep empty unless a real API key is configured in the environment.
    GEMINI_API_KEY: str = ""

    # --- Phase 2: demo mode -------------------------------------------------
    DEMO_MODE_ENABLED: bool = True

    # --- Scoring engine config file --------------------------------------
    SCORING_CONFIG_PATH: str = "app/forensic/scoring_weights.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()
