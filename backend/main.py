"""
MAILSHIELD - AI-Powered Email Forensic Intelligence Platform
Unified Backend FastAPI Application
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load environment variables from .env
env_path = Path(__file__).resolve().parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Import MailShield core services for lifecycle initialization
from services.ml_service import get_ml_service
from services.nlp_service import get_nlp_service

# Import MailShield route modules
from routes.health import router as health_router
from routes.analysis import router as analysis_router
from routes.assistant import router as assistant_router
from routes.auth import router as auth_router
from routes.gmail import router as gmail_router

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mailshield.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to load models once at application startup."""
    logger.info("Initializing MailShield Backend Services...")

    # Load ML Model (mailshield_ml.keras)
    try:
        ml_service = get_ml_service()
        ml_service.load()
        logger.info("MailShield ML Phishing Detection Model loaded into RAM.")
    except Exception as e:
        logger.error("Failed to load ML Model: %s", e)

    # Load NLP Model (mailshield_nlp.keras)
    try:
        nlp_service = get_nlp_service()
        nlp_service.load()
        logger.info("MailShield NLP Threat-Pattern Model loaded into RAM.")
    except Exception as e:
        logger.error("Failed to load NLP Model: %s", e)

    # Initialize legacy database if available
    try:
        from app.database.session import init_db
        init_db()
        logger.info("Database initialized.")
    except Exception as e:
        logger.warning("Database initialization note: %s", e)

    yield

    logger.info("Shutting down MailShield backend.")


app = FastAPI(
    title="MAILSHIELD",
    description="AI-Powered Email Forensic Intelligence & Threat Detection Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for local development and frontend
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

env_cors = os.getenv("CORS_ORIGINS")
if env_cors:
    for origin in env_cors.split(","):
        o = origin.strip()
        if o and o not in CORS_ORIGINS:
            CORS_ORIGINS.append(o)

frontend_url = os.getenv("FRONTEND_URL")
if frontend_url and frontend_url not in CORS_ORIGINS:
    CORS_ORIGINS.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=r"https://.*\.vercel\.app",
)

# ── Mount Core API Routers ───────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(analysis_router)
app.include_router(assistant_router)
app.include_router(auth_router)
app.include_router(gmail_router)

# ── Mount Legacy Routers to Preserve Platform Depth (SOC, Dossier, Timeline) ─
try:
    from app.api.v1 import investigations, health, alerts, blockchain, dashboard, timeline, cases, chat, sse, system
    app.include_router(investigations.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(blockchain.router, prefix="/api/v1")
    app.include_router(blockchain.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api/v1")
    app.include_router(timeline.router, prefix="/api/v1")
    app.include_router(cases.router, prefix="/api/v1")
    app.include_router(chat.router, prefix="/api/v1")
    app.include_router(sse.router, prefix="/api/v1")
    app.include_router(system.router, prefix="/api/v1")
    logger.info("Mounted all MailShield API routers (auth + forensic + legacy).")
except Exception as e:
    logger.warning("Could not mount legacy routers: %s", e)


# ── Frontend Static Distribution Serving ─────────────────────────────────────
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("auth"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"API route not found: /{full_path}")
        target = FRONTEND_DIST / full_path
        if full_path and target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
