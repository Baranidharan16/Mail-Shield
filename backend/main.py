from __future__ import annotations
"""
MAILSHIELD - AI-Powered Email Forensic Intelligence Platform
Unified Backend FastAPI Application
"""
# ── CRITICAL: This MUST be imported before ANY keras/tensorflow import. ────────
# Patches builtins.open to default to UTF-8 so Keras can read the
# TextVectorization vocabulary file inside the .keras zip without crashing with:
#   ValueError: 'charmap' codec can't decode byte 0x9d ...
# Setting os.environ["PYTHONUTF8"] mid-process does NOT work (interpreter
# encoding is locked at startup). This builtins.open patch is the only
# reliable in-process fix, and it must run before any `import keras`.
import mailshield_codec_fix  # noqa: F401  (side-effect import)
# ─────────────────────────────────────────────────────────────────────────────


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
    from app.core.config import get_settings as _gs
    _load_models = _gs().LOAD_ML_MODELS

    # MailShield Keras ML + NLP models. They are served by the TensorFlow-free
    # Keras-Lite runtime (models/*.npz), so they load even on Render's 512 MB
    # free instance. LOAD_ML_MODELS=false only forbids falling back to full
    # TensorFlow when an .npz export is missing.
    from pathlib import Path as _P
    _models_dir = _P(__file__).resolve().parent / "models"
    _have_lite = all((_models_dir / n).exists() for n in
                     ("Mailshield_phishing_model_v2.npz", "MailShield_NLP_v2.npz"))
    if not (_load_models or _have_lite):
        logger.info(
            "LOAD_ML_MODELS=false and no Keras-Lite exports found - "
            "analysis uses the scikit-learn models + rule engine."
        )
    else:
        # Load ML Model (Keras phishing detector)
        try:
            ml_service = get_ml_service()
            ml_service.load()
            logger.info("MailShield ML Phishing Detection Model loaded into RAM.")
        except Exception:
            logger.exception(
                "Could not load optional Keras ML model - falling back to "
                "scikit-learn models + rule engine."
            )

        # Load NLP Model (Keras)
        try:
            nlp_service = get_nlp_service()
            nlp_service.load()
            logger.info("MailShield NLP Threat-Pattern Model loaded into RAM.")
        except Exception:
            logger.exception(
                "Could not load optional Keras NLP model - falling back to "
                "scikit-learn models + rule engine."
            )

    # Initialize legacy database if available
    try:
        from app.database.session import init_db
        init_db()
        logger.info("Database initialized.")
    except Exception as e:
        logger.warning("Database initialization note: %s", e)

    # Real-time Gmail monitor + retention purge
    try:
        from services.email_monitor import start_monitor
        start_monitor()
        from app.database.session import SessionLocal
        from app.services.data_lifecycle import purge_expired
        _db = SessionLocal()
        try:
            purge_expired(_db)
        finally:
            _db.close()
    except Exception as e:
        logger.warning("Monitor/retention startup note: %s", e)

    yield

    from services.email_monitor import stop_monitor
    await stop_monitor()
    logger.info("Shutting down MailShield backend.")


app = FastAPI(
    title="MAILSHIELD",
    description="AI-Powered Email Forensic Intelligence & Threat Detection Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Only explicitly configured origins may make credentialed requests. Configure
# with CORS_ORIGINS (JSON list or comma-separated) and/or FRONTEND_URL.
# NOTE: a wildcard like https://*.vercel.app is deliberately NOT allowed —
# anyone can deploy a site there and it would be able to use visitors' sessions.
from app.core.config import get_settings  # noqa: E402

settings = get_settings()
CORS_ORIGINS = list(settings.CORS_ORIGINS)
logger.info("CORS allowed origins: %s", CORS_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-API-Key"],
    expose_headers=["X-Auth-Error", "Retry-After"],
)


# ── Clear errors when the database is unreachable ───────────────────────────
from fastapi import Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from sqlalchemy.exc import OperationalError, InterfaceError  # noqa: E402


@app.exception_handler(OperationalError)
@app.exception_handler(InterfaceError)
async def _db_unavailable_handler(request: Request, exc: Exception):
    logger.error("Database unavailable: %s", type(exc).__name__)
    return JSONResponse(
        status_code=503,
        content={"detail": "The database is temporarily unavailable. Please try again shortly."},
    )


# ── Mount Routers ────────────────────────────────────────────────────────────
from fastapi import Depends  # noqa: E402
from utils.auth_deps import get_current_user, require_resource_owner  # noqa: E402

AUTH = [Depends(get_current_user)]            # must be signed in
OWNER = [Depends(require_resource_owner)]     # signed in AND owns {investigation_id}/{alert_id}

app.include_router(health_router)                          # public: liveness only
app.include_router(auth_router)                            # public: register/login/refresh
app.include_router(analysis_router, dependencies=AUTH)     # scans are saved under the caller
app.include_router(assistant_router, dependencies=AUTH)    # paid AI APIs — no anonymous use
app.include_router(gmail_router)                           # per-route auth (OAuth callback is public)

from app.api.v1 import investigations, alerts, blockchain, dashboard, timeline, cases, chat, sse, system, privacy  # noqa: E402

app.include_router(investigations.router, prefix="/api/v1", dependencies=OWNER)
app.include_router(alerts.router, prefix="/api/v1", dependencies=OWNER)
app.include_router(cases.router, prefix="/api/v1", dependencies=OWNER)
app.include_router(timeline.router, prefix="/api/v1", dependencies=OWNER)
app.include_router(sse.router, prefix="/api/v1", dependencies=OWNER)
app.include_router(dashboard.router, prefix="/api/v1", dependencies=AUTH)
app.include_router(blockchain.router, prefix="/api/v1", dependencies=AUTH)
app.include_router(blockchain.router, prefix="/api", dependencies=AUTH)
app.include_router(chat.router, prefix="/api/v1", dependencies=AUTH)
app.include_router(system.router, prefix="/api/v1", dependencies=AUTH)
app.include_router(privacy.router, prefix="/api/v1", dependencies=AUTH)

# Isolated sandbox → AI-security / GRC / VAPT → threat report → ledger → SOC alarms
from app.api.v1 import advanced  # noqa: E402
app.include_router(advanced.inv_router, prefix="/api/v1", dependencies=OWNER)
app.include_router(advanced.soc_router, prefix="/api/v1", dependencies=AUTH)
logger.info("Mounted all MailShield API routers (auth + forensic + legacy).")


# ── Frontend Static Distribution Serving ─────────────────────────────────────
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("auth/") or full_path in ("api", "auth"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"API route not found: /{full_path}")
        target = FRONTEND_DIST / full_path
        if full_path and target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
