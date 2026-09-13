from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.error_handlers import register_exception_handlers
from app.core.rate_limit import RateLimitMiddleware
from app.database.session import init_db
from app.api.v1 import investigations, health, alerts, blockchain, dashboard, timeline, cases, chat, sse, system

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("forensic_platform")

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-Powered Email Threat Detection, GeoLocation and Forensic "
        "Intelligence Platform - SIH 2026 Problem Statement 26106 "
        "(AICTE Cyber Security Cell). Phase 1: forensic analysis foundation."
    ),
    version="0.1.0-phase1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)

register_exception_handlers(app)

app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(investigations.router, prefix=settings.API_V1_PREFIX)
app.include_router(alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(blockchain.router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_V1_PREFIX)
app.include_router(timeline.router, prefix=settings.API_V1_PREFIX)
app.include_router(cases.router, prefix=settings.API_V1_PREFIX)
app.include_router(chat.router, prefix=settings.API_V1_PREFIX)
app.include_router(sse.router, prefix=settings.API_V1_PREFIX)
app.include_router(system.router, prefix=settings.API_V1_PREFIX)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("%s starting up. DB=%s", settings.APP_NAME, settings.DATABASE_URL.split("://")[0])


from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Check for frontend build artifacts to serve as a unified full-stack platform
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    # Mount assets directory if present
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Serve exact file if it exists in dist (e.g. favicon, vite.svg)
        target = FRONTEND_DIST / full_path
        if full_path and target.exists() and target.is_file():
            return FileResponse(str(target))
        # Otherwise fallback to index.html for client-side routing
        return FileResponse(str(FRONTEND_DIST / "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "app": settings.APP_NAME,
            "phase": "Phase 1",
            "docs": "/docs",
            "health": f"{settings.API_V1_PREFIX}/health",
        }
