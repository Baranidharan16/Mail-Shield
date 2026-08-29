from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.schemas.investigation import HealthOut

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
    return HealthOut(status="ok", app_name=settings.APP_NAME, database=db_status)
