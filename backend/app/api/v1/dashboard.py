"""
Dashboard aggregate statistics endpoint (Phase 3).
Provides real counts from the database — no fabricated numbers.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.investigation import Alert, Campaign, Investigation

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(Investigation).count()
    critical = db.query(Investigation).filter(Investigation.classification == "CRITICAL").count()
    high = db.query(Investigation).filter(Investigation.classification == "HIGH").count()
    medium = db.query(Investigation).filter(Investigation.classification == "MEDIUM").count()
    low = db.query(Investigation).filter(Investigation.classification == "LOW").count()
    processing = db.query(Investigation).filter(
        Investigation.status.in_(["QUEUED", "PROCESSING"])
    ).count()
    completed = db.query(Investigation).filter(Investigation.status == "COMPLETED").count()
    failed = db.query(Investigation).filter(Investigation.status == "FAILED").count()
    campaigns = db.query(Campaign).count()
    active_alerts = db.query(Alert).filter(Alert.acknowledged == False).count()  # noqa: E712

    return {
        "total_investigations": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "processing": processing,
        "completed": completed,
        "failed": failed,
        "campaigns": campaigns,
        "active_alerts": active_alerts,
    }


@router.get("/threat_trend")
def get_threat_trend(days: int = 7, db: Session = Depends(get_db)):
    """Returns daily classification breakdown for the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(Investigation)
        .filter(Investigation.created_at >= since, Investigation.status == "COMPLETED")
        .order_by(Investigation.created_at.asc())
        .all()
    )
    # Bucket by date
    from collections import defaultdict
    buckets: dict = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0})
    for inv in rows:
        day = inv.created_at.strftime("%Y-%m-%d") if inv.created_at else "unknown"
        cls = inv.classification or "LOW"
        buckets[day][cls] = buckets[day].get(cls, 0) + 1
        buckets[day]["total"] += 1

    return {"days": days, "data": [{"date": d, **v} for d, v in sorted(buckets.items())]}


@router.get("/recent_alerts")
def get_recent_alerts(limit: int = 10, db: Session = Depends(get_db)):
    alerts = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(min(limit, 50))
        .all()
    )
    return [
        {
            "id": a.id,
            "investigation_id": a.investigation_id,
            "severity": a.severity,
            "classification": a.classification,
            "threat_score": a.threat_score,
            "key_reason": a.key_reason,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]
