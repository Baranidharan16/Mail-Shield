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
from app.models.user import User
from utils.auth_deps import get_optional_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    base_q = db.query(Investigation)
    if current_user:
        base_q = base_q.filter(Investigation.user_id == current_user.id)
    else:
        base_q = base_q.filter(Investigation.user_id.is_(None))

    total = base_q.count()
    critical = base_q.filter(Investigation.classification == "CRITICAL").count()
    high = base_q.filter(Investigation.classification == "HIGH").count()
    medium = base_q.filter(Investigation.classification == "MEDIUM").count()
    low = base_q.filter(Investigation.classification == "LOW").count()
    processing = base_q.filter(
        Investigation.status.in_(["QUEUED", "PROCESSING"])
    ).count()
    completed = base_q.filter(Investigation.status == "COMPLETED").count()
    failed = base_q.filter(Investigation.status == "FAILED").count()
    campaigns = db.query(Campaign).count()

    alerts_q = db.query(Alert).filter(Alert.acknowledged == False)  # noqa: E712
    if current_user:
        alerts_q = alerts_q.join(Investigation).filter(Investigation.user_id == current_user.id)
    active_alerts = alerts_q.count()

    return {
        "total_investigations": total,
        "phishing_detected": critical + high,
        "safe_emails": low,
        "high_risk_emails": critical + high,
        "critical_incidents": critical,
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
def get_threat_trend(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """Returns daily classification breakdown for the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(Investigation).filter(Investigation.created_at >= since, Investigation.status == "COMPLETED")
    if current_user:
        q = q.filter(Investigation.user_id == current_user.id)
    else:
        q = q.filter(Investigation.user_id.is_(None))

    rows = q.order_by(Investigation.created_at.asc()).all()
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
def get_recent_alerts(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    alerts_q = db.query(Alert).join(Investigation, Alert.investigation_id == Investigation.id)
    if current_user:
        alerts_q = alerts_q.filter(Investigation.user_id == current_user.id)
    else:
        alerts_q = alerts_q.filter(Investigation.user_id.is_(None))

    alerts = (
        alerts_q
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
