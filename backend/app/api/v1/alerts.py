from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.investigation import Alert, Investigation, AuditLog
from app.models.user import User
from app.core.auth import get_current_caller
from utils.auth_deps import get_optional_current_user

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertPatchRequest(BaseModel):
    acknowledged: Optional[bool] = None
    status: Optional[str] = None       # DETECTED/TRIAGED/INVESTIGATING/CONTAINED/RESOLVED
    analyst: Optional[str] = None
    note: Optional[str] = None


@router.get("")
def list_alerts(
    db: Session = Depends(get_db),
    limit: int = 100,
    offset: int = 0,
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Returns alerts scoped to the authenticated user's investigations."""
    q = db.query(Alert).join(Investigation, Alert.investigation_id == Investigation.id)
    if current_user:
        q = q.filter(Investigation.user_id == current_user.id)
    else:
        q = q.filter(Investigation.user_id.is_(None))
    alerts = q.order_by(Alert.created_at.desc()).offset(offset).limit(min(limit, 500)).all()
    out = []
    for a in alerts:
        inv = db.get(Investigation, a.investigation_id)
        out.append({
            "id": a.id,
            "investigation_id": a.investigation_id,
            "case_id": inv.case_id if inv else None,
            "original_filename": inv.original_filename if inv else None,
            "sender": (inv.email_metadata.from_address if inv and inv.email_metadata else None),
            "subject": (inv.email_metadata.subject if inv and inv.email_metadata else None),
            "severity": a.severity,
            "threat_score": a.threat_score,
            "classification": a.classification,
            "key_reason": a.key_reason,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "acknowledged": a.acknowledged,
            "status": getattr(a, "alert_status", "DETECTED"),
            "analyst": getattr(a, "alert_analyst", None),
        })
    return out


@router.get("/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    inv = db.get(Investigation, a.investigation_id)
    return {
        "id": a.id,
        "investigation_id": a.investigation_id,
        "case_id": inv.case_id if inv else None,
        "original_filename": inv.original_filename if inv else None,
        "sender": (inv.email_metadata.from_address if inv and inv.email_metadata else None),
        "subject": (inv.email_metadata.subject if inv and inv.email_metadata else None),
        "severity": a.severity,
        "threat_score": a.threat_score,
        "classification": a.classification,
        "key_reason": a.key_reason,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "acknowledged": a.acknowledged,
        "status": getattr(a, "alert_status", "DETECTED"),
        "analyst": getattr(a, "alert_analyst", None),
    }


@router.patch("/{alert_id}")
def update_alert(
    alert_id: str,
    body: AlertPatchRequest,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.acknowledged is not None:
        a.acknowledged = body.acknowledged
    db.add(a)
    db.commit()
    return {"id": a.id, "acknowledged": a.acknowledged}
