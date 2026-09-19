"""Privacy, data-control and real-time monitor endpoints (all scoped to the caller)."""
from __future__ import annotations

from datetime import timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.models.investigation import Investigation
from app.models.processed_email import MonitorState, ProcessedEmail
from app.models.user import User
from utils.auth_deps import get_current_user

router = APIRouter(tags=["privacy-and-monitoring"])


def _iso(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@router.get("/privacy/my-data")
def my_data_summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.models.gmail_account import GmailAccount
    s = get_settings()
    return {
        "account": {"name": user.name, "email": user.email, "created_at": _iso(user.created_at)},
        "investigations": db.query(Investigation).filter(Investigation.user_id == user.id).count(),
        "processed_emails": db.query(ProcessedEmail).filter(ProcessedEmail.user_id == user.id).count(),
        "gmail_connected": db.query(GmailAccount).filter(GmailAccount.user_id == user.id,
                                                         GmailAccount.is_active == True).count() > 0,  # noqa: E712
        "retention_days": s.DATA_RETENTION_DAYS,
        "auto_quarantine": s.GMAIL_AUTO_QUARANTINE,
    }


@router.delete("/privacy/my-data")
def delete_my_data(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Right to erasure: deletes all of the caller's investigations, evidence files,
    monitor records and stored Gmail OAuth tokens. The login account itself stays."""
    from app.models.gmail_account import GmailAccount
    from app.services.data_lifecycle import delete_investigations
    ids = [r[0] for r in db.query(Investigation.id).filter(Investigation.user_id == user.id).all()]
    n = delete_investigations(db, ids)
    db.query(ProcessedEmail).filter(ProcessedEmail.user_id == user.id).delete(synchronize_session=False)
    db.query(MonitorState).filter(MonitorState.user_id == user.id).delete(synchronize_session=False)
    db.query(GmailAccount).filter(GmailAccount.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    return {"deleted_investigations": n, "gmail_tokens_deleted": True,
            "message": "All your forensic data and stored Gmail tokens were deleted."}


@router.delete("/investigations/{investigation_id}")
def delete_one_investigation(investigation_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.services.data_lifecycle import delete_investigations
    inv = db.get(Investigation, investigation_id)
    if not inv or inv.user_id != user.id:
        raise HTTPException(status_code=404, detail="Investigation not found")
    delete_investigations(db, [inv.id])
    return {"deleted": True}


# ── real-time monitor ───────────────────────────────────────────────────────
class ToggleRequest(BaseModel):
    enabled: bool


@router.get("/monitor/status")
def monitor_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from app.models.gmail_account import GmailAccount
    from services.email_monitor import last_cycle
    s = get_settings()
    st = db.get(MonitorState, user.id)
    connected = db.query(GmailAccount).filter(GmailAccount.user_id == user.id,
                                              GmailAccount.is_active == True).count() > 0  # noqa: E712
    return {
        "server_monitor_enabled": s.GMAIL_MONITOR_ENABLED,
        "poll_interval_seconds": s.GMAIL_POLL_INTERVAL_SECONDS,
        "gmail_connected": connected,
        "enabled_for_you": (st.enabled if st else True) and connected,
        "last_run_at": _iso(st.last_run_at) if st else None,
        "last_success_at": _iso(st.last_success_at) if st else None,
        "last_error": st.last_error if st else None,
        "messages_processed": st.messages_processed if st else 0,
        "server_last_cycle": {k: v for k, v in last_cycle().items() if k != "users"},
    }


@router.post("/monitor/toggle")
def monitor_toggle(body: ToggleRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    st = db.get(MonitorState, user.id)
    if st is None:
        st = MonitorState(user_id=user.id, enabled=body.enabled)
        db.add(st)
    else:
        st.enabled = body.enabled
    db.commit()
    return {"enabled": st.enabled}


@router.post("/monitor/run-now")
async def monitor_run_now(user: User = Depends(get_current_user)):
    from services.email_monitor import process_user
    n = await process_user(user.id)
    return {"analyzed": n}


@router.get("/monitor/recent")
def monitor_recent(limit: int = 30, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (db.query(ProcessedEmail).filter(ProcessedEmail.user_id == user.id)
            .order_by(ProcessedEmail.processed_at.desc()).limit(max(1, min(limit, 100))).all())
    out = []
    for r in rows:
        inv = db.get(Investigation, r.investigation_id) if r.investigation_id else None
        if inv is not None and inv.user_id != user.id:
            inv = None
        meta = inv.email_metadata if inv else None
        out.append({
            "message_id": r.provider_message_id, "status": r.status, "detail": r.detail,
            "processed_at": _iso(r.processed_at), "investigation_id": inv.id if inv else None,
            "case_id": inv.case_id if inv else None,
            "subject": meta.subject if meta else None, "sender": meta.from_address if meta else None,
            "risk_score": inv.risk_score if inv else None, "classification": inv.classification if inv else None,
            "verdict": ("THREAT" if (inv.risk_score or 0) >= 50 else "SUSPICIOUS" if (inv.risk_score or 0) >= 25 else "SAFE") if inv and inv.status == "COMPLETED" else None,
        })
    return out
