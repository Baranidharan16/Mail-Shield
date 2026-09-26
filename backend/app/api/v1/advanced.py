"""API for the sandbox / AI-security / GRC / VAPT / SOC-alarm pipeline.

Investigation routes are mounted with the router-level owner guard
(require_resource_owner) so only the case owner can read or trigger them.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.advanced import soc
from app.advanced.pipeline import advanced_view, is_running, schedule_advanced_pipeline
from app.database.session import get_db
from app.models.advanced import AdvancedAnalysis, SocAlarm
from app.models.investigation import Investigation
from app.models.user import User
from app.sandbox import client as sandbox_client
from utils.auth_deps import get_current_user

inv_router = APIRouter(prefix="/investigations", tags=["sandbox-threat-report"])
soc_router = APIRouter(prefix="/soc", tags=["soc-alarms"])


def _adv(db: Session, investigation_id: str) -> Optional[AdvancedAnalysis]:
    return db.query(AdvancedAnalysis).filter(AdvancedAnalysis.investigation_id == investigation_id).first()


def _view(db: Session, investigation_id: str) -> dict:
    adv = _adv(db, investigation_id)
    v = advanced_view(adv, is_running(investigation_id))
    tr = v.get("threat_report")
    if tr and adv and adv.ledger_block_index is not None:
        tr = copy.deepcopy(tr)
        for s in tr.get("pipeline", []):
            if s["step"] == "Blockchain audit log":
                s.update(status="ANCHORED", detail=f"Block #{adv.ledger_block_index} · {adv.ledger_block_hash[:16]}…",
                         at=adv.updated_at.isoformat() if adv.updated_at else None)
        v["threat_report"] = tr
    return v


@inv_router.get("/{investigation_id}/advanced")
def get_advanced(investigation_id: str, db: Session = Depends(get_db)):
    """Quarantine + sandbox + AI-security + GRC + VAPT + consolidated threat report for one case."""
    return _view(db, investigation_id)


@inv_router.post("/{investigation_id}/sandbox/run")
def run_sandbox(investigation_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """(Re)submit the case's artefacts to the isolated sandbox and rebuild the threat report."""
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    if inv.status != "COMPLETED":
        raise HTTPException(409, "Analysis has not completed yet.")
    if is_running(investigation_id):
        return {"queued": False, "detail": "Already running."}
    schedule_advanced_pipeline(investigation_id, None, "MANUAL_RERUN", force_sandbox=True)
    return {"queued": True, "detail": "Artefacts submitted to the isolated sandbox."}


@inv_router.get("/{investigation_id}/threat-report")
def threat_report_json(investigation_id: str, db: Session = Depends(get_db)):
    v = _view(db, investigation_id)
    if not v.get("threat_report"):
        raise HTTPException(409, "Threat report not ready yet.")
    return {**v["threat_report"], "ledger": v["ledger"]}


@inv_router.get("/{investigation_id}/threat-report/pdf")
def threat_report_pdf(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    v = _view(db, investigation_id)
    if not v.get("threat_report") or inv is None:
        raise HTTPException(409, "Threat report not ready yet.")
    from app.reports.pdf_report import generate_pdf_report
    base = inv.report.report_json if inv.report else {"case_id": inv.case_id}
    pdf = generate_pdf_report(base, advanced=v)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{inv.case_id}_threat_report.pdf"'})


# ── SOC configuration & alarms ──────────────────────────────────────────────
class SocConfigIn(BaseModel):
    alarm_enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    sound_enabled: Optional[bool] = None
    browser_notifications: Optional[bool] = None
    repeat_until_ack: Optional[bool] = None
    repeat_interval_seconds: Optional[int] = None
    sandbox_scope: Optional[str] = None
    alarm_on_sandbox_malicious: Optional[bool] = None
    alarm_on_grc_violation: Optional[bool] = None
    auto_escalate_critical: Optional[bool] = None
    escalation_contact: Optional[str] = None
    webhook_url: Optional[str] = None


@soc_router.get("/config")
def get_soc_config(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return soc.config_dict(soc.get_config(db, user.id))


@soc_router.put("/config")
def put_soc_config(body: SocConfigIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        cfg = soc.update_config(db, user.id, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return soc.config_dict(cfg)


@soc_router.get("/alarms")
def list_alarms(status: Optional[str] = None, limit: int = 50, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    q = db.query(SocAlarm).filter(SocAlarm.user_id == user.id)
    if status:
        q = q.filter(SocAlarm.status == status.upper())
    rows = q.order_by(SocAlarm.created_at.desc()).limit(max(1, min(limit, 200))).all()
    active = db.query(SocAlarm).filter(SocAlarm.user_id == user.id, SocAlarm.status == "ACTIVE").count()
    return {"active_count": active, "alarms": [soc.alarm_dict(a) for a in rows]}


@soc_router.post("/alarms/{alarm_id}/ack")
def ack_alarm(alarm_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    a = db.query(SocAlarm).filter(SocAlarm.id == alarm_id, SocAlarm.user_id == user.id).first()
    if not a:
        raise HTTPException(404, "Alarm not found")
    if a.status == "ACTIVE":
        a.status, a.acknowledged_by, a.acknowledged_at = "ACKNOWLEDGED", user.email, datetime.now(timezone.utc)
        db.commit()
    return soc.alarm_dict(a)


@soc_router.post("/alarms/ack-all")
def ack_all(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    n = (db.query(SocAlarm).filter(SocAlarm.user_id == user.id, SocAlarm.status == "ACTIVE")
         .update({"status": "ACKNOWLEDGED", "acknowledged_by": user.email, "acknowledged_at": now}, synchronize_session=False))
    db.commit()
    return {"acknowledged": n}


@soc_router.post("/alarms/test")
def test_alarm(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    a = soc.raise_alarm(db, user.id, "HIGH", "TEST", "Test alarm — SOC alerting is working",
                        "Triggered from SOC configuration.", force=True)
    return soc.alarm_dict(a)


@soc_router.get("/sandbox/health")
def sandbox_health():
    h = sandbox_client.health()
    h["isolation"] = {"separate_service": True, "auth": "HMAC-SHA256 signed requests",
                      "data_shared": "attachment bytes, URLs, HTML body only"}
    return h
