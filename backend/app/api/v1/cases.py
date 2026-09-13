"""
Case management endpoints (Phase 3 Part 15/16).
Cases in this system are Investigations with case-management fields.
Provides chain-of-custody via the AuditLog.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_current_caller
from app.database.session import get_db
from app.models.investigation import AuditLog, Investigation
from app.models.user import User
from utils.auth_deps import get_optional_current_user

logger = logging.getLogger("forensic_platform")
router = APIRouter(prefix="/cases", tags=["cases"])


class CasePatchRequest(BaseModel):
    case_status: Optional[str] = None   # OPEN/UNDER_INVESTIGATION/RESOLVED/ARCHIVED
    analyst: Optional[str] = None
    note: Optional[str] = None          # Appends a note; stored in Investigation.notes JSON list


@router.get("")
def list_cases(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    q = db.query(Investigation)
    if current_user:
        q = q.filter(Investigation.user_id == current_user.id)
    else:
        q = q.filter(Investigation.user_id.is_(None))

    if status:
        q = q.filter(Investigation.case_status == status.upper())
    rows = q.order_by(Investigation.created_at.desc()).offset(offset).limit(min(limit, 200)).all()
    return [_case_summary(inv) for inv in rows]


@router.get("/{investigation_id}")
def get_case(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Case not found")

    if inv.user_id and (not current_user or current_user.id != inv.user_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to view this case.")

    return _case_summary(inv)


@router.patch("/{investigation_id}")
def update_case(
    investigation_id: str,
    body: CasePatchRequest,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Case not found")

    if inv.user_id and (not current_user or current_user.id != inv.user_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to modify this case.")


    actor = caller or "unauthenticated-analyst"

    if body.case_status:
        valid_statuses = {"OPEN", "UNDER_INVESTIGATION", "RESOLVED", "ARCHIVED"}
        if body.case_status.upper() not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid case_status. Must be one of: {valid_statuses}")
        inv.case_status = body.case_status.upper()
        db.add(AuditLog(investigation_id=investigation_id, actor=actor, action="CASE_STATUS_UPDATE", detail=f"→ {inv.case_status}"))

    if body.analyst is not None:
        inv.analyst = body.analyst
        db.add(AuditLog(investigation_id=investigation_id, actor=actor, action="ANALYST_ASSIGNED", detail=f"analyst={body.analyst}"))

    if body.note:
        from datetime import datetime, timezone
        notes = list(inv.notes or [])
        notes.append({"author": actor, "text": body.note, "created_at": datetime.now(timezone.utc).isoformat()})
        inv.notes = notes
        db.add(AuditLog(investigation_id=investigation_id, actor=actor, action="NOTE_ADDED", detail=body.note[:200]))

    db.add(inv)
    db.commit()
    return _case_summary(inv)


@router.get("/{investigation_id}/chain-of-custody")
def get_chain_of_custody(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Case not found")

    audit = (
        db.query(AuditLog)
        .filter(AuditLog.investigation_id == investigation_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )

    from app.models.investigation import AgentActionLog, BlockchainBlock
    agent_logs = (
        db.query(AgentActionLog)
        .filter(AgentActionLog.investigation_id == investigation_id)
        .order_by(AgentActionLog.created_at.asc())
        .all()
    )
    block = (
        db.query(BlockchainBlock)
        .filter(BlockchainBlock.case_id == inv.case_id)
        .order_by(BlockchainBlock.block_index.desc())
        .first()
    )

    return {
        "case_id": inv.case_id,
        "investigation_id": investigation_id,
        "evidence_hash": inv.evidence_hash_sha256,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "created_by": inv.created_by or "anonymous",
        "blockchain_anchor": {
            "block_index": block.block_index if block else None,
            "block_hash": block.block_hash if block else None,
            "anchored_at": block.timestamp if block else None,
        },
        "audit_trail": [
            {"timestamp": a.created_at.isoformat() if a.created_at else None,
             "actor": a.actor, "action": a.action, "detail": a.detail}
            for a in audit
        ],
        "agent_actions": [
            {"timestamp": a.created_at.isoformat() if a.created_at else None,
             "tool": a.tool_name, "succeeded": a.succeeded, "duration_ms": a.duration_ms}
            for a in agent_logs
        ],
    }


def _case_summary(inv: Investigation) -> dict:
    return {
        "id": inv.id,
        "case_id": inv.case_id,
        "original_filename": inv.original_filename,
        "status": inv.status,
        "case_status": inv.case_status,
        "classification": inv.classification,
        "risk_score": inv.risk_score,
        "confidence": inv.confidence,
        "analyst": inv.analyst,
        "severity": inv.severity,
        "campaign_id": inv.campaign_id,
        "notes": inv.notes or [],
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "analyzed_at": inv.analyzed_at.isoformat() if inv.analyzed_at else None,
        "processing_stage": inv.processing_stage,
    }
