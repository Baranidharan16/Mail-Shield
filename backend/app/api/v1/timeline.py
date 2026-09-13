"""
Forensic timeline endpoint (Phase 3 Part 13).
Builds a chronological event list from real database records only.
No fabricated timestamps.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from typing import Optional
from app.models.user import User
from utils.auth_deps import get_optional_current_user

router = APIRouter(prefix="/investigations", tags=["timeline"])


@router.get("/{investigation_id}/timeline")
def get_timeline(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.user_id and (not current_user or current_user.id != inv.user_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to view this timeline.")

    events = []

    def _ts(dt):
        if dt is None:
            return None
        return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)

    # 1. Email upload / ingestion
    events.append({
        "type": "INGESTION",
        "label": "Email evidence uploaded",
        "detail": f"File: {inv.original_filename} ({inv.file_size_bytes:,} bytes)",
        "timestamp": _ts(inv.created_at),
        "icon": "upload",
    })

    # 2. Email date (from parsed metadata)
    if inv.email_metadata and inv.email_metadata.date_parsed:
        events.append({
            "type": "EMAIL_DATE",
            "label": "Email composition timestamp",
            "detail": f"Date header: {inv.email_metadata.date_raw}",
            "timestamp": _ts(inv.email_metadata.date_parsed),
            "icon": "mail",
        })

    # 3. Received hops
    for hop in (inv.received_hops or []):
        if hop.timestamp_parsed:
            events.append({
                "type": "RELAY_HOP",
                "label": f"Relay hop {hop.hop_index} observed",
                "detail": f"{hop.from_host or '?'} → {hop.by_host or '?'}" + (f" [{hop.ip_address}]" if hop.ip_address else ""),
                "timestamp": _ts(hop.timestamp_parsed),
                "icon": "network",
            })

    # 4. Audit log entries (system actions)
    audit_entries = (
        db.query(AuditLog)
        .filter(AuditLog.investigation_id == investigation_id)
        .order_by(AuditLog.created_at.asc())
        .all()
    )
    action_icon_map = {
        "FORENSIC_ANALYSIS_COMPLETE": "shield",
        "EVIDENCE_ANCHORED": "link",
        "AI_ANALYSIS": "cpu",
        "THREAT_INTELLIGENCE": "globe",
        "CORRELATION": "share2",
        "AGENT_INVESTIGATION": "bot",
    }
    for entry in audit_entries:
        events.append({
            "type": "SYSTEM",
            "label": entry.action.replace("_", " ").title(),
            "detail": entry.detail or "",
            "timestamp": _ts(entry.created_at),
            "icon": action_icon_map.get(entry.action, "activity"),
            "actor": entry.actor or "system",
        })

    # 5. Analysis completion
    if inv.analyzed_at:
        events.append({
            "type": "ANALYSIS_COMPLETE",
            "label": "Investigation analysis completed",
            "detail": f"Score: {inv.risk_score:.1f}/100 — {inv.classification}" if inv.risk_score else "",
            "timestamp": _ts(inv.analyzed_at),
            "icon": "check-circle",
        })

    # 6. Report generation
    if inv.report:
        events.append({
            "type": "REPORT",
            "label": "Forensic report generated",
            "detail": "Full structured JSON report available",
            "timestamp": _ts(inv.report.generated_at),
            "icon": "file-text",
        })

    # 7. Blockchain anchor
    from app.models.investigation import BlockchainBlock
    block = (
        db.query(BlockchainBlock)
        .filter(BlockchainBlock.case_id == inv.case_id)
        .order_by(BlockchainBlock.block_index.desc())
        .first()
    )
    if block:
        events.append({
            "type": "BLOCKCHAIN",
            "label": "Evidence hash anchored to ledger",
            "detail": f"Block #{block.block_index} · hash: {block.block_hash[:16]}…",
            "timestamp": block.timestamp,
            "icon": "lock",
        })

    # Sort by timestamp ascending (nulls last)
    events.sort(key=lambda e: (e["timestamp"] is None, e["timestamp"] or ""))

    return {"investigation_id": investigation_id, "case_id": inv.case_id, "events": events}
