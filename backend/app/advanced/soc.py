"""SOC alarm engine + per-analyst configuration.

An alarm is raised (not just a row in a list) when a case crosses the
analyst's configured severity, when the sandbox proves an artefact
malicious, or when GRC finds a legal violation. The UI polls active alarms
and sounds a siren / browser notification until acknowledged; an optional
HTTPS webhook forwards a content-free alert to Slack / Teams / a SIEM.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.models.advanced import SocAlarm, SocConfig

logger = logging.getLogger("mailshield.soc")
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
CONFIG_FIELDS = ("alarm_enabled", "min_severity", "sound_enabled", "browser_notifications", "repeat_until_ack",
                 "repeat_interval_seconds", "sandbox_scope", "alarm_on_sandbox_malicious", "alarm_on_grc_violation",
                 "auto_escalate_critical", "escalation_contact", "webhook_url")


def get_config(db: Session, user_id: str) -> SocConfig:
    cfg = db.query(SocConfig).filter(SocConfig.user_id == user_id).first()
    if cfg is None:
        cfg = SocConfig(user_id=user_id)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def config_dict(cfg: SocConfig) -> dict:
    return {k: getattr(cfg, k) for k in CONFIG_FIELDS} | {"updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None}


def validate_webhook(url: Optional[str]) -> Optional[str]:
    """https only, and never to private / loopback / link-local addresses (SSRF guard)."""
    if not url:
        return None
    sp = urlsplit(url.strip())
    if sp.scheme != "https" or not sp.hostname:
        raise ValueError("Webhook must be an https:// URL.")
    try:
        infos = socket.getaddrinfo(sp.hostname, sp.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("Webhook host does not resolve.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Webhook may not target private or internal addresses.")
    return url.strip()


def update_config(db: Session, user_id: str, data: dict) -> SocConfig:
    cfg = get_config(db, user_id)
    for k, v in data.items():
        if k not in CONFIG_FIELDS or v is None and k not in ("escalation_contact", "webhook_url"):
            continue
        if k == "min_severity" and v not in ("MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError("min_severity must be MEDIUM, HIGH or CRITICAL.")
        if k == "sandbox_scope" and v not in ("SUSPICIOUS", "ALL", "OFF"):
            raise ValueError("sandbox_scope must be SUSPICIOUS, ALL or OFF.")
        if k == "repeat_interval_seconds":
            v = max(10, min(600, int(v)))
        if k == "webhook_url":
            v = validate_webhook(v)
        if k == "escalation_contact" and v:
            v = str(v)[:256]
        setattr(cfg, k, v)
    db.commit()
    db.refresh(cfg)
    return cfg


def _post_webhook(url: str, payload: dict, alarm_id: str) -> None:
    from app.database.session import SessionLocal
    status = "sent"
    try:
        import httpx
        validate_webhook(url)
        r = httpx.post(url, json=payload, timeout=10, follow_redirects=False)
        status = f"HTTP {r.status_code}"
    except Exception as exc:  # noqa: BLE001
        status = f"failed: {type(exc).__name__}"
    db = SessionLocal()
    try:
        a = db.get(SocAlarm, alarm_id)
        if a:
            a.webhook_status = status[:64]
            db.commit()
    finally:
        db.close()


def raise_alarm(db: Session, user_id: Optional[str], severity: str, source: str, title: str, message: str,
                investigation_id: Optional[str] = None, case_id: Optional[str] = None, force: bool = False) -> Optional[SocAlarm]:
    if not user_id:
        return None
    cfg = get_config(db, user_id)
    if not force:
        if not cfg.alarm_enabled or SEV_ORDER.get(severity, 0) < SEV_ORDER.get(cfg.min_severity, 2):
            return None
        if source == "SANDBOX" and not cfg.alarm_on_sandbox_malicious:
            return None
        if source == "GRC" and not cfg.alarm_on_grc_violation:
            return None
        # one active alarm per case+source
        dup = db.query(SocAlarm).filter(SocAlarm.user_id == user_id, SocAlarm.investigation_id == investigation_id,
                                        SocAlarm.source == source, SocAlarm.status == "ACTIVE").first()
        if dup and investigation_id:
            return dup
    alarm = SocAlarm(user_id=user_id, investigation_id=investigation_id, case_id=case_id, severity=severity, source=source,
                     title=title[:256], message=message, escalated=bool(cfg.auto_escalate_critical and severity == "CRITICAL"))
    db.add(alarm)
    db.commit()
    db.refresh(alarm)
    if cfg.webhook_url:
        payload = {"product": "MailShield", "alarm_id": alarm.id, "case_id": case_id, "severity": severity, "source": source,
                   "title": title, "escalated": alarm.escalated, "raised_at": datetime.now(timezone.utc).isoformat(),
                   "note": "Content-free alert. Open MailShield for evidence."}
        threading.Thread(target=_post_webhook, args=(cfg.webhook_url, payload, alarm.id), daemon=True).start()
    logger.info("SOC alarm %s raised: %s %s (%s)", alarm.id, severity, source, case_id)
    return alarm


def alarm_dict(a: SocAlarm) -> dict:
    return {"id": a.id, "investigation_id": a.investigation_id, "case_id": a.case_id, "severity": a.severity,
            "source": a.source, "title": a.title, "message": a.message, "status": a.status, "escalated": a.escalated,
            "webhook_status": a.webhook_status, "acknowledged_by": a.acknowledged_by,
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            "created_at": a.created_at.isoformat() if a.created_at else None}
