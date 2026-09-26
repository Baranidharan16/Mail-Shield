"""Tables for the post-detection pipeline:
Suspicious e-mail -> Quarantine -> Isolated Sandbox -> AI-security / GRC / VAPT
-> consolidated Threat Report -> Blockchain audit -> SOC alarm.

investigation_id is a plain indexed column (no FK) so it never blocks the
existing retention / right-to-erasure deletes; data_lifecycle.delete_investigations
removes these rows automatically because they carry an `investigation_id` column.
"""
from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, JSON

from app.database.session import Base
from app.models.investigation import gen_uuid, utcnow


class AdvancedAnalysis(Base):
    __tablename__ = "advanced_analyses"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), nullable=False, unique=True, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    case_id = Column(String(32), nullable=True)

    pipeline_status = Column(String(24), nullable=False, default="PENDING")   # PENDING/RUNNING/COMPLETED/FAILED
    trigger = Column(String(24), nullable=True)                               # AUTO / MANUAL_QUARANTINE / MANUAL_RERUN

    quarantine_status = Column(String(24), nullable=False, default="NOT_REQUIRED")  # NOT_REQUIRED/QUARANTINED/RELEASED
    quarantine_reason = Column(Text, nullable=True)
    quarantined_at = Column(DateTime(timezone=True), nullable=True)

    sandbox_status = Column(String(24), nullable=False, default="NOT_REQUIRED")
    # NOT_REQUIRED / QUEUED / RUNNING / COMPLETED / NO_ARTIFACTS / UNAVAILABLE / FAILED / DISABLED
    sandbox_verdict = Column(String(16), nullable=True)                       # SAFE / SUSPICIOUS / MALICIOUS
    sandbox_score = Column(Float, nullable=True)
    sandbox_result = Column(JSON, nullable=True)
    sandbox_submission = Column(JSON, nullable=True)                          # manifest of what was sent (names/hashes only)
    sandbox_attempts = Column(Integer, nullable=False, default=0)
    sandbox_error = Column(Text, nullable=True)
    sandbox_started_at = Column(DateTime(timezone=True), nullable=True)
    sandbox_completed_at = Column(DateTime(timezone=True), nullable=True)

    ai_security = Column(JSON, nullable=True)
    grc = Column(JSON, nullable=True)
    vapt = Column(JSON, nullable=True)
    threat_report = Column(JSON, nullable=True)

    final_verdict = Column(String(16), nullable=True)
    final_score = Column(Float, nullable=True)
    ledger_block_index = Column(Integer, nullable=True)
    ledger_block_hash = Column(String(64), nullable=True)
    report_hash = Column(String(64), nullable=True)
    error = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SocConfig(Base):
    """Per-analyst SOC alarm configuration."""
    __tablename__ = "soc_configs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), nullable=False, unique=True, index=True)
    alarm_enabled = Column(Boolean, nullable=False, default=True)
    min_severity = Column(String(16), nullable=False, default="HIGH")          # MEDIUM / HIGH / CRITICAL
    sound_enabled = Column(Boolean, nullable=False, default=True)
    browser_notifications = Column(Boolean, nullable=False, default=True)
    repeat_until_ack = Column(Boolean, nullable=False, default=True)
    repeat_interval_seconds = Column(Integer, nullable=False, default=30)
    sandbox_scope = Column(String(16), nullable=False, default="SUSPICIOUS")   # SUSPICIOUS / ALL / OFF
    alarm_on_sandbox_malicious = Column(Boolean, nullable=False, default=True)
    alarm_on_grc_violation = Column(Boolean, nullable=False, default=True)
    auto_escalate_critical = Column(Boolean, nullable=False, default=True)
    escalation_contact = Column(String(256), nullable=True)
    webhook_url = Column(String(512), nullable=True)                           # Slack/Teams/SIEM (https only)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SocAlarm(Base):
    __tablename__ = "soc_alarms"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    case_id = Column(String(32), nullable=True)
    severity = Column(String(16), nullable=False)
    source = Column(String(24), nullable=False)          # DETECTION / SANDBOX / GRC / TEST
    title = Column(String(256), nullable=False)
    message = Column(Text, nullable=True)
    status = Column(String(16), nullable=False, default="ACTIVE")   # ACTIVE / ACKNOWLEDGED / RESOLVED
    escalated = Column(Boolean, nullable=False, default=False)
    webhook_status = Column(String(64), nullable=True)
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
