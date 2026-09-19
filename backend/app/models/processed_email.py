"""
Real-time e-mail monitoring records.

* ProcessedEmail – one row per provider message that has been ingested for a
  user. The (user_id, provider_message_id) unique constraint guarantees a
  message is never analysed twice, and links the message to the investigation
  that holds its full forensic results.
* MonitorState   – per-user real-time monitoring switch and last-run status.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ProcessedEmail(Base):
    __tablename__ = "processed_emails"
    __table_args__ = (
        UniqueConstraint("user_id", "provider_message_id", name="uq_processed_user_message"),
        Index("ix_processed_user_time", "user_id", "processed_at"),
    )

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(16), nullable=False, default="gmail")
    provider_message_id = Column(String(128), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(16), nullable=False, default="ANALYZED")   # ANALYZED / FAILED / SKIPPED
    detail = Column(Text, nullable=True)
    received_at = Column(DateTime(timezone=True), nullable=True)
    processed_at = Column(DateTime(timezone=True), nullable=False, default=_now)


class MonitorState(Base):
    __tablename__ = "email_monitor_state"

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    messages_processed = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=False, default=_now)
