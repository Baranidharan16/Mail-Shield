"""
GmailAccount ORM model — per-user Gmail OAuth token storage.
Each MailShield user can link exactly one Gmail account.
OAuth tokens are Fernet-encrypted at rest.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


def _gen_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id = Column(String(36), primary_key=True, default=_gen_uuid)

    # Owning MailShield user — strict 1-to-1 per user
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,      # each user has AT MOST one linked Gmail account
        index=True,
    )

    # The google-account email that was authorised
    google_account_email = Column(String(255), nullable=True)
    google_email = Column(String(255), nullable=True)

    # Provider name (always 'google')
    provider = Column(String(50), default="google", nullable=False)

    # Fernet-encrypted OAuth tokens (base64 ciphertext stored as text)
    # NEVER store plaintext access_token or refresh_token.
    encrypted_access_token = Column(Text, nullable=True)
    encrypted_refresh_token = Column(Text, nullable=True)

    # Token expiry timestamp / epoch seconds
    token_expiry = Column(String(64), nullable=True)
    token_expiry_epoch = Column(String(32), nullable=True)

    # Comma-separated list of granted scopes
    granted_scopes = Column(Text, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    connected_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # Relationship back to User
    user = relationship("User", back_populates="gmail_account")

    def __repr__(self) -> str:
        return f"<GmailAccount user_id={self.user_id} email={self.google_email}>"
