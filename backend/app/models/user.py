"""
User ORM model for MailShield.
Stores persistent user accounts with Argon2 password hashing.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.orm import relationship

from app.database.session import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # 1-to-many relationship with investigations
    investigations = relationship(
        "Investigation",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # 1-to-1 relationship with linked Gmail account (per-user OAuth isolation)
    gmail_account = relationship(
        "GmailAccount",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        """Returns safe user representation (never exposes password_hash)."""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
