"""
MailShield Authentication Service.
Handles Argon2 password hashing, verification, and JWT access token creation/validation.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.core.config import get_settings

logger = logging.getLogger("mailshield.services.auth")
settings = get_settings()

# Initialize Argon2 PasswordHasher.
# memory_cost=16384 (16 MiB) is still well above the OWASP minimum of 12 MiB
# and dramatically faster than 64 MiB on a laptop CPU — which was causing
# 40-50 second response times and triggering Axios/client timeouts that showed
# as "Registration failed" / "Login failed" on the frontend even though the
# operation was actually succeeding server-side.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=16384,  # 16 MiB — OWASP-compliant, ~4x faster than 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using Argon2. Never stores or logs plaintext."""
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(plain_password)


async def hash_password_async(plain_password: str) -> str:
    """Async wrapper: runs Argon2 hashing in a thread pool so it never blocks
    the FastAPI event loop. Use this in all async route handlers."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, hash_password, plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2 password hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as exc:
        logger.error("Error during password verification: %s", exc)
        return False


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    """Async wrapper: runs Argon2 verification in a thread pool so it never
    blocks the FastAPI event loop. Use this in all async route handlers."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, verify_password, plain_password, hashed_password)


def create_access_token(
    user_id: str,
    email: str,
    name: str,
    session_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generates a short-lived JWT access token bound to a server-side session."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    payload: Dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "name": name,
        "typ": "access",
        "jti": secrets.token_hex(8),
        "iat": now,
        "exp": expire,
    }
    if session_id:
        payload["sid"] = session_id

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


class TokenError(Exception):
    """Raised when a token is expired or invalid (reason in .code)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code  # "token_expired" | "token_invalid"


def decode_access_token_strict(token: str) -> Dict[str, Any]:
    """Decodes an access token, raising TokenError with a reason code on failure."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],  # pinned: rejects alg=none / alg confusion
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired")
    except jwt.InvalidTokenError:
        raise TokenError("token_invalid")
    if payload.get("typ", "access") != "access":
        raise TokenError("token_invalid")
    return payload


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT access token. Returns None if invalid or expired."""
    try:
        return decode_access_token_strict(token)
    except TokenError:
        return None


# ── Opaque refresh / reset tokens ────────────────────────────────────────────

def new_opaque_token() -> str:
    """Cryptographically random URL-safe token (sent to the client once)."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Only the SHA-256 of opaque tokens is persisted, never the token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── Password policy ─────────────────────────────────────────────────────────

_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "iloveyou", "admin123", "welcome1", "letmein123",
    "11111111", "abc12345", "passw0rd", "mailshield", "football", "baseball",
}


def password_problems(password: str, email: str = "", name: str = "") -> list[str]:
    """Returns a list of human-readable reasons why a password is too weak."""
    problems: list[str] = []
    if len(password) < 8:
        problems.append("at least 8 characters")
    if len(password) > 128:
        problems.append("at most 128 characters")
    if not any(c.isalpha() for c in password):
        problems.append("at least one letter")
    if not any(c.isdigit() for c in password):
        problems.append("at least one number")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        problems.append("not be a commonly used password")
    local = (email or "").split("@")[0].lower()
    if local and len(local) >= 4 and local in lowered:
        problems.append("not contain your email address")
    return problems


# Pre-computed hash used to equalise login timing for unknown e-mails
# (prevents discovering which e-mails are registered by measuring latency).
_DUMMY_HASH = _hasher.hash("mailshield-timing-equaliser")


async def verify_password_constant_time(plain_password: str, hashed_password: Optional[str]) -> bool:
    if not hashed_password:
        await verify_password_async(plain_password, _DUMMY_HASH)
        return False
    return await verify_password_async(plain_password, hashed_password)
