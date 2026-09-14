"""
MailShield Authentication Service.
Handles Argon2 password hashing, verification, and JWT access token creation/validation.
"""
from __future__ import annotations

import asyncio
import logging
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
    loop = asyncio.get_event_loop()
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
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, verify_password, plain_password, hashed_password)


def create_access_token(
    user_id: str,
    email: str,
    name: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generates a secure JWT access token for authenticated API requests."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "name": name,
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT access token. Returns None if invalid or expired."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Token has expired.")
        return None
    except jwt.InvalidTokenError as exc:
        logger.debug("Invalid JWT token: %s", exc)
        return None
