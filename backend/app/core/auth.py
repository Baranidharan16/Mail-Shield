"""
Minimal API-key authentication for Phase 1.

Per the project brief: "Keep simple in Phase 1 but design the architecture
so role-based authentication can be added later." This module implements
the simplest thing that actually authenticates callers (a shared-secret
header, checked in constant time) while keeping a clean seam for Phase 2:

  - `get_current_caller` is a FastAPI dependency other routes can require.
  - The resolved caller identity flows straight into
    `Investigation.created_by`, which already exists in the schema.
  - Swapping this for real user accounts / JWT / OAuth later only means
    replacing the body of `get_current_caller` - no call sites change.

Authentication is OFF by default (AUTH_ENABLED=false) so the platform
remains a zero-friction hackathon demo out of the box; operators turn it
on via environment variables when they need it.
"""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

settings = get_settings()


def _constant_time_lookup(api_key: str, keys: dict[str, str]) -> Optional[str]:
    """Looks up api_key against configured keys using constant-time
    comparison per key, to avoid leaking timing information about which
    prefix of a guessed key was correct."""
    for candidate, identity in keys.items():
        if hmac.compare_digest(candidate, api_key):
            return identity
    return None


async def get_current_caller(x_api_key: Optional[str] = Header(default=None)) -> Optional[str]:
    """FastAPI dependency: returns the caller identity, or None if auth is
    disabled. Raises 401 if auth is enabled and the key is missing/invalid.
    """
    if not settings.AUTH_ENABLED:
        return None

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    identity = _constant_time_lookup(x_api_key, settings.API_KEYS)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return identity
