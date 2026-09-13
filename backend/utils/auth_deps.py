"""
MailShield FastAPI Authentication Dependencies.
Extracts and validates JWT Bearer tokens from requests and injects the current authenticated User.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from services.auth_service import decode_access_token

logger = logging.getLogger("mailshield.auth.deps")

# Use HTTPBearer with auto_error=False to allow flexible dependency handling
http_bearer = HTTPBearer(auto_error=False)


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Extracts user from Authorization: Bearer <token> or query/header if present.
    Returns None if no token or token is invalid (does not raise 401).
    """
    token: Optional[str] = None

    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        # Fallback check for header "authorization" or "x-access-token" or query param "token"
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif request.headers.get("x-access-token"):
            token = request.headers.get("x-access-token")
        elif request.query_params.get("token"):
            token = request.query_params.get("token")
        elif request.cookies.get("access_token"):
            token = request.cookies.get("access_token")

    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        return None

    user = db.get(User, user_id)
    if not user or not user.is_active:
        return None

    return user


async def get_current_user(
    user: Optional[User] = Depends(get_optional_current_user),
) -> User:
    """
    Requires an authenticated active user.
    Raises HTTP 401 Unauthorized if token is missing, expired, or invalid.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# Alias for semantic clarity in Gmail and other strict-auth routes
get_required_current_user = get_current_user
