"""
MailShield FastAPI Authentication & Authorization Dependencies.

* get_optional_current_user / get_current_user
    Validate the `Authorization: Bearer <access token>` header, check that the
    server-side session referenced by the token is still active, and load the
    user from the database. The user identity is ALWAYS taken from the verified
    token — never from a user id supplied by the client.

* require_resource_owner
    Router-level dependency that enforces ownership for any route containing an
    `{investigation_id}` or `{alert_id}` path parameter. Records owned by other
    users (or by nobody) respond with 404 so ids cannot be probed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.auth_session import UserSession
from app.models.user import User
from services.auth_service import TokenError, decode_access_token_strict

logger = logging.getLogger("mailshield.auth.deps")

http_bearer = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    # Tokens are accepted ONLY from headers. Query-string tokens leak into
    # logs, browser history and Referer headers, so they are not supported.
    if credentials and credentials.credentials:
        return credentials.credentials
    return request.headers.get("x-access-token") or None


def _as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _resolve_user(request: Request, token: str, db: Session) -> User:
    """Returns the active user for a token or raises TokenError."""
    payload = decode_access_token_strict(token)
    user_id = payload.get("sub")
    session_id = payload.get("sid")

    if session_id:
        sess = db.get(UserSession, session_id)
        now = datetime.now(timezone.utc)
        if (
            sess is None
            or sess.user_id != user_id
            or sess.revoked_at is not None
            or _as_aware(sess.expires_at) <= now
        ):
            raise TokenError("session_revoked")
    else:
        # Legacy tokens issued before server-side sessions existed are refused,
        # which forces one fresh login after this upgrade.
        raise TokenError("token_invalid")

    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise TokenError("token_invalid")

    request.state.session_id = session_id
    return user


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Returns the authenticated user, or None when no/invalid token is sent."""
    token = _extract_token(request, credentials)
    if not token:
        return None
    try:
        return _resolve_user(request, token, db)
    except TokenError:
        return None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Requires an authenticated, active user with a live session (else HTTP 401)."""
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer", "X-Auth-Error": "not_authenticated"},
        )
    try:
        return _resolve_user(request, token, db)
    except TokenError as exc:
        message = {
            "token_expired": "Your session has expired. Please sign in again.",
            "session_revoked": "This session has been signed out. Please sign in again.",
        }.get(exc.code, "Invalid authentication token. Please sign in again.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=message,
            headers={"WWW-Authenticate": "Bearer", "X-Auth-Error": exc.code},
        )


# Alias for semantic clarity in Gmail and other strict-auth routes
get_required_current_user = get_current_user


def _not_found(kind: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{kind} not found")


async def require_resource_owner(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """
    Router-level guard: every route with an {investigation_id} or {alert_id}
    path parameter is only reachable by the user who owns that record.
    Enforced in the backend for every current AND future sub-route.
    """
    from app.models.investigation import Alert, Investigation

    params = request.path_params
    inv_id = params.get("investigation_id")
    if inv_id is not None:
        owned = (
            db.query(Investigation.id)
            .filter(Investigation.id == inv_id, Investigation.user_id == current_user.id)
            .first()
        )
        if not owned:
            raise _not_found("Investigation")

    alert_id = params.get("alert_id")
    if alert_id is not None:
        owned = (
            db.query(Alert.id)
            .join(Investigation, Investigation.id == Alert.investigation_id)
            .filter(Alert.id == alert_id, Investigation.user_id == current_user.id)
            .first()
        )
        if not owned:
            raise _not_found("Alert")

    return current_user
