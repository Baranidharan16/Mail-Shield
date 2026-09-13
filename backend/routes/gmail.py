"""
MailShield - Gmail OAuth 2.0 & Email Acquisition Routes
Per-user authentication enforced on ALL Gmail endpoints.

Routes:
  GET  /auth/google                   — Initiates OAuth flow (requires auth)
  GET  /auth/google/callback          — Google OAuth callback handler
  GET  /api/v1/gmail/status           — Connection status for the current user
  GET  /api/v1/gmail/profile          — Gmail profile for the current user
  GET  /api/v1/gmail/messages         — Inbox list for the current user
  GET  /api/v1/gmail/search           — Inbox search for the current user
  GET  /api/v1/gmail/message/{id}     — Raw email metadata
  POST /api/v1/gmail/analyze/{id}     — Full forensic analysis of a Gmail message
  POST /api/v1/gmail/quarantine/{id}  — Quarantine a message (current user only)
  POST /api/v1/gmail/release/{id}     — Release quarantined message (current user only)
  POST /api/v1/gmail/disconnect       — Remove Gmail OAuth tokens for current user

SECURITY: Every endpoint that touches Gmail data REQUIRES a valid JWT session.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional

import jwt as _jwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from services.gmail_service import (
    build_authorization_url,
    exchange_code_for_tokens,
    load_user_gmail_session,
    save_user_gmail_tokens,
    disconnect_user_gmail,
)
from services.email_parser import parse_eml_bytes
# NOTE: routes.analysis is imported lazily inside analyze_gmail_message()
# to avoid loading Keras/TensorFlow at module import time.
from app.services.investigation_service import create_investigation, run_analysis
from utils.auth_deps import get_optional_current_user, get_required_current_user

import os

logger = logging.getLogger("mailshield.routes.gmail")
router = APIRouter(tags=["Gmail Integration"])


def _require_gmail_session(current_user: User, db: Session):
    """
    Loads the Gmail session for the authenticated user.
    Raises 401 if not connected.
    """
    session = load_user_gmail_session(current_user.id, db)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gmail not connected. Please link your Gmail account via /auth/google.",
        )
    return session


# ── OAuth Flow ────────────────────────────────────────────────────────────────

@router.get("/auth/google")
@router.get("/api/v1/auth/google")
async def google_auth_login(
    current_user: User = Depends(get_required_current_user),
):
    """
    Initiates Gmail OAuth 2.0 flow for the currently authenticated user.
    Encodes the user's JWT identity in the 'state' parameter to associate
    the callback with the correct MailShield account.
    REQUIRES: valid JWT session (user must be logged into MailShield first).
    """
    secret = os.getenv("JWT_SECRET_KEY", "mailshield-insecure-dev-secret-key-change-in-production-2026")
    # Encode user_id in state so we can retrieve it on callback (signed JWT)
    state_payload = {"user_id": current_user.id, "sub": current_user.email}
    state_token = _jwt.encode(state_payload, secret, algorithm="HS256")

    try:
        auth_url = build_authorization_url(state=state_token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    return {"authorization_url": auth_url}


@router.get("/auth/google/callback")
@router.get("/api/v1/auth/google/callback")
async def google_auth_callback(
    code: Optional[str] = None,
    error: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Handles Google OAuth authorization code callback.
    Decodes the 'state' JWT to retrieve the MailShield user_id,
    then saves the encrypted tokens to that user's gmail_accounts row.
    """
    if error:
        logger.error("Google OAuth error: %s", error)
        return RedirectResponse(url="/upload?oauth_error=" + error)

    if not code:
        return RedirectResponse(url="/upload?oauth_error=no_code")

    if not state:
        logger.warning("OAuth callback received without state — cannot associate tokens with user")
        return RedirectResponse(url="/upload?oauth_error=missing_state")

    # Decode state to get user_id
    secret = os.getenv("JWT_SECRET_KEY", "mailshield-insecure-dev-secret-key-change-in-production-2026")
    try:
        payload = _jwt.decode(state, secret, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise ValueError("Missing user_id in state token")
    except Exception as e:
        logger.error("OAuth state token invalid: %s", e)
        return RedirectResponse(url="/upload?oauth_error=invalid_state")

    # Exchange authorization code for tokens
    try:
        tokens = await exchange_code_for_tokens(code)
    except ValueError as e:
        logger.error("Token exchange failed: %s", e)
        return RedirectResponse(url="/upload?oauth_error=token_exchange_failed")

    # Persist encrypted tokens for this user
    await save_user_gmail_tokens(user_id=user_id, tokens=tokens, db=db)
    logger.info("Gmail OAuth tokens saved for user_id=%s", user_id)

    return RedirectResponse(url="/upload?gmail_connected=true")


# ── Authenticated Gmail Endpoints ─────────────────────────────────────────────

@router.get("/api/v1/gmail/status")
@router.get("/api/gmail/status")
async def get_gmail_status(
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Returns Gmail connection status for the authenticated user."""
    from app.models.gmail_account import GmailAccount
    account = db.query(GmailAccount).filter(
        GmailAccount.user_id == current_user.id,
        GmailAccount.is_active == True,  # noqa: E712
    ).first()

    if not account:
        return {
            "connected": False,
            "email": "",
            "messages_total": 0,
            "user_id": current_user.id,
        }

    # Try to fetch live profile
    session = load_user_gmail_session(current_user.id, db)
    messages_total = 0
    if session:
        try:
            profile = await session.fetch_profile()
            messages_total = profile.get("messagesTotal", 0)
        except Exception:
            pass

    return {
        "connected": True,
        "email": account.google_email or "",
        "messages_total": messages_total,
        "user_id": current_user.id,
        "connected_at": account.connected_at.isoformat() if account.connected_at else None,
    }


@router.get("/api/v1/gmail/profile")
@router.get("/api/gmail/profile")
async def get_gmail_profile(
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Returns Gmail profile for the authenticated user."""
    session = _require_gmail_session(current_user, db)
    return await session.fetch_profile()


@router.get("/api/v1/gmail/messages")
@router.get("/api/gmail/messages")
async def get_gmail_messages(
    q: str = "",
    limit: int = 15,
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves inbox messages for the authenticated user only."""
    session = _require_gmail_session(current_user, db)
    msgs = await session.list_messages(query=q, max_results=min(limit, 50))
    return {"messages": msgs, "count": len(msgs), "user_email": session.user_email}


@router.get("/api/v1/gmail/search")
@router.get("/api/gmail/search")
async def search_gmail_messages(
    q: str = Query(..., description="Gmail search query"),
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Searches inbox for the authenticated user."""
    session = _require_gmail_session(current_user, db)
    msgs = await session.list_messages(query=q)
    return {"messages": msgs, "query": q, "count": len(msgs)}


@router.get("/api/v1/gmail/message/{message_id}")
@router.get("/api/gmail/message/{message_id}")
async def get_gmail_message_detail(
    message_id: str,
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Fetches metadata and forensic preview for a single Gmail message."""
    session = _require_gmail_session(current_user, db)
    raw_bytes = await session.get_raw_email(message_id)
    if not raw_bytes:
        raise HTTPException(status_code=404, detail="Email not found or could not be retrieved from Gmail.")
    parsed = parse_eml_bytes(raw_bytes)
    return {
        "id": message_id,
        "subject": parsed.subject,
        "sender": parsed.from_header,
        "date": parsed.date,
        "message_id": parsed.message_id,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "size_bytes": len(raw_bytes),
        "snippet": (parsed.body_text or "")[:300],
        "user_id": current_user.id,
    }


@router.post("/api/v1/gmail/analyze/{message_id}")
@router.post("/api/gmail/analyze/{message_id}")
async def analyze_gmail_message(
    message_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_required_current_user),
):
    """
    Acquires RFC822 raw email from Gmail, runs full forensic analysis pipeline,
    creates investigation record (owned by current user), anchors evidence hash.
    Autonomous quarantine applied if risk score >= 61 (HIGH/CRITICAL).
    """
    session = _require_gmail_session(current_user, db)
    raw_bytes = await session.get_raw_email(message_id)
    if not raw_bytes:
        raise HTTPException(status_code=404, detail="Email could not be acquired from Gmail API.")

    parsed = parse_eml_bytes(raw_bytes)

    # Lazy import to avoid Keras/TF loading at startup
    from routes.analysis import _process_analysis
    analysis_res = await _process_analysis(parsed, current_user=current_user, db=db)

    investigation = create_investigation(
        db=db,
        raw_bytes=raw_bytes,
        original_filename=f"gmail_{message_id}.eml",
        mime_type="message/rfc822",
        created_by=current_user.email,
        user_id=current_user.id,          # strict user ownership
    )
    run_analysis(db, investigation.id, raw_bytes)

    quarantined = False
    if analysis_res.risk.score >= 61:
        await session.quarantine_message(message_id)
        quarantined = True

    return {
        "analysis": analysis_res,
        "investigation_id": investigation.id,
        "case_id": investigation.case_id,
        "quarantined": quarantined,
        "evidence_hash": hashlib.sha256(raw_bytes).hexdigest(),
        "source": "GMAIL_OAUTH_ACQUISITION",
        "user_id": current_user.id,
    }


@router.post("/api/v1/gmail/quarantine/{message_id}")
@router.post("/api/gmail/quarantine/{message_id}")
async def quarantine_gmail_message(
    message_id: str,
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Quarantines a Gmail message for the authenticated user."""
    session = _require_gmail_session(current_user, db)
    return await session.quarantine_message(message_id)


@router.post("/api/v1/gmail/release/{message_id}")
@router.post("/api/gmail/release/{message_id}")
async def release_gmail_message(
    message_id: str,
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Releases a quarantined Gmail message back to inbox (current user only)."""
    session = _require_gmail_session(current_user, db)
    return await session.release_message(message_id)


@router.post("/api/v1/gmail/disconnect")
@router.post("/api/gmail/disconnect")
async def disconnect_gmail_account(
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Removes Gmail OAuth tokens for the current user."""
    disconnect_user_gmail(current_user.id, db)
    return {"status": "DISCONNECTED", "user_id": current_user.id}


# ── Backward-compat stub (deprecated, returns 401) ───────────────────────────

@router.post("/api/v1/gmail/connect-sandbox")
@router.post("/api/gmail/connect-sandbox")
async def connect_sandbox_deprecated(
    current_user: User = Depends(get_required_current_user),
):
    """DEPRECATED: Sandbox mode removed. Connect via /auth/google OAuth flow."""
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail=(
            "Sandbox mode has been removed for security. "
            "Please use the real Gmail OAuth flow at /auth/google."
        ),
    )
