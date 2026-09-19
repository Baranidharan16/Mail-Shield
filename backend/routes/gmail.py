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
from datetime import datetime, timezone
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
from datetime import timedelta
from urllib.parse import quote

from app.core.config import get_settings

_settings = get_settings()


def _safe_return_path(origin: Optional[str]) -> str:
    """Only same-site relative paths are allowed as post-OAuth destinations (no open redirect)."""
    if origin and origin.startswith("/") and not origin.startswith("//") and "\\" not in origin:
        return origin[:200]
    return "/dashboard"


def _frontend_url(path: str) -> str:
    return (_settings.FRONTEND_URL or "").rstrip("/") + path

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
    redirect: Optional[bool] = Query(False, description="Redirect directly to Google in browser if true"),
    origin: Optional[str] = Query(None, description="Originating frontend URL to redirect back to"),
    current_user: User = Depends(get_required_current_user),
):
    """
    Initiates Gmail OAuth 2.0 flow for the currently authenticated user.
    Encodes the user's JWT identity in the 'state' parameter to associate
    the callback with the correct MailShield account.
    REQUIRES: valid JWT session (user must be logged into MailShield first).
    """
    # Signed, short-lived, purpose-bound state (CSRF protection for the OAuth flow)
    now = datetime.now(timezone.utc)
    state_payload = {
        "user_id": current_user.id,
        "purpose": "gmail_oauth",
        "origin": _safe_return_path(origin),
        "iat": now,
        "exp": now + timedelta(minutes=10),
    }
    state_token = _jwt.encode(state_payload, _settings.JWT_SECRET_KEY, algorithm="HS256")

    try:
        auth_url = build_authorization_url(state=state_token)
    except ValueError as e:
        logger.error("Failed to build Google authorization URL: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )

    # If requested by browser directly or query param redirect=true, return 302 redirect
    if redirect:
        return RedirectResponse(url=auth_url)

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
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    client_id_loaded = bool(os.getenv("GOOGLE_CLIENT_ID"))
    client_secret_loaded = bool(os.getenv("GOOGLE_CLIENT_SECRET"))

    # Log safe diagnostic info without exposing secret values
    logger.info("=== GOOGLE OAUTH DIAGNOSTICS ===")
    logger.info("OAuth provider: Google")
    logger.info("Redirect URI: %s", redirect_uri)
    logger.info("Backend: http://localhost:8000")
    logger.info("Callback route: /auth/google/callback")
    logger.info("Environment loaded: YES")
    logger.info("Client ID loaded: %s", "YES" if client_id_loaded else "NO")
    logger.info("Client secret loaded: %s", "YES" if client_secret_loaded else "NO")
    logger.info("Code present: %s | State present: %s | Error: %s", bool(code), bool(state), error or "None")

    fallback_url = _frontend_url("/dashboard")

    if error:
        logger.error("Google OAuth returned error from Google consent: %s", error)
        return RedirectResponse(url=f"{fallback_url}?oauth_error={quote(error)[:64]}")

    if not code:
        logger.error("OAuth callback missing code parameter")
        return RedirectResponse(url=f"{fallback_url}?oauth_error=no_code")

    if not state:
        logger.warning("OAuth callback received without state — cannot associate tokens with user")
        return RedirectResponse(url=f"{fallback_url}?oauth_error=missing_state")

    # Decode state to get user_id and originating url
    return_url = fallback_url
    try:
        payload = _jwt.decode(state, _settings.JWT_SECRET_KEY, algorithms=["HS256"], options={"require": ["exp"]})
        user_id = payload.get("user_id")
        if payload.get("purpose") != "gmail_oauth" or not user_id:
            raise ValueError("Wrong-purpose or incomplete state token")
        if not db.get(User, user_id):
            raise ValueError("Unknown user in state token")
        return_url = _frontend_url(_safe_return_path(payload.get("origin")))
    except Exception as e:
        logger.error("OAuth state token invalid: %s", e)
        return RedirectResponse(url=f"{fallback_url}?oauth_error=invalid_state")

    # Exchange authorization code for tokens
    try:
        tokens = await exchange_code_for_tokens(code)
    except Exception as e:
        logger.error("Token exchange failed with error category: %s", type(e).__name__)
        return RedirectResponse(url=f"{return_url}?oauth_error=token_exchange_failed")

    # Persist encrypted tokens for this user
    try:
        await save_user_gmail_tokens(user_id=user_id, tokens=tokens, db=db)
        logger.info("Gmail OAuth tokens securely stored for user_id=%s", user_id)
    except Exception as e:
        logger.error("Failed to store Gmail tokens: %s", e)
        return RedirectResponse(url=f"{return_url}?oauth_error=storage_failed")

    sep = "&" if "?" in return_url else "?"
    return RedirectResponse(url=f"{return_url}{sep}gmail_connected=true")


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
    destination: Optional[str] = Query(None, description="Target quarantine destination: 'quarantine' or 'spam'"),
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """
    Quarantines a Gmail message for the authenticated user:
    1. Verifies the user has a valid, active Gmail OAuth session.
    2. Enforces ownership: if an investigation exists for this email, confirms current_user owns it.
    3. Finds or creates the dynamic 'Quarantine' label (or 'SPAM' if requested) via Gmail API.
    4. Applies target label and removes INBOX label.
    5. Confirms with Gmail API and updates investigation case_status to 'CONTAINED'.
    """
    session = _require_gmail_session(current_user, db)

    # Enforce security: verify ownership of corresponding investigation if present
    from app.models.investigation import Investigation
    inv = db.query(Investigation).filter(
        (Investigation.original_filename == f"gmail_{message_id}.eml") |
        (Investigation.id == message_id)
    ).first()

    if inv and inv.user_id and inv.user_id != current_user.id:
        logger.warning(
            "Security violation: User %s attempted to quarantine message %s owned by user %s",
            current_user.id, message_id, inv.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this email investigation.",
        )

    res = await session.quarantine_message(message_id, destination=destination)

    # If associated investigation exists, update case_status to CONTAINED
    if inv:
        inv.case_status = "CONTAINED"
        inv.severity = "HIGH"
        notes = list(inv.notes or [])
        notes.append({
            "author": current_user.email,
            "text": f"Gmail message quarantined to {res.get('label_name', 'Quarantine')} (Label ID: {res.get('label_id')}); removed from INBOX.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        inv.notes = notes
        db.commit()
        db.refresh(inv)
        res["investigation_id"] = inv.id
        res["case_id"] = inv.case_id

    return res


@router.post("/api/v1/investigations/{investigation_id}/quarantine")
@router.post("/api/investigations/{investigation_id}/quarantine")
async def quarantine_investigation_email(
    investigation_id: str,
    destination: Optional[str] = Query(None, description="Target quarantine destination: 'quarantine' or 'spam'"),
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """
    Quarantines the Gmail email corresponding to an analyzed investigation:
    1. Identifies the exact Gmail message ID associated with that investigation.
    2. Verifies that the currently authenticated user owns the investigation.
    3. Uses that user's Gmail OAuth credentials.
    4. Finds the Gmail user label named exactly 'Quarantine' (or creates it if missing).
    5. Applies the label and removes the INBOX label via users.messages.modify.
    6. Updates investigation status in MailShield to 'CONTAINED'.
    7. Returns success confirmation to frontend.
    """
    from app.models.investigation import Investigation
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        inv = db.query(Investigation).filter(Investigation.case_id == investigation_id).first()

    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    if inv.user_id != current_user.id:
        logger.warning(
            "Security violation: User %s attempted to quarantine investigation %s owned by %s",
            current_user.id, inv.id, inv.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this email investigation.",
        )

    # Extract Gmail message ID from original_filename (e.g. gmail_1a09de2da7154c7a.eml) or notes
    message_id = None
    orig_name = inv.original_filename or ""
    if orig_name.startswith("gmail_"):
        raw_id = orig_name[6:]
        if raw_id.endswith(".eml"):
            raw_id = raw_id[:-4]
        message_id = raw_id
    elif inv.notes:
        for n in inv.notes:
            if isinstance(n, dict) and n.get("gmail_message_id"):
                message_id = n["gmail_message_id"]
                break

    if not message_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "This investigation does not originate from an acquired Gmail message. "
                "Only Gmail-acquired emails can be quarantined via the Gmail API."
            ),
        )

    session = _require_gmail_session(current_user, db)
    res = await session.quarantine_message(message_id, destination=destination)

    # Update investigation record in MailShield
    inv.case_status = "CONTAINED"
    inv.severity = "HIGH"
    notes = list(inv.notes or [])
    notes.append({
        "author": current_user.email,
        "text": f"Email quarantined to {res.get('label_name', 'Quarantine')} (Label ID: {res.get('label_id')}); removed from INBOX.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    inv.notes = notes
    db.commit()
    db.refresh(inv)

    res["investigation_id"] = inv.id
    res["case_id"] = inv.case_id
    return res


@router.post("/api/v1/gmail/release/{message_id}")
@router.post("/api/gmail/release/{message_id}")
async def release_gmail_message(
    message_id: str,
    current_user: User = Depends(get_required_current_user),
    db: Session = Depends(get_db),
):
    """Releases a quarantined Gmail message back to inbox (current user only)."""
    session = _require_gmail_session(current_user, db)
    res = await session.release_message(message_id)

    # Restore investigation status if exists
    from app.models.investigation import Investigation
    inv = db.query(Investigation).filter(
        (Investigation.original_filename == f"gmail_{message_id}.eml") |
        (Investigation.id == message_id)
    ).first()
    if inv and inv.user_id == current_user.id:
        inv.case_status = "OPEN"
        db.commit()
        res["investigation_id"] = inv.id
        res["case_id"] = inv.case_id

    return res


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
