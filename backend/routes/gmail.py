"""
MailShield - Gmail API & OAuth Endpoints
Provides complete Gmail integration:
  - GET /api/v1/auth/google
  - GET /api/v1/auth/google/callback
  - GET /api/v1/gmail/status
  - GET /api/v1/gmail/profile
  - GET /api/v1/gmail/messages
  - GET /api/v1/gmail/search
  - GET /api/v1/gmail/message/{id}
  - POST /api/v1/gmail/analyze/{id}
  - POST /api/v1/gmail/quarantine/{id}
  - POST /api/v1/gmail/release/{id}
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from services.gmail_service import get_gmail_service
from services.email_parser import parse_eml_bytes
from routes.analysis import _process_analysis
from app.services.investigation_service import create_investigation, run_analysis
from utils.auth_deps import get_optional_current_user

logger = logging.getLogger("mailshield.routes.gmail")
router = APIRouter(tags=["Gmail Integration"])


@router.get("/auth/google")
@router.get("/api/v1/auth/google")
async def google_auth_login():
    """Generates and redirects to the Google OAuth 2.0 authorization URL."""
    gmail = get_gmail_service()
    auth_url = gmail.get_authorization_url()
    return {"authorization_url": auth_url}


@router.get("/auth/google/callback")
@router.get("/api/v1/auth/google/callback")
async def google_auth_callback(
    code: Optional[str] = None,
    error: Optional[str] = None,
    state: Optional[str] = None,
):
    """Handles Google OAuth authorization code callback."""
    if error:
        logger.error("OAuth error received from Google: %s", error)
        return RedirectResponse(url="/upload?oauth_error=" + error)

    gmail = get_gmail_service()
    if code:
        await gmail.exchange_code_for_tokens(code)

    return RedirectResponse(url="/upload?gmail_connected=true")


@router.get("/api/v1/gmail/status")
@router.get("/api/gmail/status")
async def get_gmail_status():
    """Returns current Gmail integration status."""
    gmail = get_gmail_service()
    profile = await gmail.fetch_profile()
    return {
        "connected": gmail.is_connected,
        "email": profile.get("emailAddress", ""),
        "messages_total": profile.get("messagesTotal", 0),
        "quarantined_count": len(gmail.quarantined_messages),
    }


@router.get("/api/v1/gmail/profile")
@router.get("/api/gmail/profile")
async def get_gmail_profile():
    """Returns user profile from Gmail API."""
    gmail = get_gmail_service()
    return await gmail.fetch_profile()


@router.get("/api/v1/gmail/messages")
@router.get("/api/gmail/messages")
async def get_gmail_messages(q: str = "", limit: int = 15):
    """Retrieves messages from Gmail inbox with threat preview indicators."""
    gmail = get_gmail_service()
    msgs = await gmail.list_messages(query=q, max_results=limit)
    return {"messages": msgs, "count": len(msgs)}


@router.get("/api/v1/gmail/search")
@router.get("/api/gmail/search")
async def search_gmail_messages(q: str = Query(..., description="Gmail search query")):
    """Searches messages in Gmail inbox."""
    gmail = get_gmail_service()
    msgs = await gmail.list_messages(query=q)
    return {"messages": msgs, "query": q}


@router.get("/api/v1/gmail/message/{message_id}")
@router.get("/api/gmail/message/{message_id}")
async def get_gmail_message_detail(message_id: str):
    """Fetches details and raw metadata of a single email."""
    gmail = get_gmail_service()
    raw_bytes = await gmail.get_raw_email(message_id)
    parsed = parse_eml_bytes(raw_bytes)
    return {
        "id": message_id,
        "subject": parsed.subject,
        "sender": parsed.from_header,
        "date": parsed.date,
        "message_id": parsed.message_id,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "size_bytes": len(raw_bytes),
        "snippet": parsed.body_text[:300],
    }


@router.post("/api/v1/gmail/analyze/{message_id}")
@router.post("/api/gmail/analyze/{message_id}")
async def analyze_gmail_message(
    message_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Acquires original raw RFC822 email from Gmail, preserves evidence with SHA-256,
    runs the complete dual-model Keras ML & NLP threat pipeline,
    registers cryptographic proof on Hyperledger Fabric, and creates an investigation case.
    """
    gmail = get_gmail_service()
    raw_bytes = await gmail.get_raw_email(message_id)
    if not raw_bytes:
        raise HTTPException(status_code=404, detail="Email could not be acquired from Gmail API.")

    parsed = parse_eml_bytes(raw_bytes)

    # 1. Run direct MailShield ML/NLP & Forensics pipeline
    analysis_res = await _process_analysis(parsed, current_user=current_user, db=db)

    # 2. Persist full investigation case with hops, graph, and blockchain anchor
    user_id = current_user.id if current_user else None
    investigation = create_investigation(
        db=db,
        raw_bytes=raw_bytes,
        original_filename=f"gmail_{message_id}.eml",
        mime_type="message/rfc822",
        created_by="GMAIL_ACQUISITION_AGENT",
        user_id=user_id,
    )
    # Execute full forensic and intelligence pipeline synchronously
    run_analysis(db, investigation.id, raw_bytes)

    # 3. Autonomous Quarantine if score is HIGH/CRITICAL
    quarantined = False
    if analysis_res.risk.score >= 61:
        await gmail.quarantine_message(message_id)
        quarantined = True

    return {
        "analysis": analysis_res,
        "investigation_id": investigation.id,
        "case_id": investigation.case_id,
        "quarantined": quarantined,
        "evidence_hash": hashlib.sha256(raw_bytes).hexdigest(),
        "source": "GMAIL_OAUTH_ACQUISITION",
    }


@router.post("/api/v1/gmail/quarantine/{message_id}")
@router.post("/api/gmail/quarantine/{message_id}")
async def quarantine_gmail_message(message_id: str):
    """Quarantines email by applying MAILSHIELD_QUARANTINE and isolating it."""
    gmail = get_gmail_service()
    return await gmail.quarantine_message(message_id)


@router.post("/api/v1/gmail/release/{message_id}")
@router.post("/api/gmail/release/{message_id}")
async def release_gmail_message(message_id: str):
    """Releases quarantined email and restores it to user's inbox."""
    gmail = get_gmail_service()
    return await gmail.release_message(message_id)


@router.post("/api/v1/gmail/connect-sandbox")
@router.post("/api/gmail/connect-sandbox")
async def connect_sandbox():
    """Enables live sandbox Gmail connection for instant demo & evaluation."""
    gmail = get_gmail_service()
    gmail.is_connected = True
    gmail.user_profile = {
        "emailAddress": "soc.analyst@mailshield.internal",
        "messagesTotal": 84,
        "threadsTotal": 52,
    }
    return {"status": "CONNECTED", "email": gmail.user_profile["emailAddress"]}


@router.post("/api/v1/gmail/disconnect")
@router.post("/api/gmail/disconnect")
async def disconnect_gmail():
    """Disconnects Gmail integration."""
    gmail = get_gmail_service()
    gmail.disconnect()
    return {"status": "DISCONNECTED"}
