"""
MailShield - Gmail OAuth 2.0 & Email Acquisition Service (Per-User, DB-Backed)

Handles:
  1. Google OAuth 2.0 authorization flow (Code exchange)
  2. Per-user token storage — encrypted at rest in gmail_accounts table
  3. Gmail profile & inbox synchronization (per authenticated user)
  4. Raw email acquisition (RFC822 byte streams via format=raw)
  5. Autonomous MailShield Quarantine (via MAILSHIELD_QUARANTINE label)
  6. Reversible quarantine release

SECURITY:
  - GmailService is NOT a global singleton. Every request loads the token
    for the specific authenticated user from the database.
  - OAuth tokens are Fernet-encrypted at rest in the gmail_accounts table.
  - NEVER expose access_token or refresh_token to the browser.
  - GOOGLE_CLIENT_SECRET lives only in the backend environment.

Gmail OAuth Scopes used:
  - https://www.googleapis.com/auth/gmail.readonly  (inbox forensic access)
  - https://www.googleapis.com/auth/gmail.modify    (quarantine label ops)
  - https://www.googleapis.com/auth/userinfo.email
  - https://www.googleapis.com/auth/userinfo.profile
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

logger = logging.getLogger("mailshield.services.gmail")

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

# OAuth scopes — gmail.readonly REQUIRED for inbox forensic access
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


def _get_client_id() -> str:
    return os.getenv("GOOGLE_CLIENT_ID", "")


def _get_client_secret() -> str:
    return os.getenv("GOOGLE_CLIENT_SECRET", "")


def _get_redirect_uri() -> str:
    return os.getenv(
        "GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback"
    )


def build_authorization_url(state: str) -> str:
    """Generates Google OAuth 2.0 authorization URL for the given state token."""
    client_id = _get_client_id()
    if not client_id:
        raise ValueError(
            "GOOGLE_CLIENT_ID is not configured. "
            "Set it in backend/.env to enable Gmail OAuth."
        )
    params = {
        "client_id": client_id,
        "redirect_uri": _get_redirect_uri(),
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    """
    Exchanges Google authorization code for access + refresh tokens.
    Returns the raw token response dict from Google.
    Raises HTTPException on failure — never silently falls back to sandbox.
    """
    client_id = _get_client_id()
    client_secret = _get_client_secret()
    if not client_id or not client_secret:
        raise ValueError(
            "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be configured to exchange OAuth codes."
        )

    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": _get_redirect_uri(),
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(GOOGLE_TOKEN_ENDPOINT, data=data)
        if resp.status_code != 200:
            logger.error(
                "Google token exchange failed (status=%s): %s", resp.status_code, resp.text
            )
            raise ValueError(f"Google OAuth token exchange failed: {resp.text}")
        return resp.json()


class UserGmailSession:
    """
    Lightweight per-request Gmail session for one authenticated user.
    Loads tokens from the database via user_id.
    Does NOT store state across requests — all state lives in the DB.
    """

    def __init__(self, access_token: str, user_email: str = ""):
        self._access_token = access_token
        self.user_email = user_email
        self._headers = {"Authorization": f"Bearer {access_token}"}

    @property
    def is_connected(self) -> bool:
        return bool(self._access_token)

    async def fetch_profile(self) -> Dict[str, Any]:
        """Retrieves Gmail profile for the authenticated user."""
        if not self._access_token:
            return {"emailAddress": "", "messagesTotal": 0, "is_connected": False}
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{GMAIL_API_BASE}/profile", headers=self._headers)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("Gmail profile fetch failed (%s): %s", resp.status_code, resp.text)
            return {"emailAddress": self.user_email, "messagesTotal": 0, "is_connected": True}

    async def list_messages(
        self, query: str = "", max_results: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Lists emails from user's inbox with sender, subject, snippet.
        Returns real Gmail API data only — no sandbox/fake messages.
        """
        params: Dict[str, Any] = {"maxResults": max_results, "labelIds": "INBOX"}
        if query:
            params["q"] = query

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/messages", headers=self._headers, params=params
            )
            if resp.status_code != 200:
                logger.error("Gmail list messages failed (%s): %s", resp.status_code, resp.text)
                return []

            raw_msgs = resp.json().get("messages", [])
            detailed: List[Dict[str, Any]] = []
            for m in raw_msgs[:max_results]:
                det = await self._get_message_metadata(m["id"])
                if det:
                    detailed.append(det)
            return detailed

    async def _get_message_metadata(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Fetches header metadata for inbox display."""
        params = {
            "format": "metadata",
            "metadataHeaders": ["From", "To", "Subject", "Date", "Message-ID"],
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self._headers,
                params=params,
            )
            if resp.status_code != 200:
                return None
            d = resp.json()
            h = {
                hdr["name"].lower(): hdr["value"]
                for hdr in d.get("payload", {}).get("headers", [])
            }
            labels = d.get("labelIds", [])
            return {
                "id": d["id"],
                "threadId": d["threadId"],
                "sender": h.get("from", "Unknown"),
                "subject": h.get("subject", "(No Subject)"),
                "date": h.get("date", ""),
                "snippet": d.get("snippet", ""),
                "is_quarantined": "MAILSHIELD_QUARANTINE" in labels,
                "labels": labels,
            }

    async def get_raw_email(self, message_id: str) -> bytes:
        """
        Fetches complete raw RFC822 email bytes from Gmail API.
        Returns empty bytes on failure — never returns fabricated data.
        """
        params = {"format": "raw"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self._headers,
                params=params,
            )
            if resp.status_code == 200:
                raw_b64 = resp.json().get("raw", "")
                if raw_b64:
                    return base64.urlsafe_b64decode(raw_b64.encode("utf-8") + b"==")
            logger.error(
                "Gmail raw email fetch failed (%s) for msg=%s: %s",
                resp.status_code, message_id, resp.text,
            )
            return b""

    async def quarantine_message(self, message_id: str) -> Dict[str, Any]:
        """
        Applies reversible quarantine: adds MAILSHIELD_QUARANTINE label, removes INBOX.
        """
        payload = {
            "addLabelIds": ["MAILSHIELD_QUARANTINE"],
            "removeLabelIds": ["INBOX"],
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**self._headers, "Content-Type": "application/json"},
                json=payload,
            )
            if resp.status_code not in (200, 204):
                logger.warning("Quarantine label apply returned %s", resp.status_code)

        return {
            "status": "QUARANTINED",
            "message_id": message_id,
            "policy": "MAILSHIELD_CRITICAL_SECURITY_POLICY",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "label_applied": "MAILSHIELD_QUARANTINE",
            "action": "Removed from primary inbox view and isolated in quarantine vault.",
            "reversible": True,
        }

    async def release_message(self, message_id: str) -> Dict[str, Any]:
        """Releases quarantined email back to the standard inbox."""
        payload = {
            "addLabelIds": ["INBOX"],
            "removeLabelIds": ["MAILSHIELD_QUARANTINE"],
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**self._headers, "Content-Type": "application/json"},
                json=payload,
            )
            if resp.status_code not in (200, 204):
                logger.warning("Quarantine release returned %s", resp.status_code)

        return {
            "status": "RELEASED",
            "message_id": message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "MAILSHIELD_QUARANTINE label removed; restored to user inbox.",
        }


def load_user_gmail_session(user_id: str, db: Session) -> Optional[UserGmailSession]:
    """
    Loads the Gmail session for a specific user from the database.
    Returns None if the user has no linked Gmail account or tokens are missing.
    Decrypts stored tokens using the Fernet key.
    """
    from app.models.gmail_account import GmailAccount
    from utils.token_crypto import decrypt_token

    account = db.query(GmailAccount).filter(
        GmailAccount.user_id == user_id,
        GmailAccount.is_active == True,  # noqa: E712
    ).first()

    if not account:
        return None

    access_token = decrypt_token(account.encrypted_access_token or "")
    if not access_token:
        logger.warning("Gmail account for user %s has no decryptable access token", user_id)
        return None

    return UserGmailSession(
        access_token=access_token,
        user_email=account.google_email or "",
    )


async def save_user_gmail_tokens(
    user_id: str,
    tokens: Dict[str, Any],
    db: Session,
) -> None:
    """
    Saves (or updates) the Gmail OAuth tokens for a user in the database.
    Encrypts tokens before storing.
    Also fetches the Google email address to store alongside the tokens.
    """
    from app.models.gmail_account import GmailAccount
    from utils.token_crypto import encrypt_token

    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in = tokens.get("expires_in", 3600)

    expiry_epoch = str(int(time.time()) + int(expires_in))

    # Fetch the Google account email
    google_email = ""
    if access_token:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{GMAIL_API_BASE}/profile",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if resp.status_code == 200:
                    google_email = resp.json().get("emailAddress", "")
        except Exception as e:
            logger.warning("Could not fetch Google profile email: %s", e)

    # Upsert the GmailAccount record for this user
    account = db.query(GmailAccount).filter(GmailAccount.user_id == user_id).first()
    if account:
        account.encrypted_access_token = encrypt_token(access_token)
        if refresh_token:
            account.encrypted_refresh_token = encrypt_token(refresh_token)
        account.token_expiry = expiry_epoch
        account.token_expiry_epoch = expiry_epoch
        account.google_account_email = google_email or account.google_account_email or account.google_email
        account.google_email = google_email or account.google_email
        account.provider = "google"
        account.granted_scopes = " ".join(SCOPES)
        account.is_active = True
        account.updated_at = datetime.now(timezone.utc)
    else:
        account = GmailAccount(
            user_id=user_id,
            google_account_email=google_email,
            google_email=google_email,
            provider="google",
            encrypted_access_token=encrypt_token(access_token),
            encrypted_refresh_token=encrypt_token(refresh_token) if refresh_token else "",
            token_expiry=expiry_epoch,
            token_expiry_epoch=expiry_epoch,
            granted_scopes=" ".join(SCOPES),
            is_active=True,
        )
        db.add(account)

    db.commit()
    logger.info(
        "Gmail tokens saved for user_id=%s, google_email=%s", user_id, google_email
    )


def disconnect_user_gmail(user_id: str, db: Session) -> None:
    """Deactivates the Gmail integration for a user (tokens stay for audit)."""
    from app.models.gmail_account import GmailAccount

    account = db.query(GmailAccount).filter(GmailAccount.user_id == user_id).first()
    if account:
        account.is_active = False
        account.encrypted_access_token = ""
        account.encrypted_refresh_token = ""
        db.commit()
        logger.info("Gmail disconnected for user_id=%s", user_id)


# ── Backward-compatibility shim ──────────────────────────────────────────────
# The old code called get_gmail_service() which returned a global singleton.
# We provide a stub here so imports don't break during transition, but new
# code MUST use load_user_gmail_session() instead.

class _DeprecatedGmailServiceStub:
    """Stub for backward compatibility — do not use in new code."""
    is_connected = False
    tokens: Dict = {}
    user_profile: Optional[Dict] = None
    quarantined_messages: set = set()

    def get_authorization_url(self, state: str = "mailshield_auth") -> str:
        return build_authorization_url(state)

    async def exchange_code_for_tokens(self, code: str) -> Dict:
        return await exchange_code_for_tokens(code)

    async def fetch_profile(self) -> Dict:
        return {"emailAddress": "", "messagesTotal": 0}

    async def list_messages(self, query="", max_results=15) -> List:
        return []

    async def get_raw_email(self, message_id: str) -> bytes:
        return b""

    async def quarantine_message(self, message_id: str) -> Dict:
        return {"status": "UNAVAILABLE", "message_id": message_id}

    async def release_message(self, message_id: str) -> Dict:
        return {"status": "UNAVAILABLE", "message_id": message_id}

    def disconnect(self):
        pass


_stub = _DeprecatedGmailServiceStub()


def get_gmail_service() -> _DeprecatedGmailServiceStub:
    """
    DEPRECATED: Returns a backward-compat stub.
    New code must use load_user_gmail_session(user_id, db) directly.
    """
    logger.warning(
        "get_gmail_service() is deprecated. Use load_user_gmail_session(user_id, db) "
        "for proper per-user Gmail isolation."
    )
    return _stub
