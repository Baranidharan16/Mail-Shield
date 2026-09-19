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
from fastapi import HTTPException, status
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

    def __init__(self, access_token: str, user_email: str = "", user_id: str = ""):
        self._access_token = access_token
        self.user_email = user_email
        self.user_id = user_id
        self._headers = {"Authorization": f"Bearer {access_token}"}
        self._quarantine_label_id: Optional[str] = None

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

    async def get_or_create_label(self, label_name: str = "Quarantine") -> str:
        """
        Dynamically discovers the Gmail user label ID by name (case-insensitive)
        using users.labels.list.
        If the label does not exist, creates it dynamically using users.labels.create.
        Never hardcodes label IDs.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{GMAIL_API_BASE}/labels",
                headers=self._headers,
            )
            if resp.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Gmail access token expired or revoked. Please re-authenticate your Gmail connection.",
                )
            if resp.status_code == 403:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient Gmail permissions. Scope https://www.googleapis.com/auth/gmail.modify is required.",
                )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Failed to query Gmail labels from API: {resp.text}",
                )

            labels = resp.json().get("labels", [])
            for l in labels:
                if l.get("name", "").strip().lower() == label_name.strip().lower():
                    logger.info("Found existing dynamic Gmail label '%s' (ID: %s)", label_name, l["id"])
                    self._quarantine_label_id = l["id"]
                    return l["id"]

            # Label does not exist -> create it dynamically via Gmail API
            logger.info("Gmail label '%s' does not exist. Creating dynamically via Gmail API...", label_name)
            create_payload = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
            create_resp = await client.post(
                f"{GMAIL_API_BASE}/labels",
                headers={**self._headers, "Content-Type": "application/json"},
                json=create_payload,
            )
            if create_resp.status_code == 409:
                # Conflict / duplicate race condition: re-fetch labels
                re_resp = await client.get(f"{GMAIL_API_BASE}/labels", headers=self._headers)
                for l in re_resp.json().get("labels", []):
                    if l.get("name", "").strip().lower() == label_name.strip().lower():
                        self._quarantine_label_id = l["id"]
                        return l["id"]

            if create_resp.status_code not in (200, 201):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Failed to create Gmail label '{label_name}': {create_resp.text}",
                )

            created_label = create_resp.json()
            label_id = created_label["id"]
            logger.info("Successfully created Gmail label '%s' with dynamic ID: %s", label_name, label_id)
            self._quarantine_label_id = label_id
            return label_id

    async def list_messages(
        self, query: str = "", max_results: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Lists emails from user's inbox with sender, subject, snippet.
        Returns real Gmail API data only — no sandbox/fake messages.
        """
        # Listing is read-only: the Quarantine label is only created when the
        # user actually quarantines a message (never just by viewing the inbox).
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
            is_quarantined = bool(
                (self._quarantine_label_id and self._quarantine_label_id in labels)
                or ("SPAM" in labels)
                or ("MAILSHIELD_QUARANTINE" in labels)
            )
            return {
                "id": d["id"],
                "threadId": d["threadId"],
                "sender": h.get("from", "Unknown"),
                "subject": h.get("subject", "(No Subject)"),
                "date": h.get("date", ""),
                "snippet": d.get("snippet", ""),
                "is_quarantined": is_quarantined,
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

    async def quarantine_message(
        self,
        message_id: str,
        destination: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Quarantines a Gmail message:
        1. Resolves target label:
           - For baranidharanboopathy66@gmail.com (or destination='quarantine'):
             Finds or creates the user label 'Quarantine' dynamically, adds Quarantine label ID, removes INBOX.
           - For destination='spam':
             Adds 'SPAM' label ID, removes INBOX.
        2. Validates message existence in user's Gmail.
        3. Executes users.messages.modify with addLabelIds and removeLabelIds.
        4. Verifies modification response from Gmail API before confirming success.
        """
        target_dest = (destination or "").strip().lower()
        if not target_dest:
            if not self.user_email:
                try:
                    prof = await self.fetch_profile()
                    self.user_email = prof.get("emailAddress", "")
                except Exception:
                    pass
            if "baranidharanboopathy66" in (self.user_email or "").lower():
                target_dest = "quarantine"
            else:
                target_dest = "spam"

        target_label_id: str
        target_label_name: str

        if target_dest == "spam":
            target_label_name = "SPAM"
            target_label_id = "SPAM"
        else:
            target_label_name = "Quarantine"
            target_label_id = await self.get_or_create_label("Quarantine")

        async with httpx.AsyncClient(timeout=15.0) as client:
            # 1. Verify message exists and inspect current labels
            check_resp = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self._headers,
                params={"format": "minimal"},
            )
            if check_resp.status_code == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Gmail message '{message_id}' not found in connected Gmail account.",
                )
            if check_resp.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Gmail access token expired. Please re-authorize via /auth/google.",
                )
            if check_resp.status_code == 403:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient Gmail permissions to inspect message. Ensure https://www.googleapis.com/auth/gmail.modify scope is granted.",
                )
            if check_resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Gmail API error checking message: {check_resp.text}",
                )

            current_labels = check_resp.json().get("labelIds", [])

            # Check if already quarantined
            if target_label_id in current_labels and "INBOX" not in current_labels:
                logger.info("Message %s is already quarantined under label %s", message_id, target_label_id)
                return {
                    "status": "QUARANTINED",
                    "message_id": message_id,
                    "label_id": target_label_id,
                    "label_name": target_label_name,
                    "destination": target_dest,
                    "already_quarantined": True,
                    "inbox_removed": True,
                    "labels": current_labels,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": f"Message is already isolated under {target_label_name}.",
                }

            # 2. Modify message: add target label, remove INBOX
            modify_payload = {
                "addLabelIds": [target_label_id],
                "removeLabelIds": ["INBOX"],
            }
            modify_resp = await client.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**self._headers, "Content-Type": "application/json"},
                json=modify_payload,
            )

            if modify_resp.status_code == 403:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient Gmail scope. Scope https://www.googleapis.com/auth/gmail.modify is required to modify message labels.",
                )
            if modify_resp.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Gmail access token expired or revoked. Please re-authorize your connection.",
                )
            if modify_resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Gmail API modification failed: {modify_resp.text}",
                )

            result_data = modify_resp.json()
            updated_labels = result_data.get("labelIds", [])

            # Verify that modification actually took effect
            if target_label_id not in updated_labels:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Gmail API modification response missing target label '{target_label_name}'.",
                )

            logger.info(
                "Quarantine successful for msg %s: applied label %s (%s), removed INBOX. Result labels: %s",
                message_id, target_label_name, target_label_id, updated_labels,
            )

            return {
                "status": "QUARANTINED",
                "message_id": message_id,
                "label_id": target_label_id,
                "label_name": target_label_name,
                "destination": target_dest,
                "inbox_removed": "INBOX" not in updated_labels,
                "labels": updated_labels,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": f"Email successfully moved to {target_label_name} and removed from INBOX.",
            }

    async def release_message(self, message_id: str) -> Dict[str, Any]:
        """Releases quarantined email back to the standard INBOX."""
        quarantine_label_id = await self.get_or_create_label("Quarantine")

        # Get current message labels so we only request removal of labels that actually exist
        async with httpx.AsyncClient(timeout=15.0) as client:
            meta_resp = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self._headers,
                params={"format": "minimal"},
            )
            current_labels = meta_resp.json().get("labelIds", []) if meta_resp.status_code == 200 else []

            remove_labels = [lbl for lbl in [quarantine_label_id, "SPAM"] if lbl in current_labels]

            payload = {
                "addLabelIds": ["INBOX"],
                "removeLabelIds": remove_labels,
            }
            resp = await client.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**self._headers, "Content-Type": "application/json"},
                json=payload,
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Gmail API release failed: {resp.text}",
                )

            return {
                "status": "RELEASED",
                "message_id": message_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "Message restored to INBOX; removed from Quarantine.",
            }


def load_user_gmail_session(user_id: str, db: Session) -> Optional[UserGmailSession]:
    """
    Loads the Gmail session for a specific user from the database.
    Returns None if the user has no linked Gmail account or tokens are missing.
    Automatically refreshes expired access tokens using the refresh token if available.
    """
    from app.models.gmail_account import GmailAccount
    from utils.token_crypto import decrypt_token, encrypt_token

    account = db.query(GmailAccount).filter(
        GmailAccount.user_id == user_id,
        GmailAccount.is_active == True,  # noqa: E712
    ).first()

    if not account:
        return None

    access_token = decrypt_token(account.encrypted_access_token or "")
    refresh_token = decrypt_token(account.encrypted_refresh_token or "")

    # Check token expiry; if expired or expiring within 60 seconds, refresh automatically
    now_epoch = int(time.time())
    expiry_epoch = int(account.token_expiry_epoch or account.token_expiry or 0)

    if (expiry_epoch - now_epoch < 60) and refresh_token:
        client_id = _get_client_id()
        client_secret = _get_client_secret()
        if client_id and client_secret:
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(
                        GOOGLE_TOKEN_ENDPOINT,
                        data={
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                        },
                    )
                    if resp.status_code == 200:
                        new_data = resp.json()
                        access_token = new_data.get("access_token", access_token)
                        expires_in = new_data.get("expires_in", 3600)
                        account.encrypted_access_token = encrypt_token(access_token)
                        account.token_expiry_epoch = str(now_epoch + int(expires_in))
                        account.token_expiry = account.token_expiry_epoch
                        db.commit()
                        logger.info("Successfully refreshed expired Gmail access token for user %s", user_id)
                    else:
                        logger.warning("Gmail token refresh attempt returned %s: %s", resp.status_code, resp.text)
            except Exception as ex:
                logger.error("Error refreshing Gmail token for user %s: %s", user_id, ex)

    if not access_token:
        logger.warning("Gmail account for user %s has no decryptable access token", user_id)
        return None

    return UserGmailSession(
        access_token=access_token,
        user_email=account.google_email or account.google_account_email or "",
        user_id=user_id,
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
