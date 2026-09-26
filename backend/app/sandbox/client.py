"""Client for the isolated MailShield sandbox service.

Security boundary
-----------------
The main server NEVER opens, renders or executes a suspicious attachment.
It only (1) extracts the raw attachment bytes, URLs and HTML body out of the
quarantined MIME message and (2) ships them to the sandbox container over an
HMAC-signed request. Only these artefacts cross the boundary — no Gmail
tokens, no database URL, no user e-mail addresses, no headers, no host paths.
"""
from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("mailshield.sandbox")

URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>()]{3,2048}")
MAX_ATTACHMENTS = 12
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024


class SandboxUnavailable(RuntimeError):
    pass


def sandbox_url() -> str:
    return os.getenv("SANDBOX_URL", "").rstrip("/")


def sandbox_secret() -> str:
    return os.getenv("SANDBOX_SHARED_SECRET", "")


def sandbox_enabled() -> bool:
    return os.getenv("SANDBOX_ENABLED", "true").lower() in ("1", "true", "yes") and bool(sandbox_url())


def extract_artifacts(raw_bytes: bytes, known_urls: Optional[List[str]] = None) -> Tuple[dict, dict]:
    """Returns (payload_for_sandbox, manifest_for_audit). The manifest holds
    names/sizes/hashes only and is what gets stored and anchored."""
    attachments: List[dict] = []
    manifest_files: List[dict] = []
    html_bodies: List[str] = []
    urls: List[str] = list(dict.fromkeys(u for u in (known_urls or []) if u))
    try:
        msg = email.message_from_bytes(raw_bytes or b"", policy=email.policy.compat32)
    except Exception:  # noqa: BLE001
        msg = None
    if msg is not None:
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = (part.get_content_type() or "").lower()
            fname = part.get_filename()
            disp = (part.get("Content-Disposition") or "").lower()
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001
                payload = b""
            is_attachment = bool(fname) or "attachment" in disp or (
                not ctype.startswith(("text/plain", "text/html", "multipart/", "message/")) and len(payload) > 0)
            if is_attachment and len(attachments) < MAX_ATTACHMENTS:
                name = str(fname or f"unnamed_part_{len(attachments) + 1}")[:255]
                sha = hashlib.sha256(payload).hexdigest()
                entry = {"filename": name, "content_type": ctype, "size_bytes": len(payload), "sha256": sha}
                if len(payload) > MAX_ATTACHMENT_BYTES:
                    entry["skipped"] = "too large for sandbox submission"
                else:
                    attachments.append({"filename": name, "content_type": ctype,
                                        "data_b64": base64.b64encode(payload).decode("ascii")})
                manifest_files.append(entry)
                continue
            if ctype in ("text/html", "text/plain"):
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, "replace")
                except LookupError:
                    text = payload.decode("utf-8", "replace")
                if ctype == "text/html" and len(html_bodies) < 3:
                    html_bodies.append(text[:3_000_000])
                for u in URL_RE.findall(text):
                    u = u.rstrip(".,;)]}'\"")
                    if u not in urls:
                        urls.append(u)
    urls = urls[:60]
    payload = {"request_id": uuid.uuid4().hex, "attachments": attachments, "urls": urls, "html_bodies": html_bodies}
    manifest = {
        "request_id": payload["request_id"],
        "files": manifest_files,
        "url_count": len(urls),
        "html_body_count": len(html_bodies),
        "artifact_bundle_sha256": hashlib.sha256(json.dumps(
            {"f": [m["sha256"] for m in manifest_files], "u": urls,
             "h": [hashlib.sha256(h.encode("utf-8", "ignore")).hexdigest() for h in html_bodies]},
            sort_keys=True).encode()).hexdigest(),
        "data_sent": "attachment bytes, URLs and HTML body only — no headers, addresses, credentials or tokens",
    }
    return payload, manifest


def _sign(body: bytes) -> Dict[str, str]:
    ts, nonce = str(int(time.time())), uuid.uuid4().hex
    sig = hmac.new(sandbox_secret().encode(), f"{ts}.{nonce}.".encode() + hashlib.sha256(body).hexdigest().encode(),
                   hashlib.sha256).hexdigest()
    return {"X-Sandbox-Timestamp": ts, "X-Sandbox-Nonce": nonce, "X-Sandbox-Signature": sig,
            "Content-Type": "application/json"}


def health(timeout: float = 8.0) -> dict:
    import httpx
    if not sandbox_url():
        return {"reachable": False, "configured": False, "detail": "SANDBOX_URL is not set"}
    try:
        r = httpx.get(f"{sandbox_url()}/health", timeout=timeout)
        return {"reachable": r.status_code == 200, "configured": True, **(r.json() if r.status_code == 200 else {})}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "configured": True, "detail": type(exc).__name__}


def submit(payload: dict) -> dict:
    """POST the artefacts to the sandbox. Retries with back-off so a Render
    free-tier instance that is cold-starting (≈30-60 s) is still reached."""
    import httpx
    if not sandbox_url():
        raise SandboxUnavailable("SANDBOX_URL is not configured")
    if not sandbox_secret():
        raise SandboxUnavailable("SANDBOX_SHARED_SECRET is not configured")
    body = json.dumps(payload).encode()
    timeout = float(os.getenv("SANDBOX_TIMEOUT_SECONDS", "90"))
    attempts = int(os.getenv("SANDBOX_MAX_RETRIES", "4"))
    last = "unknown error"
    for i in range(attempts):
        try:
            r = httpx.post(f"{sandbox_url()}/v1/analyze", content=body, headers=_sign(body), timeout=timeout)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403, 413, 400):
                raise SandboxUnavailable(f"sandbox rejected request: HTTP {r.status_code} {r.text[:200]}")
            last = f"HTTP {r.status_code}"
        except SandboxUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001  (connect error / timeout while cold-starting)
            last = type(exc).__name__
        logger.info("sandbox attempt %d/%d failed (%s); retrying", i + 1, attempts, last)
        time.sleep(min(20, 5 * (i + 1)))
    raise SandboxUnavailable(f"sandbox unreachable after {attempts} attempts ({last})")
