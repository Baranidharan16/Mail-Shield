"""MailShield Isolated Sandbox Service.

A separate container that receives ONLY the suspicious artefacts of a
quarantined e-mail (attachments as bytes, URLs, HTML body) — never mailbox
credentials, database URLs, user identities or host paths — and returns a
static-analysis threat verdict.

Endpoints
  GET  /health          liveness (no auth, no data)
  POST /v1/analyze      HMAC-signed analysis request
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .engine import ENGINE_VERSION
from .isolation import run_isolated

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] sandbox: %(message)s")
log = logging.getLogger("sandbox")

SECRET = os.getenv("SANDBOX_SHARED_SECRET", "")
MAX_BODY = int(os.getenv("SANDBOX_MAX_REQUEST_BYTES", str(40 * 1024 * 1024)))
SKEW = 300
_seen_nonces: deque = deque(maxlen=5000)

app = FastAPI(title="MailShield Isolated Sandbox", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health():
    return {"status": "ok", "engine": ENGINE_VERSION, "auth_configured": bool(SECRET), "mode": "STATIC_CONTROLLED"}


def _verify(req_ts: str, nonce: str, sig: str, body: bytes) -> None:
    if not SECRET:
        raise HTTPException(503, "Sandbox shared secret is not configured.")
    try:
        ts = int(req_ts)
    except (TypeError, ValueError):
        raise HTTPException(401, "Missing/invalid timestamp.")
    if abs(time.time() - ts) > SKEW:
        raise HTTPException(401, "Request expired.")
    if not nonce or nonce in _seen_nonces:
        raise HTTPException(401, "Replay detected.")
    expected = hmac.new(SECRET.encode(), f"{ts}.{nonce}.".encode() + hashlib.sha256(body).hexdigest().encode(),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig or ""):
        raise HTTPException(401, "Bad signature.")
    _seen_nonces.append(nonce)


@app.post("/v1/analyze")
async def analyze(request: Request):
    cl = int(request.headers.get("content-length") or 0)
    if cl > MAX_BODY:
        raise HTTPException(413, "Request too large.")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Request too large.")
    _verify(request.headers.get("x-sandbox-timestamp"), request.headers.get("x-sandbox-nonce", ""),
            request.headers.get("x-sandbox-signature", ""), body)
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(400, "Invalid payload.")
    log.info("job %s: %d attachment(s), %d url(s)", str(payload.get("request_id"))[:40],
             len(payload.get("attachments") or []), len(payload.get("urls") or []))
    msg = run_isolated(payload)
    if not msg.get("ok"):
        log.warning("job failed: %s", msg.get("error"))
        # A parser crash / timeout on attacker-supplied input is itself a signal.
        return JSONResponse(status_code=200, content={
            "request_id": payload.get("request_id"), "engine_version": ENGINE_VERSION, "analysis_mode": "STATIC_CONTROLLED",
            "verdict": "SUSPICIOUS", "score": 50.0,
            "reasons": [f"[SBX-ISO-001] Analysis job {msg.get('error')} — content that crashes or stalls analysis "
                        "tooling is treated as suspicious."],
            "files": [], "urls": [], "skipped_files": [], "predicted_behavior": [], "mitre_techniques": [],
            "html_body": {"verdict": "SAFE", "score": 0, "findings": []}, "error": msg.get("error"),
        })
    return msg["result"]
