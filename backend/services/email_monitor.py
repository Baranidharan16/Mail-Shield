"""
Real-time (near-real-time) Gmail threat monitor.

Every GMAIL_POLL_INTERVAL_SECONDS, for each user who has connected Gmail via
OAuth and has monitoring enabled:

    list new INBOX message ids (Gmail API, read-only call)
      -> skip ids already in processed_emails (no duplicate processing)
      -> fetch raw RFC 822 message
      -> canonical pipeline (forensic engine -> ML -> NLP -> rules -> intel ->
         fusion -> conditional forensic agent -> report -> ledger anchor)
      -> investigation + alert stored under THAT user's id
      -> processed_emails row (message id, user id, timestamp, status)

The UI's live feed/alerts poll the user's own investigations, so new results
appear without any button press. Nothing is pre-generated.

Notes
  * Polling (not Gmail push/Pub/Sub) is used because it needs no public
    Pub/Sub topic; interval and per-cycle caps keep API usage small.
  * On free hosting that sleeps when idle, monitoring pauses while asleep
    and catches up (look-back window) when the service wakes.
  * The monitor never modifies the mailbox unless GMAIL_AUTO_QUARANTINE=true.
  * OAuth tokens are decrypted only in memory for the API call.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from typing import List, Optional

import httpx
from starlette.concurrency import run_in_threadpool

from app.core.config import get_settings

logger = logging.getLogger("mailshield.monitor")
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

_task: Optional[asyncio.Task] = None
_last_cycle: dict = {"started_at": None, "finished_at": None, "users": 0, "processed": 0, "errors": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _list_new_ids(access_token: str, after: datetime, limit: int) -> List[str]:
    params = {"labelIds": "INBOX", "maxResults": min(50, max(limit * 3, 10)),
              "q": f"after:{int(after.timestamp())}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(f"{GMAIL_API_BASE}/messages", params=params,
                             headers={"Authorization": f"Bearer {access_token}"})
    if r.status_code != 200:
        raise RuntimeError(f"Gmail list failed ({r.status_code})")
    return [m["id"] for m in r.json().get("messages", [])]


async def process_user(user_id: str) -> int:
    """One monitoring pass for one user. Returns number of messages analysed."""
    from app.database.session import SessionLocal
    from app.models.gmail_account import GmailAccount
    from app.models.processed_email import MonitorState, ProcessedEmail
    from app.models.user import User
    from app.services.investigation_service import analyze_email_for_user
    from services.gmail_service import load_user_gmail_session

    settings = get_settings()
    db = SessionLocal()
    count = 0
    try:
        user = db.get(User, user_id)
        state = db.get(MonitorState, user_id)
        if state is None:
            state = MonitorState(user_id=user_id, enabled=True)
            db.add(state)
            db.commit()
        if not user or not user.is_active or not state.enabled:
            return 0
        state.last_run_at = _now()
        db.commit()

        session = await run_in_threadpool(load_user_gmail_session, user_id, db)
        if session is None:
            state.last_error = "Gmail not connected or token could not be refreshed — reconnect Gmail."
            db.commit()
            return 0

        after = _aware(state.last_success_at) or (_now() - timedelta(days=settings.GMAIL_LOOKBACK_DAYS))
        after = after - timedelta(minutes=10)  # overlap window; duplicates are filtered below
        ids = await _list_new_ids(session._access_token, after, settings.GMAIL_MAX_PER_CYCLE)
        done = {r[0] for r in db.query(ProcessedEmail.provider_message_id)
                .filter(ProcessedEmail.user_id == user_id, ProcessedEmail.provider_message_id.in_(ids or [""])).all()}
        own = (session.user_email or "").lower()

        for mid in [i for i in ids if i not in done][: settings.GMAIL_MAX_PER_CYCLE]:
            try:
                raw = await session.get_raw_email(mid)
                if not raw:
                    db.add(ProcessedEmail(user_id=user_id, provider_message_id=mid, status="FAILED",
                                          detail="Raw message could not be fetched"))
                    db.commit()
                    continue
                head = raw[:8192].decode("utf-8", errors="ignore")
                from_line = next((ln[5:] for ln in head.splitlines() if ln.lower().startswith("from:")), "")
                if own and parseaddr(from_line)[1].lower() == own:
                    # The account owner's own mail is never treated as an attack.
                    db.add(ProcessedEmail(user_id=user_id, provider_message_id=mid, status="SKIPPED",
                                          detail="Sent by the account owner"))
                    db.commit()
                    continue
                inv_id = await run_in_threadpool(analyze_email_for_user, raw, f"gmail_{mid}.eml",
                                                 user_id, user.email, "GMAIL_REALTIME")
                db.add(ProcessedEmail(user_id=user_id, provider_message_id=mid, investigation_id=inv_id,
                                      status="ANALYZED"))
                db.commit()
                count += 1
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                logger.warning("Monitor: message %s for user %s failed: %s", mid, user_id, type(exc).__name__)
                try:
                    db.add(ProcessedEmail(user_id=user_id, provider_message_id=mid, status="FAILED",
                                          detail=type(exc).__name__))
                    db.commit()
                except Exception:
                    db.rollback()

        state = db.get(MonitorState, user_id)
        state.last_success_at = _now()
        state.last_error = None
        state.messages_processed = (state.messages_processed or 0) + count
        db.commit()
        return count
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("Monitor pass failed for user %s: %s", user_id, exc)
        try:
            st = db.get(MonitorState, user_id)
            if st:
                st.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                db.commit()
        except Exception:
            db.rollback()
        return count
    finally:
        db.close()


async def run_cycle() -> dict:
    from app.database.session import SessionLocal
    from app.models.gmail_account import GmailAccount
    _last_cycle.update(started_at=_now().isoformat(), processed=0, errors=0)
    db = SessionLocal()
    try:
        user_ids = [r[0] for r in db.query(GmailAccount.user_id).filter(GmailAccount.is_active == True).all()]  # noqa: E712
    finally:
        db.close()
    total = 0
    for uid in user_ids:
        total += await process_user(uid)
    _last_cycle.update(finished_at=_now().isoformat(), users=len(user_ids), processed=total)
    return dict(_last_cycle)


async def _loop() -> None:
    settings = get_settings()
    await asyncio.sleep(15)  # let the app finish starting
    last_purge = 0.0
    import time as _time
    while True:
        try:
            await run_cycle()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Monitor cycle error: %s", exc)
        if _time.time() - last_purge > 3600:
            last_purge = _time.time()
            try:
                from app.database.session import SessionLocal
                from app.services.data_lifecycle import purge_expired
                db = SessionLocal()
                try:
                    await run_in_threadpool(purge_expired, db)
                finally:
                    db.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Retention purge error: %s", exc)
        await asyncio.sleep(max(20, settings.GMAIL_POLL_INTERVAL_SECONDS))


def start_monitor() -> None:
    global _task
    if get_settings().GMAIL_MONITOR_ENABLED and _task is None:
        _task = asyncio.get_event_loop().create_task(_loop())
        logger.info("Real-time Gmail monitor started (interval %ss).", get_settings().GMAIL_POLL_INTERVAL_SECONDS)


async def stop_monitor() -> None:
    global _task
    if _task:
        _task.cancel()
        _task = None


def last_cycle() -> dict:
    return dict(_last_cycle)
