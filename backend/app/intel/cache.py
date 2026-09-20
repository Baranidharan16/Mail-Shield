"""
TTL cache for threat-intelligence lookups (Part 6).

Backed by the `threat_intel_cache` table so it survives process restarts
and is inspectable/auditable. Every provider call in `providers.py` goes
through `get_or_fetch()` - no indicator is looked up twice within its TTL
window, which is what keeps this safe to use against rate-limited
external APIs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.intel.interfaces import IntelResult
from app.models.investigation import ThreatIntelCache

DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours
_MAX_INDICATOR_LEN = 512  # threat_intel_cache.indicator is VARCHAR(512)


def _cache_key(indicator: str) -> str:
    """Tracking/redirect URLs can be thousands of characters long. Such
    indicators are keyed by their SHA-256 so they fit the column and still
    match exactly on the next lookup."""
    indicator = indicator or ""
    if len(indicator) <= _MAX_INDICATOR_LEN:
        return indicator
    import hashlib
    return "sha256:" + hashlib.sha256(indicator.encode("utf-8", "replace")).hexdigest()


def get_cached(db: Session, provider: str, indicator_type: str, indicator: str) -> Optional[IntelResult]:
    indicator = _cache_key(indicator)
    row = (
        db.query(ThreatIntelCache)
        .filter(
            ThreatIntelCache.provider == provider,
            ThreatIntelCache.indicator_type == indicator_type,
            ThreatIntelCache.indicator == indicator,
        )
        .order_by(ThreatIntelCache.fetched_at.desc())
        .first()
    )
    if not row:
        return None
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return None  # expired - caller will re-fetch
    return IntelResult(**row.result_json)


def store_cached(db: Session, provider: str, indicator_type: str, indicator: str, result: IntelResult, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
    row = ThreatIntelCache(
        provider=provider,
        indicator_type=indicator_type,
        indicator=_cache_key(indicator),
        result_json=result.__dict__,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
    )
    db.add(row)
    db.commit()


def get_or_fetch(
    db: Session,
    provider: str,
    indicator_type: str,
    indicator: str,
    fetch_fn: Callable[[], IntelResult],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> IntelResult:
    """Returns a cached result if fresh, otherwise calls fetch_fn() and
    caches the outcome (even error/unavailable results, with a short TTL,
    so a flapping provider doesn't get hammered)."""
    cached = get_cached(db, provider, indicator_type, indicator)
    if cached is not None:
        return cached

    result = fetch_fn()
    effective_ttl = ttl_seconds if result.available else min(ttl_seconds, 5 * 60)
    store_cached(db, provider, indicator_type, indicator, result, ttl_seconds=effective_ttl)
    return result
