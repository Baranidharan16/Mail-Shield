"""Deletion / retention helpers (privacy: right to erasure + configurable retention)."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import Base

logger = logging.getLogger("mailshield.lifecycle")


def delete_investigations(db: Session, ids: List[str]) -> int:
    """Removes investigations and EVERY dependent row + stored evidence file.
    Ledger blocks are kept: they contain only hashes/case ids (no personal data)
    and removing them would break the tamper-evident chain."""
    from app.models.investigation import Investigation
    if not ids:
        return 0
    files = [r[0] for r in db.execute(select(Investigation.filename).where(Investigation.id.in_(ids))).all()]
    for table in reversed(Base.metadata.sorted_tables):
        if table.name != "investigations" and "investigation_id" in table.c:
            col = table.c.investigation_id
            if table.name == "processed_emails":
                db.execute(table.update().where(col.in_(ids)).values(investigation_id=None))
            else:
                db.execute(delete(table).where(col.in_(ids)))
    n = db.execute(delete(Investigation).where(Investigation.id.in_(ids))).rowcount or 0
    db.commit()
    base = os.path.abspath(get_settings().UPLOAD_STORAGE_DIR)
    for f in files:
        try:
            p = os.path.join(base, f or "")
            if f and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    return n


def purge_expired(db: Session) -> int:
    from app.models.investigation import Investigation
    days = get_settings().DATA_RETENTION_DAYS
    if not days or days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    ids = [r[0] for r in db.execute(select(Investigation.id).where(Investigation.created_at < cutoff)).all()]
    n = delete_investigations(db, ids)
    if n:
        logger.info("Retention: purged %d investigations older than %d days", n, days)
    return n
