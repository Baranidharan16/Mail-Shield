"""
Server-Sent Events (SSE) for real-time investigation status (Phase 3 Part 29).
Streams actual processing_stage from the database — no fake progress.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.investigation import Investigation

logger = logging.getLogger("forensic_platform")
router = APIRouter(prefix="/investigations", tags=["sse"])

TERMINAL_STATUSES = {"COMPLETED", "FAILED"}
POLL_INTERVAL_SECONDS = 1.5


@router.get("/{investigation_id}/status-stream")
async def status_stream(investigation_id: str, db: Session = Depends(get_db)):
    """
    SSE endpoint. Streams investigation status updates until COMPLETED or FAILED.
    Frontend connects with EventSource('…/status-stream').
    Each event payload is JSON: {status, processing_stage, risk_score, classification}.
    """

    async def generate() -> AsyncGenerator[str, None]:
        last_stage = None
        attempts = 0
        max_attempts = 200  # ~5 minutes cap

        while attempts < max_attempts:
            db.expire_all()
            inv = db.get(Investigation, investigation_id)
            if inv is None:
                payload = json.dumps({"error": "investigation_not_found"})
                yield f"data: {payload}\n\n"
                return

            current_stage = inv.processing_stage or inv.status
            if current_stage != last_stage:
                payload = json.dumps({
                    "status": inv.status,
                    "processing_stage": inv.processing_stage,
                    "risk_score": inv.risk_score,
                    "classification": inv.classification,
                    "confidence": inv.confidence,
                    "error_message": inv.error_message,
                })
                yield f"data: {payload}\n\n"
                last_stage = current_stage

            if inv.status in TERMINAL_STATUSES:
                yield "data: {\"terminal\": true}\n\n"
                return

            attempts += 1
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

        yield "data: {\"timeout\": true}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
