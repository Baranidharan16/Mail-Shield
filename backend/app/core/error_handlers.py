from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("forensic_platform")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log full details server-side (without dumping request bodies / email content)
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        # Never return raw exception details to the client
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred. Please try again or contact support."},
        )
