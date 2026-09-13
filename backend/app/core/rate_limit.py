from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory sliding-window rate limiter, keyed by client IP.

    This is intentionally lightweight (no Redis dependency) since it is
    sufficient for a single-process hackathon prototype. For multi-instance
    production deployments this should be swapped for a shared store.
    """

    def __init__(self, app, requests_per_minute: int | None = None):
        super().__init__(app)
        self.limit = requests_per_minute or 600
        self.window_seconds = 60
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    # Paths that are exempt from rate limiting (read-only polling endpoints
    # and developer tooling that the UI calls on every render cycle).
    _EXEMPT_PREFIXES = (
        "/api/v1/health",
        "/api/v1/dashboard",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/assets",
    )

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Exempt read-only polling paths and dev tooling entirely
        if any(path.startswith(prefix) for prefix in self._EXEMPT_PREFIXES):
            return await call_next(request)
        # Also exempt all safe GET requests against investigation/case sub-resources
        if request.method == "GET" and path.startswith("/api/v1/investigations"):
            return await call_next(request)
        if request.method == "GET" and path.startswith("/api/v1/cases"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        hits = self._hits[client_ip]

        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()

        if len(hits) >= self.limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please try again shortly."},
            )

        hits.append(now)
        return await call_next(request)
