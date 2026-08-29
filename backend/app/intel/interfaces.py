"""
Threat-intelligence provider interfaces.

These are deliberately vendor-agnostic ABCs so no single vendor is
hard-coded (per the brief). Concrete implementations live in
`app/intel/providers.py`. All provider calls MUST go through
`app/intel/cache.py` for TTL caching and through the timeout/error
handling built into `BaseHttpIntelProvider` - callers never hit a raw
`requests`/`httpx` call directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class IntelResult:
    indicator: str
    indicator_type: str  # ip / domain / url
    provider: str
    available: bool
    data: Dict[str, Any] = field(default_factory=dict)
    risk_score: Optional[float] = None  # 0-100, provider's own risk estimate if any
    error: Optional[str] = None
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_synthetic_demo_data: bool = False


class IPIntelligenceProvider(ABC):
    name: str = "base"

    @abstractmethod
    def lookup_ip(self, ip_address: str) -> IntelResult: ...


class DomainIntelligenceProvider(ABC):
    name: str = "base"

    @abstractmethod
    def lookup_domain(self, domain: str) -> IntelResult: ...


class URLIntelligenceProvider(ABC):
    name: str = "base"

    @abstractmethod
    def lookup_url(self, url: str) -> IntelResult: ...
