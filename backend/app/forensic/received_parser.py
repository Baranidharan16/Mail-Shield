"""
Received-header relay-chain reconstruction.

Received headers are appended top-down by each hop, so the LAST header in
the message is the EARLIEST hop chronologically. We reverse the list so
hop_index 0 = earliest observed hop.

IMPORTANT (per project rules): we never claim the earliest IP is
"the attacker's IP" - Received headers can be forged by anything after
the true origin, and legitimate infrastructure (load balancers, relays)
is common. We use "earliest observed sending infrastructure" language
and preserve uncertainty in a `confidence_note` field.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Optional

_IP_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,45})"
)
_FROM_RE = re.compile(r"from\s+([^\s;]+(?:\s+\([^)]*\))?)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([^\s;]+)", re.IGNORECASE)


@dataclass
class ReceivedHop:
    hop_index: int
    raw_header: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_parsed: Optional[datetime] = None


def _extract_ip(segment: str) -> Optional[str]:
    """Pull the first valid IPv4/IPv6 literal out of a `from` clause, typically inside []."""
    bracket_match = re.search(r"\[([0-9a-fA-F:.]+)\]", segment)
    candidates = []
    if bracket_match:
        candidates.append(bracket_match.group(1))
    candidates += _IP_RE.findall(segment)
    for c in candidates:
        try:
            ipaddress.ip_address(c)
            return c
        except ValueError:
            continue
    return None


def parse_received_headers(received_headers_raw: List[str]) -> List[ReceivedHop]:
    """received_headers_raw is in header order (top = most recent, appended by msg.get_all).

    Returns hops ordered earliest-first (hop_index 0 = earliest observed).
    """
    if not received_headers_raw:
        return []

    # Headers as returned by email.message.get_all preserve document order,
    # which is newest-first (each relay prepends). Reverse for chronological order.
    ordered = list(reversed(received_headers_raw))

    hops: List[ReceivedHop] = []
    for idx, raw in enumerate(ordered):
        normalized = re.sub(r"\s+", " ", raw).strip()

        from_match = _FROM_RE.search(normalized)
        by_match = _BY_RE.search(normalized)
        with_match = _WITH_RE.search(normalized)

        from_host = from_match.group(1).strip() if from_match else None
        by_host = by_match.group(1).strip() if by_match else None
        with_protocol = with_match.group(1).strip().rstrip(";") if with_match else None

        ip_address = _extract_ip(from_host) if from_host else None
        if not ip_address:
            ip_address = _extract_ip(normalized)

        # Timestamp is generally after a trailing semicolon
        timestamp_raw = None
        timestamp_parsed = None
        if ";" in normalized:
            timestamp_raw = normalized.rsplit(";", 1)[-1].strip()
            try:
                timestamp_parsed = parsedate_to_datetime(timestamp_raw)
            except Exception:
                timestamp_parsed = None

        hops.append(
            ReceivedHop(
                hop_index=idx,
                raw_header=raw,
                from_host=from_host,
                by_host=by_host,
                with_protocol=with_protocol,
                ip_address=ip_address,
                timestamp_raw=timestamp_raw,
                timestamp_parsed=timestamp_parsed,
            )
        )

    return hops


def describe_originating_infrastructure(hops: List[ReceivedHop]) -> Optional[str]:
    """Returns a cautiously-worded description of the earliest observed hop, or None."""
    if not hops:
        return None
    earliest = hops[0]
    host = earliest.from_host or "an unspecified host"
    ip = f" ({earliest.ip_address})" if earliest.ip_address else ""
    return (
        f"Earliest observed sending infrastructure in the Received chain: {host}{ip}. "
        "This is the earliest hop VISIBLE in the message headers, not a confirmed "
        "attacker location - Received headers can be forged or incomplete."
    )
