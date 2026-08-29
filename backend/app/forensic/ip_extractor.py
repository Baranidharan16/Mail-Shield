from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional

from app.forensic.received_parser import ReceivedHop
from app.forensic.url_analyzer import URLFinding


@dataclass
class IPFinding:
    ip_address: str
    ip_version: int
    source: str  # received_hop / url
    is_private: bool
    hop_index: Optional[int] = None


def extract_ip_addresses(hops: List[ReceivedHop], url_findings: List[URLFinding]) -> List[IPFinding]:
    findings: List[IPFinding] = []
    seen = set()

    for hop in hops:
        if not hop.ip_address:
            continue
        try:
            ip_obj = ipaddress.ip_address(hop.ip_address)
        except ValueError:
            continue
        key = (str(ip_obj), "received_hop", hop.hop_index)
        if key in seen:
            continue
        seen.add(key)
        findings.append(IPFinding(
            ip_address=str(ip_obj),
            ip_version=ip_obj.version,
            source="received_hop",
            is_private=ip_obj.is_private,
            hop_index=hop.hop_index,
        ))

    for url in url_findings:
        if not url.is_ip_based or not url.hostname:
            continue
        host = url.hostname.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            continue
        key = (str(ip_obj), "url", None)
        if key in seen:
            continue
        seen.add(key)
        findings.append(IPFinding(
            ip_address=str(ip_obj),
            ip_version=ip_obj.version,
            source="url",
            is_private=ip_obj.is_private,
        ))

    return findings
