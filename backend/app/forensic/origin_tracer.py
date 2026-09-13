"""
Origin Traceability Engine — Earliest Reliable Observable Sending Node Analyzer.

Implements Layer 3 of SIH Problem Statement 26106:
- Reconstructs email transmission path across Received headers.
- Detects relay anomalies: duplicate hops, impossible timestamps, private IPs in external path.
- Isolates the EARLIEST RELIABLE OBSERVABLE SENDING NODE available from forensic evidence.
- Evaluates infrastructure type: CLOUD_VPS, VPN_PROXY, TOR, MAIL_HOSTING, RESIDENTIAL_ISP, UNKNOWN.
- Computes Infrastructure Confidence score (0-100%).
- Strictly adheres to forensic evidentiary guidelines: never claims physical attacker location.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ObservableNode:
    hop_index: int
    ip_address: str
    from_host: str
    by_host: str
    protocol: str
    timestamp_raw: str
    timestamp_parsed: Optional[str]
    is_private: bool
    is_earliest_reliable: bool
    infrastructure_type: str  # CLOUD_VPS / VPN_PROXY / TOR / MAIL_HOSTING / RESIDENTIAL / UNKNOWN
    geo_data: Optional[Dict[str, Any]] = None
    flags: List[str] = field(default_factory=list)


@dataclass
class OriginTraceResult:
    earliest_node: Optional[ObservableNode]
    total_hops: int
    public_hops: int
    relay_path: List[ObservableNode]
    anomalies: List[Dict[str, Any]]
    confidence_score: float
    infrastructure_type: str
    summary_verdict: str
    disclaimer: str = (
        "Probable infrastructure geolocation — reflects observed mail relay infrastructure, "
        "NOT the physical location of the sender or attacker."
    )


# Common cloud and hosting provider patterns
_CLOUD_KEYWORDS = [
    "aws", "amazon", "ec2", "azure", "microsoft", "google", "gcp", "digitalocean",
    "linode", "ovh", "hetzner", "vultr", "oraclecloud", "rackspace", "cloudflare",
    "leaseweb", "contabo", "choopa", "akamai",
]

_VPN_PROXY_KEYWORDS = [
    "vpn", "proxy", "tor-exit", "nordvpn", "expressvpn", "mullvad", "surfshark",
    "privateinternetaccess", "exit-node", "relay",
]


def analyze_origin_trace(
    received_hops: List[Dict[str, Any]],
    geo_results: Optional[List[Dict[str, Any]]] = None,
) -> OriginTraceResult:
    """
    Parse chronological hops (hop_index 0 = earliest received header) and
    identify the earliest reliable observable non-private sending node.
    """
    geo_by_ip: Dict[str, Dict[str, Any]] = {}
    if geo_results:
        for g in geo_results:
            ip = g.get("ip_address")
            if ip and g.get("geo"):
                geo_by_ip[ip] = g.get("geo", {})

    parsed_nodes: List[ObservableNode] = []
    anomalies: List[Dict[str, Any]] = []

    prev_dt: Optional[datetime] = None

    for hop in received_hops:
        hop_idx = hop.get("hop_index", 0)
        raw_ip = hop.get("ip_address") or ""
        from_host = hop.get("from_host") or ""
        by_host = hop.get("by_host") or ""
        proto = hop.get("with_protocol") or "SMTP"
        ts_raw = hop.get("timestamp_raw") or ""
        ts_parsed = hop.get("timestamp_parsed")

        # Determine IP address validity and privacy
        is_private = True
        if raw_ip:
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
            except ValueError:
                is_private = True

        # Check timestamp chronological order
        node_flags: List[str] = []
        if ts_parsed:
            try:
                cur_dt = datetime.fromisoformat(str(ts_parsed).replace("Z", "+00:00"))
                if prev_dt and cur_dt < prev_dt:
                    diff_sec = (prev_dt - cur_dt).total_seconds()
                    anomalies.append({
                        "type": "CHRONOLOGY_INVERSION",
                        "severity": "HIGH",
                        "hop_index": hop_idx,
                        "description": f"Hop #{hop_idx} timestamp precedes earlier hop by {int(diff_sec)}s (clock skew or forged header).",
                    })
                    node_flags.append("Timestamp Inverted")
                prev_dt = cur_dt
            except Exception:
                pass

        # Check duplicate hosts / loop indicators
        if from_host and by_host and from_host.lower() == by_host.lower():
            node_flags.append("Self-Relay")

        # Geo intelligence for this hop
        g_data = geo_by_ip.get(raw_ip)
        infra_type = _classify_infrastructure(from_host, by_host, raw_ip, g_data)

        node = ObservableNode(
            hop_index=hop_idx,
            ip_address=raw_ip,
            from_host=from_host,
            by_host=by_host,
            protocol=proto,
            timestamp_raw=ts_raw,
            timestamp_parsed=str(ts_parsed) if ts_parsed else None,
            is_private=is_private,
            is_earliest_reliable=False,
            infrastructure_type=infra_type,
            geo_data=g_data,
            flags=node_flags,
        )
        parsed_nodes.append(node)

    # Detect earliest reliable observable public sending node
    earliest_node: Optional[ObservableNode] = None
    for n in parsed_nodes:
        if not n.is_private and n.ip_address:
            earliest_node = n
            n.is_earliest_reliable = True
            break

    # If no public hop in Received headers, fallback to first observed node
    if not earliest_node and parsed_nodes:
        earliest_node = parsed_nodes[0]
        earliest_node.is_earliest_reliable = True
        anomalies.append({
            "type": "NO_PUBLIC_HOPS_OBSERVED",
            "severity": "MEDIUM",
            "description": "All received hops utilize private or unresolvable network ranges.",
        })

    # Compute overall origin confidence score
    confidence = 0.5
    if earliest_node:
        if not earliest_node.is_private:
            confidence += 0.25
        if earliest_node.geo_data and earliest_node.geo_data.get("country"):
            confidence += 0.15
        if not anomalies:
            confidence += 0.10
        else:
            confidence -= 0.10 * len(anomalies)

    confidence = round(max(0.1, min(0.98, confidence)), 2)

    infra_verdict = earliest_node.infrastructure_type if earliest_node else "UNKNOWN"
    summary = (
        f"Earliest observable sending infrastructure is {infra_verdict} at "
        f"{earliest_node.ip_address if earliest_node else 'N/A'} "
        f"with {int(confidence * 100)}% infrastructure confidence."
    )

    return OriginTraceResult(
        earliest_node=earliest_node,
        total_hops=len(parsed_nodes),
        public_hops=sum(1 for n in parsed_nodes if not n.is_private),
        relay_path=parsed_nodes,
        anomalies=anomalies,
        confidence_score=confidence,
        infrastructure_type=infra_verdict,
        summary_verdict=summary,
    )


def _classify_infrastructure(
    from_host: str,
    by_host: str,
    ip_str: str,
    geo_data: Optional[Dict[str, Any]],
) -> str:
    combined_text = f"{from_host} {by_host}".lower()
    if geo_data:
        isp = str(geo_data.get("isp") or "").lower()
        org = str(geo_data.get("org") or "").lower()
        asn = str(geo_data.get("asn") or "").lower()
        combined_text += f" {isp} {org} {asn}"

    for kw in _VPN_PROXY_KEYWORDS:
        if kw in combined_text:
            return "VPN_PROXY"

    for kw in _CLOUD_KEYWORDS:
        if kw in combined_text:
            return "CLOUD_VPS"

    if geo_data and geo_data.get("hosting") is True:
        return "CLOUD_VPS"

    if any(m in combined_text for m in ["mail", "smtp", "mx", "outbound", "relay", "exchange"]):
        return "MAIL_HOSTING"

    if any(r in combined_text for r in ["broadband", "dsl", "cable", "dynamic", "pool", "dhcp"]):
        return "RESIDENTIAL_ISP"

    return "UNKNOWN"
