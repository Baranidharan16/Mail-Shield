"""
Threat-intelligence enrichment orchestrator.

Takes a Phase 1 `ForensicAnalysisResult`, runs every distinct IP/domain/URL
indicator through the configured providers (via the TTL cache), and
produces an aggregate score + reasons the Threat Fusion Engine can
consume. This is the "Part 5/6" glue layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.forensic.engine import ForensicAnalysisResult
from app.intel.cache import get_or_fetch
from app.intel.interfaces import IntelResult
from app.intel.providers import get_default_domain_provider, get_default_ip_provider, get_default_url_provider

settings = get_settings()


@dataclass
class EnrichmentSummary:
    ip_results: List[Dict] = field(default_factory=list)
    domain_results: List[Dict] = field(default_factory=list)
    url_results: List[Dict] = field(default_factory=list)
    aggregate_score: Optional[float] = None
    reasons: List[str] = field(default_factory=list)
    providers_used: List[str] = field(default_factory=list)


def enrich_investigation(db: Session, result: ForensicAnalysisResult) -> EnrichmentSummary:
    ip_provider = get_default_ip_provider()
    domain_provider = get_default_domain_provider(getattr(settings, "THREAT_INTEL_DOMAIN_PROVIDER", "local"))
    url_provider = get_default_url_provider()

    providers_used = {ip_provider.name, domain_provider.name, url_provider.name}
    reasons: List[str] = []
    risk_points: List[float] = []

    ip_results = []
    seen_ips = {ip.ip_address for ip in result.ip_findings}
    for ip_addr in seen_ips:
        intel = get_or_fetch(
            db, ip_provider.name, "ip", ip_addr,
            fetch_fn=lambda addr=ip_addr: ip_provider.lookup_ip(addr),
        )
        ip_results.append(_intel_to_dict(intel))
        if intel.available and intel.risk_score:
            risk_points.append(intel.risk_score)
            if intel.is_synthetic_demo_data:
                reasons.append(f"IP {ip_addr}: {intel.data.get('note', 'synthetic demo intelligence')}")
            elif intel.risk_score > 0:
                reasons.append(f"IP {ip_addr} intelligence indicates elevated risk (heuristic score {intel.risk_score:.0f}).")

    domain_results = []
    seen_domains = {d.domain for d in result.domain_findings}
    for domain in seen_domains:
        intel = get_or_fetch(
            db, domain_provider.name, "domain", domain,
            fetch_fn=lambda d=domain: domain_provider.lookup_domain(d),
        )
        domain_results.append(_intel_to_dict(intel))
        if intel.available and intel.risk_score:
            risk_points.append(intel.risk_score)
            if intel.risk_score > 20:
                reasons.append(f"Domain intelligence for {domain} flags lexical risk indicators (score {intel.risk_score:.0f}).")

    url_results = []
    seen_urls = {u.url for u in result.url_findings}
    for url in seen_urls:
        intel = get_or_fetch(
            db, url_provider.name, "url", url,
            fetch_fn=lambda u=url: url_provider.lookup_url(u),
        )
        url_results.append(_intel_to_dict(intel))
        if intel.available and intel.risk_score:
            risk_points.append(intel.risk_score)

    aggregate_score = round(sum(risk_points) / len(risk_points), 2) if risk_points else None

    if not reasons:
        reasons.append("No elevated-risk indicators returned by the configured threat-intelligence providers.")

    return EnrichmentSummary(
        ip_results=ip_results,
        domain_results=domain_results,
        url_results=url_results,
        aggregate_score=aggregate_score,
        reasons=reasons,
        providers_used=sorted(providers_used),
    )


def _intel_to_dict(intel: IntelResult) -> Dict:
    return {
        "indicator": intel.indicator,
        "indicator_type": intel.indicator_type,
        "provider": intel.provider,
        "available": intel.available,
        "data": intel.data,
        "risk_score": intel.risk_score,
        "error": intel.error,
        "fetched_at": intel.fetched_at,
        "is_synthetic_demo_data": intel.is_synthetic_demo_data,
    }
