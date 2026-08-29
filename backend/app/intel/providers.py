"""
Concrete threat-intelligence providers (Part 5).

Two providers ship out of the box, selected via THREAT_INTEL_PROVIDER:

  - "local" (DEFAULT): a fully offline, deterministic heuristic provider.
    It never makes a network call, so it always works, never times out,
    and never returns unreliable data - important because this
    application may run in network-restricted environments (sandboxes,
    air-gapped SOCs) where "real" enrichment cannot be trusted anyway.
    Every result is explicitly flagged so the UI can show "heuristic /
    demo" rather than imply a live vendor lookup.

  - "dns": a best-effort REAL provider that performs actual DNS A/MX/NS
    lookups for domain intelligence via dnspython. This is genuine network
    enrichment (not fabricated), but is wrapped in strict timeouts and
    exception handling per the brief ("every external API must have
    timeout/error handling... continue functioning with degraded
    intelligence if unavailable").

Additional real vendor integrations (AbuseIPDB, VirusTotal, etc.) can be
added as additional classes implementing the same interfaces in
`interfaces.py` - callers never need to change, only the
THREAT_INTEL_PROVIDER config value and an API key env var.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from typing import Optional

from app.intel.interfaces import DomainIntelligenceProvider, IntelResult, IPIntelligenceProvider, URLIntelligenceProvider
from urllib.parse import urlparse

DNS_TIMEOUT_SECONDS = 2.0

# TEST-NET ranges (RFC 5737) used throughout our SYNTHETIC test fixtures.
# Mapped to fixed demo metadata so the geolocation/ASN UI has something
# meaningful to render for the bundled demo data, CLEARLY labeled as
# synthetic - never presented as real geolocation.
_DEMO_IP_RANGES = {
    "192.0.2.0/24": {"country": "Demo-Country A", "asn": "AS64511", "org": "Synthetic Demo Hosting A", "is_synthetic": True},
    "198.51.100.0/24": {"country": "Demo-Country B", "asn": "AS64512", "org": "Synthetic Demo Hosting B", "is_synthetic": True},
    "203.0.113.0/24": {"country": "Demo-Country C", "asn": "AS64513", "org": "Synthetic Demo Hosting C", "is_synthetic": True},
}


class LocalHeuristicIPProvider(IPIntelligenceProvider):
    name = "local_heuristic"

    def lookup_ip(self, ip_address: str) -> IntelResult:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return IntelResult(indicator=ip_address, indicator_type="ip", provider=self.name, available=False, error="Invalid IP address")

        # Check documentation/demo ranges FIRST: Python's ipaddress module
        # classifies RFC 5737 TEST-NET ranges (used throughout this
        # platform's synthetic fixtures) as `is_private`, which would
        # otherwise short-circuit them into the generic private/reserved
        # bucket below before we ever get to show the demo data.
        for cidr, meta in _DEMO_IP_RANGES.items():
            if ip_obj in ipaddress.ip_network(cidr):
                return IntelResult(
                    indicator=ip_address, indicator_type="ip", provider=self.name, available=True,
                    data={**meta, "note": "SYNTHETIC DEMONSTRATION DATA - this IP falls in an RFC 5737 documentation range used by this platform's test fixtures."},
                    risk_score=35.0,
                    is_synthetic_demo_data=True,
                )

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return IntelResult(
                indicator=ip_address, indicator_type="ip", provider=self.name, available=True,
                data={"classification": "private/reserved", "note": "Private or reserved address space - no external reputation applicable."},
                risk_score=0.0,
            )

        return IntelResult(
            indicator=ip_address, indicator_type="ip", provider=self.name, available=True,
            data={"note": "No local heuristic data available for this public IP. Configure THREAT_INTEL_PROVIDER for live enrichment."},
            risk_score=None,
        )


class LocalHeuristicDomainProvider(DomainIntelligenceProvider):
    name = "local_heuristic"

    def lookup_domain(self, domain: str) -> IntelResult:
        from app.forensic.domain_analyzer import analyze_domain
        finding = analyze_domain(domain, role="intel_lookup")
        return IntelResult(
            indicator=domain, indicator_type="domain", provider=self.name, available=True,
            data={
                "is_punycode": finding.is_punycode,
                "suspicious_tld": finding.suspicious_tld,
                "excessive_hyphenation": finding.excessive_hyphenation,
                "note": "Heuristic lexical analysis only - no live DNS/WHOIS/reputation query performed by this provider.",
            },
            risk_score=finding.risk_score,
        )


class LocalHeuristicURLProvider(URLIntelligenceProvider):
    name = "local_heuristic"

    def lookup_url(self, url: str) -> IntelResult:
        from app.forensic.url_analyzer import _build_finding
        finding = _build_finding(url, source_location="intel_lookup", anchor_text=None)
        return IntelResult(
            indicator=url, indicator_type="url", provider=self.name, available=True,
            data={"risk_reasons": finding.risk_reasons, "note": "Heuristic lexical analysis only - URL was never fetched."},
            risk_score=finding.risk_score,
        )


class DNSDomainProvider(DomainIntelligenceProvider):
    """Best-effort REAL DNS enrichment (A/MX/NS records). Genuine network
    lookup, not fabricated - but gracefully degrades to unavailable on any
    timeout/error, per the brief's resilience requirement."""
    name = "dns"

    def lookup_domain(self, domain: str) -> IntelResult:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT_SECONDS
            resolver.lifetime = DNS_TIMEOUT_SECONDS

            data = {}
            for rtype in ("A", "MX", "NS"):
                try:
                    answers = resolver.resolve(domain, rtype)
                    data[rtype] = [str(r) for r in answers]
                except Exception:
                    data[rtype] = []

            has_any = any(data.values())
            return IntelResult(
                indicator=domain, indicator_type="domain", provider=self.name, available=has_any,
                data=data,
                risk_score=0.0 if has_any else None,
                error=None if has_any else "No DNS records resolved (domain may not exist, or network egress is restricted in this environment).",
            )
        except Exception as exc:  # noqa: BLE001
            return IntelResult(
                indicator=domain, indicator_type="domain", provider=self.name, available=False,
                error=f"DNS lookup failed: {type(exc).__name__}: {exc}",
            )


class GeoIPProvider:
    """
    Real geolocation via ip-api.com (free tier, no API key required).
    Rate limited to 45 req/min. Fails gracefully per resilience requirement.

    IMPORTANT: Results are labeled 'Probable infrastructure geolocation'.
    Never claim this identifies the physical location of an attacker.
    Received-header IPs reflect mail relay infrastructure, not the sender.
    """
    name = "geoip_ipapi"
    _ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query,hosting"

    def lookup_geo(self, ip_address: str) -> dict:
        try:
            import ipaddress as _ip
            ip_obj = _ip.ip_address(ip_address)
            # Skip private/reserved - no public geo applies
            for cidr in _DEMO_IP_RANGES:
                if ip_obj in _ip.ip_network(cidr):
                    demo = _DEMO_IP_RANGES[cidr]
                    return {
                        "available": True,
                        "is_synthetic_demo_data": True,
                        "country": demo.get("country", "Demo Country"),
                        "country_code": "ZZ",
                        "city": "Demo City",
                        "region": "Demo Region",
                        "isp": demo.get("org", "Demo ISP"),
                        "asn": demo.get("asn", "AS64511"),
                        "lat": 0.0,
                        "lon": 0.0,
                        "hosting": True,
                        "disclaimer": "SYNTHETIC DEMONSTRATION DATA — not a real geolocation.",
                        "label": "Probable infrastructure geolocation (SYNTHETIC)",
                    }
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return {"available": False, "reason": "Private/reserved address — no geolocation applicable."}
        except ValueError:
            return {"available": False, "reason": "Invalid IP address"}

        try:
            import requests as _req
            resp = _req.get(
                self._ENDPOINT.format(ip=ip_address),
                timeout=3.0,
            )
            resp.raise_for_status()
            d = resp.json()
            if d.get("status") != "success":
                return {"available": False, "reason": d.get("message", "ip-api returned non-success status")}
            return {
                "available": True,
                "is_synthetic_demo_data": False,
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "asn": d.get("as"),
                "lat": d.get("lat"),
                "lon": d.get("lon"),
                "hosting": d.get("hosting", False),
                "disclaimer": "Probable infrastructure geolocation — this reflects observed mail relay infrastructure, NOT the physical location of the sender or attacker.",
                "label": "Probable infrastructure geolocation",
            }
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "reason": f"GeoIP lookup unavailable: {type(exc).__name__}"}


_geoip_provider = GeoIPProvider()


def get_geoip_provider() -> GeoIPProvider:
    return _geoip_provider


def get_default_ip_provider() -> IPIntelligenceProvider:
    return LocalHeuristicIPProvider()


def get_default_domain_provider(provider_name: str = "local") -> DomainIntelligenceProvider:
    if provider_name == "dns":
        return DNSDomainProvider()
    return LocalHeuristicDomainProvider()


def get_default_url_provider() -> URLIntelligenceProvider:
    return LocalHeuristicURLProvider()
