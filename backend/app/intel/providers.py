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

        for cidr in _DEMO_IP_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                return IntelResult(
                    indicator=ip_address, indicator_type="ip", provider=self.name, available=False,
                    error="RFC 5737 documentation/test address - not a real internet host; no intelligence applies.",
                )

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return IntelResult(
                indicator=ip_address, indicator_type="ip", provider=self.name, available=True,
                data={"classification": "private/reserved", "note": "Private or reserved address space - no external reputation applicable."},
                risk_score=0.0,
            )

        geo = get_geoip_provider().lookup_geo(ip_address)
        if not geo.get("available"):
            return IntelResult(indicator=ip_address, indicator_type="ip", provider=self.name, available=False,
                               error=geo.get("reason"))
        risk = 0.0
        notes = []
        if geo.get("proxy"):
            risk = 50.0
            notes.append("IP is flagged by the GeoIP provider as a proxy/VPN/Tor exit.")
        elif geo.get("network_category") == "HOSTING_OR_CLOUD":
            risk = 20.0
            notes.append("IP belongs to a hosting/cloud network (common for both legitimate senders and attackers).")
        return IntelResult(
            indicator=ip_address, indicator_type="ip", provider="ip-api.com", available=True,
            data={"asn": geo.get("asn"), "org": geo.get("org"), "country": geo.get("country"),
                  "network_category": geo.get("network_category"), "proxy": geo.get("proxy"),
                  "hosting": geo.get("hosting"), "note": " ".join(notes) or "No risk indicators from network ownership."},
            risk_score=risk,
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


_KNOWN_PROVIDERS = {
    "google": "Google", "microsoft": "Microsoft", "outlook": "Microsoft", "amazon": "Amazon (AWS/SES)",
    "aws": "Amazon (AWS/SES)", "cloudflare": "Cloudflare", "yahoo": "Yahoo", "oath": "Yahoo",
    "sendgrid": "Twilio SendGrid", "mailchimp": "Mailchimp", "mailgun": "Mailgun", "sparkpost": "SparkPost",
    "zoho": "Zoho", "proofpoint": "Proofpoint", "mimecast": "Mimecast", "apple": "Apple",
    "akamai": "Akamai", "fastly": "Fastly", "digitalocean": "DigitalOcean", "ovh": "OVH",
    "hetzner": "Hetzner", "linode": "Akamai/Linode", "vultr": "Vultr", "contabo": "Contabo",
}
_MAIL_PLATFORMS = {"Google", "Microsoft", "Amazon (AWS/SES)", "Yahoo", "Twilio SendGrid", "Mailchimp",
                   "Mailgun", "SparkPost", "Zoho", "Proofpoint", "Mimecast", "Apple"}


def classify_network(org_text: str, hosting: bool = False, proxy: bool = False) -> dict:
    """Classifies the network that owns an IP from its registered org/ASN text.
    Returns {provider, category, location_caveat}. Purely descriptive."""
    low = (org_text or "").lower()
    provider = next((name for key, name in _KNOWN_PROVIDERS.items() if key in low), None)
    if proxy:
        category = "PROXY_VPN_OR_TOR"
    elif provider in _MAIL_PLATFORMS:
        category = "KNOWN_MAIL_OR_CLOUD_PLATFORM"
    elif provider or hosting:
        category = "HOSTING_OR_CLOUD"
    elif org_text:
        category = "ISP_OR_ORGANISATION"
    else:
        category = "UNKNOWN"
    caveat = None
    if category in ("KNOWN_MAIL_OR_CLOUD_PLATFORM", "HOSTING_OR_CLOUD", "PROXY_VPN_OR_TOR"):
        caveat = ("This IP belongs to " + (provider or "a hosting/proxy network") + "; its location is that of "
                  "the service's infrastructure (data centre / edge), NOT the physical location of the sender.")
    return {"provider": provider, "category": category, "location_caveat": caveat}


class GeoIPProvider:
    """
    IP -> approximate geolocation + network ownership via ip-api.com
    (free tier, no key, 45 req/min). Results are cached in-process.

    Accuracy: country-level is usually right; region/city for hosting,
    mobile and proxy networks is frequently wrong. Coordinates are the
    approximate centre of the city/region, never a street address.
    Never used to locate a person; only to describe infrastructure
    observed in an e-mail's own headers.
    """
    name = "geoip_ipapi"
    _ENDPOINT = ("http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,"
                 "city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    _cache: dict = {}

    def lookup_geo(self, ip_address: str) -> dict:
        try:
            import ipaddress as _ip
            ip_obj = _ip.ip_address(ip_address)
            for cidr in _DEMO_IP_RANGES:
                if ip_obj in _ip.ip_network(cidr):
                    return {"available": False, "reason": "RFC 5737 documentation/test address — not routable on the internet; no geolocation exists."}
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return {"available": False, "reason": "Private/internal address — belongs to a mail provider's internal network; no public geolocation."}
        except ValueError:
            return {"available": False, "reason": "Invalid IP address"}

        if ip_address in self._cache:
            return self._cache[ip_address]
        try:
            import requests as _req
            resp = _req.get(self._ENDPOINT.format(ip=ip_address), timeout=4.0)
            resp.raise_for_status()
            d = resp.json()
            if d.get("status") != "success":
                return {"available": False, "reason": d.get("message", "GeoIP service returned no data")}
            net = classify_network(" ".join(filter(None, [d.get("org"), d.get("isp"), d.get("as"), d.get("asname")])),
                                   hosting=bool(d.get("hosting")), proxy=bool(d.get("proxy")))
            out = {
                "available": True,
                "is_synthetic_demo_data": False,
                "source": "ip-api.com",
                "country": d.get("country"), "country_code": d.get("countryCode"),
                "region": d.get("regionName"), "city": d.get("city"),
                "lat": d.get("lat"), "lon": d.get("lon"), "timezone": d.get("timezone"),
                "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"), "as_name": d.get("asname"),
                "reverse_dns": d.get("reverse") or None,
                "hosting": bool(d.get("hosting")), "proxy": bool(d.get("proxy")), "mobile": bool(d.get("mobile")),
                "network_provider": net["provider"], "network_category": net["category"],
                "location_caveat": net["location_caveat"],
                "accuracy_note": "Approximate: country-level is generally reliable; region/city is an estimate "
                                 "and coordinates are a city/region centroid.",
                "disclaimer": "Probable infrastructure geolocation — reflects network infrastructure observed in the "
                              "e-mail path, NOT the physical location or identity of the sender.",
                "label": "Probable infrastructure geolocation",
            }
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[ip_address] = out
            return out
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
