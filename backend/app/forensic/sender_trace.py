"""
Sender tracking (SIH PS 26106 — origin traceability).

Adds three evidence sources on top of the Received-chain reconstruction:

1. CLIENT-SUBMISSION IPs — headers that submitting mail servers / webmail
   stamp with the IP of the device that actually submitted the message
   (X-Originating-IP, X-Sender-IP, X-MS-Exchange-...-OriginalClientIPAddress,
   X-Forwarded-For, ...). When present this is the closest observable point to
   the real sender, earlier than any Received hop.
2. SENDER-DOMAIN INFRASTRUCTURE — live DNS A / MX resolution of the From,
   Return-Path and DKIM (d=) domains, so the platform can show where the
   claimed sender's mail/web infrastructure is hosted even when the mail
   provider (e.g. Gmail) strips the client IP.
3. DNS BLOCKLIST REPUTATION — real-time DNSBL queries (Spamhaus ZEN, SpamCop,
   Barracuda) for every public IP observed in the trace.

Everything is real network evidence with strict timeouts; on any failure the
item is returned as unavailable — nothing is fabricated. Locations describe
INFRASTRUCTURE, never the physical location or identity of a person.
"""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Tuple

DNS_TIMEOUT = 2.0

# Header name (lower-case) -> human description. Order = trust preference.
CLIENT_IP_HEADERS: List[Tuple[str, str]] = [
    ("x-ms-exchange-organization-originalclientipaddress", "Microsoft 365 original client IP"),
    ("x-originating-ip", "Webmail/submission server stamped originating client IP"),
    ("x-sender-ip", "Submission server stamped sender IP"),
    ("x-client-ip", "Client IP stamped by submission server"),
    ("x-real-ip", "Client IP stamped by front-end proxy"),
    ("x-forwarded-for", "Client IP chain stamped by proxy (first entry)"),
    ("x-mailgun-sending-ip", "Mailgun sending IP"),
    ("x-sender-ip-address", "Sender IP stamped by submission server"),
    ("x-yahoo-post-ip", "Yahoo webmail posting IP"),
    ("x-apparently-from-ip", "Apparent sender IP"),
]

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
]


def _is_public(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (o.is_private or o.is_loopback or o.is_reserved or o.is_link_local
                or o.is_multicast or o.is_unspecified)


def _ips_in(value: str) -> List[str]:
    out: List[str] = []
    for m in list(_IPV4.findall(value or "")) + list(_IPV6.findall(value or "")):
        try:
            out.append(str(ipaddress.ip_address(m.strip("[]"))))
        except ValueError:
            continue
    return out


def extract_client_ips(headers: Iterable[Tuple[str, str]]) -> List[Dict[str, object]]:
    """Returns [{ip, header, description, is_public}] from client-submission headers."""
    found: List[Dict[str, object]] = []
    seen = set()
    hdrs = [((n or "").strip().lower(), v or "") for n, v in headers]
    for name, desc in CLIENT_IP_HEADERS:
        for hname, value in hdrs:
            if hname != name:
                continue
            ips = _ips_in(value)
            if name == "x-forwarded-for":
                ips = ips[:1]
            for ip in ips:
                if ip in seen:
                    continue
                seen.add(ip)
                found.append({"ip": ip, "header": hname, "description": desc, "is_public": _is_public(ip)})
    return found


def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    return r


def _resolve(name: str, rtype: str) -> List[str]:
    try:
        return [str(x).rstrip(".") for x in _resolver().resolve(name, rtype)]
    except Exception:  # noqa: BLE001 — NXDOMAIN / timeout / no egress
        return []


def resolve_domain_infrastructure(domain: str, role: str, max_ips: int = 3) -> List[Dict[str, object]]:
    """A + MX resolution for one domain -> [{role, domain, host, ip, record}]."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return []
    items: List[Dict[str, object]] = []
    for ip in _resolve(domain, "A")[:max_ips]:
        items.append({"role": role, "domain": domain, "host": domain, "ip": ip, "record": "A"})
    mx_hosts = []
    for mx in _resolve(domain, "MX"):
        parts = mx.split()
        mx_hosts.append((int(parts[0]) if parts[0].isdigit() else 0, parts[-1]))
    for _, host in sorted(mx_hosts)[:2]:
        for ip in _resolve(host, "A")[:1]:
            items.append({"role": role, "domain": domain, "host": host, "ip": ip, "record": "MX"})
    return items


def dnsbl_check(ip: str) -> Dict[str, object]:
    """Real-time DNSBL reputation for an IPv4 address.

    Spamhaus answers 127.255.255.x when the query is refused (e.g. via public
    resolvers) — those are reported as 'unavailable', never as listed."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return {"checked": False, "reason": "invalid IP"}
    if o.version != 4 or not _is_public(ip):
        return {"checked": False, "reason": "only public IPv4 addresses are checked against DNSBLs"}
    rev = ".".join(reversed(ip.split(".")))

    def one(zone_label):
        zone, label = zone_label
        answers = _resolve(f"{rev}.{zone}", "A")
        if not answers:
            return {"list": label, "listed": False}
        if all(a.startswith("127.255.255.") for a in answers):
            return {"list": label, "listed": None, "note": "query refused by list operator"}
        return {"list": label, "listed": True, "codes": answers}

    with ThreadPoolExecutor(max_workers=len(DNSBL_ZONES)) as ex:
        results = list(ex.map(one, DNSBL_ZONES))
    listed = [r["list"] for r in results if r.get("listed")]
    return {"checked": True, "listed_on": listed, "results": results,
            "reputation": "BLOCKLISTED" if listed else "CLEAN"}


def build_sender_infrastructure(
    from_domain: Optional[str],
    return_path_domain: Optional[str],
    dkim_domain: Optional[str],
    geo_lookup,
) -> List[Dict[str, object]]:
    """Resolve + geolocate the claimed sender's infrastructure (deduplicated by IP)."""
    roles = []
    for dom, role in ((from_domain, "FROM_DOMAIN"), (return_path_domain, "RETURN_PATH_DOMAIN"),
                      (dkim_domain, "DKIM_SIGNING_DOMAIN")):
        if dom and dom.lower() not in [d for d, _ in roles]:
            roles.append((dom.lower(), role))
    if not roles:
        return []
    with ThreadPoolExecutor(max_workers=3) as ex:
        groups = list(ex.map(lambda dr: resolve_domain_infrastructure(dr[0], dr[1]), roles))
    items, seen = [], set()
    for g in groups:
        for it in g:
            if it["ip"] in seen:
                continue
            seen.add(it["ip"])
            items.append(it)
    items = items[:8]
    with ThreadPoolExecutor(max_workers=4) as ex:
        geos = list(ex.map(lambda it: geo_lookup(it["ip"]), items))
    for it, geo in zip(items, geos):
        it["geo"] = geo if geo and geo.get("available") else None
    return items
