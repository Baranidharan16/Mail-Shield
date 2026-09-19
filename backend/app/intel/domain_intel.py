"""
Live domain intelligence (real lookups, cached, strict timeouts):

* RDAP (the IETF successor of WHOIS, via https://rdap.org bootstrap):
  registration date -> domain age, registrar.
* DNS: MX records, SPF (TXT v=spf1) and DMARC (_dmarc TXT) policy.

Every field is either an observed lookup result or None with a reason —
nothing is guessed. Newly registered domains (< 30 days) are a strong,
well-documented phishing indicator.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Dict, Optional

_CACHE: Dict[str, dict] = {}
_LOCK = threading.Lock()
_TTL = 6 * 3600


_TLDX = None


def _extractor():
    """Offline public-suffix extractor, built once (construction is expensive)."""
    global _TLDX
    if _TLDX is None:
        import tldextract
        _TLDX = tldextract.TLDExtract(suffix_list_urls=())
    return _TLDX


def _registrable(domain: str) -> str:
    try:
        ext = _extractor()(domain)
        return ".".join(p for p in (ext.domain, ext.suffix) if p) or domain
    except Exception:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _rdap(domain: str) -> dict:
    try:
        import requests
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=5, headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return {"rdap_available": False, "rdap_reason": "Domain not found in RDAP (may be unregistered or its registry has no RDAP)."}
        r.raise_for_status()
        d = r.json()
        created = None
        for ev in d.get("events", []):
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
        registrar = None
        for ent in d.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        age_days = None
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
            except Exception:
                pass
        return {"rdap_available": True, "registered_on": created, "domain_age_days": age_days, "registrar": registrar}
    except Exception as exc:  # noqa: BLE001
        return {"rdap_available": False, "rdap_reason": f"RDAP lookup unavailable ({type(exc).__name__})."}


def _dns(domain: str) -> dict:
    out = {"mx": [], "spf_record": None, "dmarc_record": None, "dmarc_policy": None, "dns_available": False}
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = res.lifetime = 3.0
        try:
            out["mx"] = sorted(str(r.exchange).rstrip(".") for r in res.resolve(domain, "MX"))[:5]
            out["dns_available"] = True
        except Exception:
            pass
        try:
            for r in res.resolve(domain, "TXT"):
                txt = b"".join(r.strings).decode(errors="ignore")
                if txt.lower().startswith("v=spf1"):
                    out["spf_record"] = txt[:300]
            out["dns_available"] = True
        except Exception:
            pass
        try:
            for r in res.resolve(f"_dmarc.{domain}", "TXT"):
                txt = b"".join(r.strings).decode(errors="ignore")
                if txt.lower().startswith("v=dmarc1"):
                    out["dmarc_record"] = txt[:300]
                    for part in txt.split(";"):
                        k, _, v = part.strip().partition("=")
                        if k.lower() == "p":
                            out["dmarc_policy"] = v.strip()
        except Exception:
            pass
    except Exception:
        pass
    return out


def lookup_domain_intel(domain: Optional[str]) -> Optional[dict]:
    if not domain:
        return None
    reg = _registrable(domain.lower().strip("."))
    with _LOCK:
        hit = _CACHE.get(reg)
        if hit and time.time() - hit["_at"] < _TTL:
            return {k: v for k, v in hit.items() if k != "_at"}
    data = {"domain": reg, **_rdap(reg), **_dns(reg)}
    age = data.get("domain_age_days")
    data["newly_registered"] = bool(age is not None and age < 30)
    data["checked_at"] = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        if len(_CACHE) > 2000:
            _CACHE.clear()
        _CACHE[reg] = {**data, "_at": time.time()}
    return data
