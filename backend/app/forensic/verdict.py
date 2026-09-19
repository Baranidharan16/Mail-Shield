"""
Forensic Verdict — the single, evidence-derived forensic conclusion for an
investigation (threat status, conditional deep-forensic agent, identity,
authentication, relay route/hops, threat origin, attack vectors, threat
path, integrity, recommended action).

Rules this module follows:
  * Every statement is computed from the investigation's stored evidence
    (parsed headers, hops, URLs, domains, indicators, model outputs) or a
    live lookup (GeoIP / RDAP / DNS). Nothing is templated as fact.
  * Every origin/geo field is tagged OBSERVED (read directly from the
    message or a lookup of an observed value), INFERRED (derived, e.g.
    geolocation of an IP) or UNKNOWN.
  * An IP is never presented as the attacker's physical location.
  * A threat vector is only listed when at least one piece of evidence
    supports it; the evidence is returned with it.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional

from app.intel.domain_intel import lookup_domain_intel
from app.intel.providers import get_geoip_provider

ORIGIN_DISCLAIMER = ("This identifies network infrastructure observed in the email path. It does not prove the "
                     "physical identity or location of the sender.")
NO_ORIGIN = "Origin cannot be reliably determined from the available evidence."

_KNOWN_MX = ("google.com", "gmail.com", "googlemail.com", "outlook.com", "protection.outlook.com",
             "hotmail.com", "office365.com", "yahoo.com", "yahoodns.net", "icloud.com", "apple.com",
             "zoho.com", "zohomail.com", "amazonses.com", "mimecast.com", "pphosted.com")

AUTH_MEANING = {
    "spf": {
        "PASS": "The sending server's IP is authorised by the sender domain's SPF record.",
        "FAIL": "The sending server's IP is NOT authorised by the sender domain — a strong spoofing indicator.",
        "SOFTFAIL": "The domain says this IP is probably not authorised (~all) — suspicious but not conclusive.",
        "NEUTRAL": "The domain makes no assertion about this IP.",
        "NONE": "No SPF result was recorded (domain has no SPF record, or the receiver did not check).",
        "PERMERROR": "The domain's SPF record is broken, so it could not be evaluated.",
        "TEMPERROR": "A temporary DNS error prevented SPF evaluation.",
    },
    "dkim": {
        "PASS": "The message carries a valid cryptographic signature — its signed content was not altered in transit.",
        "FAIL": "The DKIM signature did not verify — the message was altered or the signature is forged.",
        "NONE": "The message is not DKIM-signed (or the receiver did not record a result).",
        "NEUTRAL": "The signature could not be evaluated.",
        "PERMERROR": "The DKIM signature/key is malformed.",
        "TEMPERROR": "A temporary error prevented DKIM verification.",
    },
    "dmarc": {
        "PASS": "SPF or DKIM passed AND is aligned with the visible From domain — the From address is authentic.",
        "FAIL": "Neither aligned SPF nor aligned DKIM passed — the visible From domain is likely spoofed.",
        "NONE": "No DMARC result was recorded (the sender domain may publish no DMARC policy).",
        "BESTGUESSPASS": "No DMARC record, but the receiver's best-guess evaluation passed.",
        "TEMPERROR": "A temporary error prevented DMARC evaluation.",
        "PERMERROR": "The domain's DMARC record is malformed.",
    },
}

RECOMMENDED = {
    "Credential Phishing": "Do not click any link or enter credentials. Report the email and quarantine it; if a password was entered, reset it and enable 2FA immediately.",
    "Business Email Compromise": "Do not pay or change bank details. Verify the request by phone using a known number (not one in the email), then report and quarantine.",
    "Invoice / Payment Fraud": "Do not pay. Confirm the invoice with the supplier through a known contact channel before any payment; report and quarantine.",
    "Malware Delivery": "Do not open the attachment. Quarantine the email and submit the attachment hash to your security team / antivirus.",
    "Sender Spoofing": "Treat the sender as unverified. Do not act on requests in this email; report and quarantine it.",
    "Phishing": "Do not click links or reply. Report the email and quarantine it.",
    "Suspicious Email": "Treat with caution: verify the sender through another channel before acting on any request.",
    "No Threat Detected": "No action required. Stay alert for unexpected requests for credentials or payments.",
}


def _is_public(ip: Optional[str]) -> bool:
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_private or o.is_loopback or o.is_reserved or o.is_link_local or o.is_multicast
                    or any(o in ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")))
    except Exception:
        return False


def _band(score: float) -> str:
    if score >= 50:
        return "THREAT"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"


def _conf_word(c: float) -> str:
    return "High" if c >= 0.75 else "Medium" if c >= 0.5 else "Low"


def _ind(inv, *types) -> list:
    return [i for i in (inv.indicators or []) if i.indicator_type in types]


def _find(inv, *rule_ids) -> list:
    return [f for f in (inv.findings or []) if f.rule_id in rule_ids]


def _headers(inv, name: str) -> List[str]:
    return [h.value for h in (inv.headers or []) if h.name.lower() == name.lower()]


# ── hops / route ────────────────────────────────────────────────────────────
def _build_route(inv, geo_enabled: bool = True) -> List[Dict[str, Any]]:
    geo = get_geoip_provider()
    hops = sorted(inv.received_hops or [], key=lambda h: h.hop_index)
    out = []
    prev_ts = None
    n = len(hops)
    for pos, h in enumerate(hops):
        ip = h.ip_address or None
        indicators: List[str] = []
        g = geo.lookup_geo(ip) if (ip and geo_enabled and _is_public(ip)) else None
        if ip and not _is_public(ip):
            infra = "INTERNAL_OR_PRIVATE"
        elif g and g.get("available"):
            cat = g.get("network_category")
            infra = {"KNOWN_MAIL_OR_CLOUD_PLATFORM": "KNOWN_INFRASTRUCTURE",
                     "PROXY_VPN_OR_TOR": "SUSPICIOUS_INFRASTRUCTURE"}.get(cat, "UNKNOWN_INFRASTRUCTURE")
            if cat == "PROXY_VPN_OR_TOR":
                indicators.append("IP flagged as proxy / VPN / Tor exit by GeoIP provider")
        else:
            infra = "UNKNOWN_INFRASTRUCTURE"
        by = (h.by_host or "").lower()
        if any(by.endswith(k) for k in _KNOWN_MX) and infra == "UNKNOWN_INFRASTRUCTURE" and not ip:
            infra = "KNOWN_INFRASTRUCTURE"
        ts = h.timestamp_parsed
        if prev_ts and ts and ts < prev_ts:
            diff = (prev_ts - ts).total_seconds()
            if diff > 300:
                indicators.append(f"Timestamp is {int(diff // 60)} min EARLIER than the previous hop (clock skew or forged header)")
        prev_ts = ts or prev_ts
        if ip and not _is_public(ip) and 0 < pos < n - 1:
            indicators.append("Private IP in the middle of an internet relay path")
        if pos == 0:
            role = "Earliest observed sender / submitting host"
        elif pos == n - 1:
            role = "Recipient's mail server (delivery)"
        else:
            role = "Intermediate relay"
        if indicators and infra == "UNKNOWN_INFRASTRUCTURE":
            infra = "SUSPICIOUS_INFRASTRUCTURE"
        out.append({
            "hop": pos + 1,
            "received_header_number": n - pos,   # 1 = top-most Received header in the raw message
            "from_host": h.from_host, "by_host": h.by_host, "protocol": h.with_protocol,
            "ip": ip, "timestamp": ts.isoformat() if ts else (h.timestamp_raw or None),
            "reverse_dns": (g or {}).get("reverse_dns"),
            "asn": (g or {}).get("asn"), "network": (g or {}).get("org") or (g or {}).get("isp"),
            "country": (g or {}).get("country"), "city": (g or {}).get("city"),
            "role": role, "infrastructure": infra, "suspicious_indicators": indicators,
        })
    return out


# ── origin ──────────────────────────────────────────────────────────────────
def _build_origin(inv, route: List[Dict[str, Any]]) -> Dict[str, Any]:
    meta = inv.email_metadata
    public = [r for r in route if r["ip"] and _is_public(r["ip"])]
    base = {
        "sender_domain": {"value": getattr(meta, "sender_domain", None), "status": "OBSERVED" if getattr(meta, "sender_domain", None) else "UNKNOWN",
                          "evidence": "From header"},
        "relay_chain": [f'{r["from_host"] or r["ip"] or "?"} → {r["by_host"] or "?"}' for r in route],
        "disclaimer": ORIGIN_DISCLAIMER,
    }
    if not public:
        return {**base, "determined": False, "message": NO_ORIGIN,
                "reason": "No public IP address appears in the Received headers (the sending client/server did not "
                          "expose one, or the provider strips it).", "confidence": "Low"}
    node = public[0]
    geo = get_geoip_provider().lookup_geo(node["ip"])
    ga = geo.get("available")
    # Confidence: a hop recorded by a well-known receiving provider is hard to forge;
    # headers added before that point can be fabricated by the sender.
    recorded_by_known = any((r["by_host"] or "").lower().endswith(_KNOWN_MX) for r in route[route.index(node):route.index(node) + 2])
    confidence = "High" if (recorded_by_known and len(route) > 1) else "Medium" if len(route) > 1 else "Low"

    def f(val, status_if_present="INFERRED"):
        return {"value": val, "status": status_if_present if val not in (None, "") else "UNKNOWN"}

    return {
        **base,
        "determined": True,
        "observed_ip": {"value": node["ip"], "status": "OBSERVED",
                        "evidence": f'Received header #{node["received_header_number"]} (hop {node["hop"]} of {len(route)})'},
        "timestamp": {"value": node["timestamp"], "status": "OBSERVED" if node["timestamp"] else "UNKNOWN"},
        "claimed_hostname": f(node["from_host"], "OBSERVED"),
        "reverse_dns": f(geo.get("reverse_dns") if ga else None, "OBSERVED"),
        "asn": f(geo.get("asn") if ga else None),
        "network": f((geo.get("org") or geo.get("isp")) if ga else None),
        "country": f(geo.get("country") if ga else None),
        "region": f(geo.get("region") if ga else None),
        "city": f(geo.get("city") if (ga and not geo.get("hosting") and not geo.get("proxy")) else None),
        "coordinates": f(f'{geo.get("lat")}, {geo.get("lon")} (approximate centroid)' if ga and geo.get("lat") is not None else None),
        "timezone": f(geo.get("timezone") if ga else None),
        "mail_provider": f(geo.get("network_provider") if ga else None),
        "infrastructure_type": f(geo.get("network_category") if ga else None),
        "suspicious_indicators": node["suspicious_indicators"],
        "location_caveat": (geo.get("location_caveat") if ga else None),
        "geo_lookup_note": None if ga else geo.get("reason"),
        "accuracy_note": geo.get("accuracy_note") if ga else None,
        "confidence": confidence,
        "confidence_reason": ("The hop was recorded by a major receiving provider, which is difficult to forge."
                              if confidence == "High" else
                              "Headers before the recipient's own mail server can be fabricated by the sender; "
                              "treat this as the earliest *claimed* public hop."),
    }


# ── identity / auth ─────────────────────────────────────────────────────────
def _identity(inv) -> Dict[str, Any]:
    m = inv.email_metadata
    doms = inv.domains or []
    looks = [{"domain": d.domain, "role": d.role, "resembles": d.lookalike_of, "similarity": round(d.similarity_score or 0, 2)}
             for d in doms if d.lookalike_of]
    return {
        "from": getattr(m, "from_address", None), "display_name": getattr(m, "from_display_name", None),
        "reply_to": getattr(m, "reply_to", None), "return_path": getattr(m, "return_path", None),
        "sender_domain": getattr(m, "sender_domain", None),
        "reply_to_mismatch": bool(m and m.reply_to_domain and m.sender_domain and m.reply_to_domain != m.sender_domain),
        "return_path_mismatch": bool(m and m.return_path_domain and m.sender_domain and m.return_path_domain != m.sender_domain),
        "display_name_impersonation": [f.explanation for f in _find(inv, "HDR-009", "HDR-010")],
        "lookalike_domains": looks,
    }


def _authentication(inv) -> Dict[str, Any]:
    a = inv.authentication_result
    res = {}
    for k in ("spf", "dkim", "dmarc"):
        val = (getattr(a, f"{k}_result", None) or "NONE").upper() if a else "NONE"
        res[k] = {"result": val, "domain": getattr(a, f"{k}_domain", None) if a and k != "dmarc" else None,
                  "meaning": AUTH_MEANING[k].get(val, "Result recorded by the receiving server.")}
    arc = _headers(inv, "ARC-Authentication-Results")
    arc_seal = _headers(inv, "ARC-Seal")
    cv = None
    for s in arc_seal:
        mm = re.search(r"cv=(\w+)", s)
        if mm:
            cv = mm.group(1).upper()
    res["arc"] = {"present": bool(arc or arc_seal), "chain_validation": cv,
                  "meaning": ("ARC preserves authentication results across forwarders/mailing lists; "
                              f"chain validation = {cv}." if (arc or arc_seal) else
                              "No ARC headers (message was not relayed through an ARC-signing intermediary).")}
    res["source"] = getattr(a, "source", None) if a else None
    res["dmarc_policy"] = getattr(a, "dmarc_policy", None) if a else None
    return res


# ── vectors ─────────────────────────────────────────────────────────────────
def _vectors(inv, auth, identity, ml_p, nlp_p) -> List[Dict[str, Any]]:
    V: List[Dict[str, Any]] = []
    urls = inv.urls or []
    meta = inv.email_metadata
    atts = (getattr(meta, "attachments", None) or [])
    names = [(a.get("filename") or "").lower() for a in atts]

    def add(key, name, evidence):
        ev = [e for e in evidence if e]
        if ev:
            V.append({"key": key, "vector": name, "evidence": ev[:5]})

    cred = _ind(inv, "credential_request", "account_verification")
    risky_urls = [u for u in urls if (u.risk_score or 0) >= 40]
    if cred and urls:
        add("credential_harvesting", "Credential harvesting",
            [f'Text: "{(i.matched_evidence or "")[:90]}"' for i in cred[:2]] + [f"Link: {u.hostname}" for u in urls[:2]])
    if risky_urls:
        add("malicious_links", "Malicious / suspicious links",
            [f'{u.hostname}: {", ".join((u.risk_reasons or [])[:2])}' for u in risky_urls[:3]])
    redir = [u for u in urls if u.is_shortened or u.anchor_text_mismatch]
    if redir:
        add("url_redirection", "URL redirection / link disguise",
            [f'{u.hostname} ({"shortener" if u.is_shortened else "displayed text points elsewhere"})' for u in redir[:3]])
    spoof_ev = []
    if auth["dmarc"]["result"] == "FAIL":
        spoof_ev.append("DMARC = FAIL for the visible From domain")
    if auth["spf"]["result"] in ("FAIL", "SOFTFAIL"):
        spoof_ev.append(f'SPF = {auth["spf"]["result"]}')
    if auth["dkim"]["result"] == "FAIL":
        spoof_ev.append("DKIM signature failed")
    if spoof_ev:
        add("spoofed_sender", "Spoofed sender", spoof_ev)
    if identity["lookalike_domains"]:
        add("typosquatting", "Domain impersonation / typosquatting",
            [f'{l["domain"]} resembles {l["resembles"]} ({int(l["similarity"] * 100)}% similar)' for l in identity["lookalike_domains"]])
    if identity["display_name_impersonation"]:
        add("display_name_spoof", "Display-name impersonation", identity["display_name_impersonation"])
    exec_imp = _ind(inv, "executive_impersonation")
    pay_ind = _ind(inv, "payment_request", "invoice_payment_diversion")
    deception = identity["reply_to_mismatch"] or identity["display_name_impersonation"] or identity["lookalike_domains"]
    if exec_imp or (pay_ind and deception):
        add("bec", "Business email compromise (BEC)",
            [f'{i.indicator_type}: "{(i.matched_evidence or "")[:80]}"' for i in (exec_imp + pay_ind)[:2]]
            + (["Reply-To goes to a different domain than From"] if identity["reply_to_mismatch"] else [])
            + [f"Display name: {d}" for d in identity["display_name_impersonation"][:1]])
    pay = _ind(inv, "payment_request", "invoice_payment_diversion")
    if pay:
        add("payment_fraud", "Invoice / payment fraud", [f'"{(i.matched_evidence or "")[:90]}"' for i in pay[:2]])
    if _ind(inv, "account_verification") and _ind(inv, "fear_threat", "urgency"):
        add("fake_account_alert", "Fake account / security alert",
            [f'"{(i.matched_evidence or "")[:80]}"' for i in (_ind(inv, "account_verification") + _ind(inv, "fear_threat", "urgency"))[:2]])
    pr = _ind(inv, "password_reset_pressure")
    if pr:
        add("password_reset_scam", "Password-reset scam", [f'"{(i.matched_evidence or "")[:90]}"' for i in pr[:2]])
    exe = [n for n in names if re.search(r"\.(exe|scr|js|vbs|bat|cmd|ps1|jar|msi|lnk|hta|com|pif)$", n)]
    dbl = [n for n in names if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$", n)]
    htm = [n for n in names if re.search(r"\.(html?|shtml|svg)$", n)]
    arc = [n for n in names if re.search(r"\.(zip|rar|7z|iso|img)$", n)]
    if exe or dbl or htm or arc:
        add("malicious_attachment", "Malicious attachment",
            [f"Executable/script: {n}" for n in exe] + [f"Double extension: {n}" for n in dbl]
            + [f"HTML/SVG attachment (often a local fake login page): {n}" for n in htm]
            + [f"Archive/disk image (hides payload from scanners): {n}" for n in arc])
    mac = [n for n in names if re.search(r"\.(docm|xlsm|pptm|doc|xls)$", n)]
    if mac:
        add("macro_document", "Macro / document-based attack", [f"Macro-capable Office file: {n}" for n in mac])
    if exe or (mac and (ml_p or 0) >= 0.5):
        add("malware_delivery", "Malware delivery", [f"Attachment: {n}" for n in (exe + mac)[:3]])
    oauth = [u for u in urls if re.search(r"(accounts\.google\.com/o/oauth2|login\.microsoftonline\.com/.+/oauth2).*client_id=", u.url or "", re.I)]
    if oauth:
        add("oauth_consent", "OAuth application-consent abuse", [f"OAuth consent link: {u.hostname}" for u in oauth[:2]])
    subj = (getattr(meta, "subject", "") or "").lower()
    if any((a.get("content_type") or "").startswith("image/") for a in atts) and ("qr" in subj or any("qr" in (i.matched_evidence or "").lower() for i in inv.indicators or [])):
        add("qr_phishing", "QR-code phishing (quishing)", ["Image attachment together with QR-code wording"])
    aligned_pass = auth["dmarc"]["result"] == "PASS" or (auth["spf"]["result"] == "PASS" and auth["dkim"]["result"] == "PASS")
    if aligned_pass and min(ml_p or 0, nlp_p or 0) >= 0.5 and max(ml_p or 0, nlp_p or 0) >= 0.8 and (inv.risk_score or 0) >= 50:
        add("compromised_account", "Possibly compromised legitimate account (or attacker-owned domain)",
            ["Sender authentication PASSED, yet content/ML strongly indicate a threat — the real mailbox may be "
             "compromised, or the attacker registered this domain themselves"])
    if _ind(inv, "urgency", "fear_threat", "suspicious_call_to_action") and V:
        add("social_engineering", "Social engineering pressure",
            [f'{i.indicator_type}: "{(i.matched_evidence or "")[:70]}"' for i in _ind(inv, "urgency", "fear_threat", "suspicious_call_to_action")[:3]])
    return V


_TYPE_PRIORITY = [
    ("malware_delivery", "Malware Delivery"), ("malicious_attachment", "Malware Delivery"),
    ("bec", "Business Email Compromise"), ("payment_fraud", "Invoice / Payment Fraud"),
    ("credential_harvesting", "Credential Phishing"), ("password_reset_scam", "Credential Phishing"),
    ("fake_account_alert", "Credential Phishing"), ("oauth_consent", "Credential Phishing"),
    ("spoofed_sender", "Sender Spoofing"), ("typosquatting", "Phishing"), ("malicious_links", "Phishing"),
]


def build_forensic_verdict(inv, integrity: Optional[dict] = None, enrich_domains: bool = True) -> Dict[str, Any]:
    mlp = inv.ml_prediction
    ml_p = (mlp.structured_probabilities or {}).get("PHISHING") if (mlp and mlp.structured_available) else None
    nlp_p = (mlp.text_probabilities or {}).get("PHISHING") if (mlp and mlp.text_available) else None
    score = float(inv.risk_score or 0)
    status = _band(score)
    conf = float(inv.confidence or 0)
    critical = [f for f in (inv.findings or []) if f.severity == "CRITICAL"]

    triggers = []
    if mlp and mlp.structured_label == "PHISHING":
        triggers.append(f"ML model flagged THREAT ({ml_p:.0%})" if ml_p is not None else "ML model flagged THREAT")
    if mlp and mlp.text_label == "PHISHING":
        triggers.append(f"NLP model flagged HIGH RISK ({nlp_p:.0%})" if nlp_p is not None else "NLP model flagged HIGH RISK")
    for f in critical[:3]:
        triggers.append(f"Critical rule: {f.title}")
    if status == "THREAT" and not triggers:
        triggers.append(f"Fused risk score {score:.0f}/100")
    agent_triggered = bool(triggers)

    identity = _identity(inv)
    auth = _authentication(inv)
    route = _build_route(inv) if agent_triggered or status != "SAFE" else _build_route(inv, geo_enabled=False)
    origin = _build_origin(inv, route) if agent_triggered or status != "SAFE" else None
    vectors = _vectors(inv, auth, identity, ml_p, nlp_p)

    domain_intel = []
    if enrich_domains and (agent_triggered or status != "SAFE"):
        seen = set()
        cands = [identity.get("sender_domain")] + [u.hostname for u in (inv.urls or [])]
        for d in cands:
            if d and d not in seen and len(domain_intel) < 4:
                seen.add(d)
                info = lookup_domain_intel(d)
                if info and info["domain"] not in {x["domain"] for x in domain_intel}:
                    domain_intel.append(info)
        new = [d for d in domain_intel if d.get("newly_registered")]
        if new:
            vectors.append({"key": "new_domain", "vector": "Newly registered domain",
                            "evidence": [f'{d["domain"]} registered {d["domain_age_days"]} days ago' for d in new]})

    # Threat path (observed): sender infra -> relays -> recipient MX -> URL destinations -> victim
    path = []
    if route:
        first = route[0]
        path.append({"stage": "Sender / submitting host", "node": first["from_host"] or first["ip"] or "unknown",
                     "infrastructure": first["infrastructure"]})
        for r in route[1:-1]:
            path.append({"stage": "Relay server", "node": r["by_host"] or r["ip"] or "unknown", "infrastructure": r["infrastructure"]})
        last = route[-1]
        path.append({"stage": "Recipient mail infrastructure", "node": last["by_host"] or "unknown", "infrastructure": last["infrastructure"]})
    for u in [u for u in (inv.urls or []) if (u.risk_score or 0) >= 40][:2]:
        path.append({"stage": "URL / redirect destination" if (u.is_shortened or u.anchor_text_mismatch) else "Link destination",
                     "node": u.hostname, "infrastructure": "SUSPICIOUS_INFRASTRUCTURE"})
    path.append({"stage": "Recipient (you)", "node": "Inbox", "infrastructure": "—"})

    if status == "SAFE":
        threat_type = "No Threat Detected"
    else:
        keys = {v["key"] for v in vectors}
        threat_type = next((t for k, t in _TYPE_PRIORITY if k in keys), "Phishing" if status == "THREAT" else "Suspicious Email")

    primary = []
    for f in sorted(inv.findings or [], key=lambda f: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f.severity) if f.severity in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] else 0, reverse=True)[:3]:
        if f.severity in ("HIGH", "CRITICAL", "MEDIUM"):
            primary.append(f.title)
    for v in vectors[:3]:
        if len(primary) < 5:
            primary.append(f'{v["vector"]}: {v["evidence"][0]}')

    obs = "Not analysed (no threat indicators, deep forensics not triggered)"
    if origin and origin.get("determined"):
        parts = [origin["observed_ip"]["value"]]
        if origin["network"]["value"]:
            parts.append(origin["network"]["value"])
        if origin["country"]["value"]:
            parts.append(origin["country"]["value"])
        obs = " · ".join(parts) + f' ({origin["observed_ip"]["evidence"]})'
    elif origin:
        obs = NO_ORIGIN

    conclusion = {
        "status": status,
        "headline": {"THREAT": "THREAT DETECTED", "SUSPICIOUS": "SUSPICIOUS EMAIL", "SAFE": "NO THREAT DETECTED"}[status],
        "threat_type": threat_type,
        "risk_score": round(score, 1),
        "ml_risk": round(ml_p * 100, 1) if ml_p is not None else None,
        "nlp_risk": round(nlp_p * 100, 1) if nlp_p is not None else None,
        "primary_evidence": primary or (["No significant risk indicators were found."] if status == "SAFE" else []),
        "observed_origin": obs,
        "threat_path": " → ".join(p["node"] for p in path),
        "likely_attack_vectors": [v["vector"] for v in vectors[:4]],
        "confidence": _conf_word(conf),
        "confidence_value": round(conf, 2),
        "recommended_action": RECOMMENDED.get(threat_type, RECOMMENDED["Suspicious Email"]),
    }

    return {
        "investigation_id": inv.id, "case_id": inv.case_id,
        "conclusion": conclusion,
        "forensic_agent": {"triggered": agent_triggered, "triggers": triggers,
                           "rule": "Deep forensics runs when ML = THREAT, OR NLP = HIGH RISK, OR a CRITICAL rule fires, OR the fused score >= 50."},
        "models": {
            "ml": {"available": bool(mlp and mlp.structured_available), "label": mlp.structured_label if mlp else None,
                   "threat_probability": ml_p, "model_version": mlp.structured_model_version if mlp else None,
                   "top_features": (mlp.structured_top_features or [])[:6] if mlp else []},
            "nlp": {"available": bool(mlp and mlp.text_available), "label": mlp.text_label if mlp else None,
                    "threat_probability": nlp_p, "model_version": mlp.text_model_version if mlp else None,
                    "top_terms": [t for t in (mlp.text_top_features or []) if "term" in t][:8] if mlp else [],
                    "suspicious_sentences": [t for t in (mlp.text_top_features or []) if "sentence" in t][:3] if mlp else [],
                    "pattern_indicators": [{"type": i.indicator_type, "evidence": i.matched_evidence, "confidence": i.confidence,
                                            "explanation": i.explanation} for i in (inv.indicators or [])][:10]},
        },
        "identity": identity,
        "authentication": auth,
        "route": route,
        "origin": origin,
        "attack_vectors": vectors,
        "threat_path": path,
        "domain_intelligence": domain_intel,
        "integrity": integrity,
    }
