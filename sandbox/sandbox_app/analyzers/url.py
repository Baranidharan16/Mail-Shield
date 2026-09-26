"""Static URL analysis. The sandbox has NO outbound network, so URLs are
never fetched ("detonation-free"): every signal is lexical/structural."""
from __future__ import annotations

import ipaddress
import re
from typing import List
from urllib.parse import parse_qs, unquote, urlsplit

from ..rules import Finding

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
              "rb.gy", "t.ly", "tiny.cc", "s.id", "bitly.com", "v.gd", "qrco.de", "urlz.fr"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam", "kim",
                   "loan", "win", "bid", "icu", "buzz", "monster", "sbs", "cfd", "quest", "support", "live", "shop", "online"}
ABUSED_HOSTING = ("ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com", "firebaseapp.com", "web.app",
                  "pages.dev", "workers.dev", "glitch.me", "repl.co", "herokuapp.com", "blogspot.com", "weebly.com",
                  "wixsite.com", "sites.google.com", "ipfs.io", "dweb.link", "github.io", "netlify.app", "vercel.app",
                  "r2.dev", "azurewebsites.net", "square.site", "godaddysites.com", "forms.gle", "linktr.ee")
BRAND_TOKENS = ("paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon", "netflix", "google", "gmail",
                "sbi", "onlinesbi", "hdfc", "icici", "axisbank", "kotak", "paytm", "phonepe", "npci", "incometax", "gst",
                "uidai", "aadhaar", "epfo", "digilocker", "indiapost", "irctc", "rbi", "sebi")
OFFICIAL = {"paypal": ("paypal.com",), "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
            "office365": ("office.com", "microsoft.com"), "outlook": ("outlook.com", "live.com", "office.com"),
            "apple": ("apple.com",), "icloud": ("icloud.com", "apple.com"), "amazon": ("amazon.com", "amazon.in"),
            "netflix": ("netflix.com",), "google": ("google.com", "google.co.in", "googleusercontent.com"), "gmail": ("gmail.com", "google.com"),
            "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi"), "onlinesbi": ("onlinesbi.sbi", "onlinesbi.com"), "hdfc": ("hdfcbank.com",),
            "icici": ("icicibank.com",), "axisbank": ("axisbank.com",), "kotak": ("kotak.com",), "paytm": ("paytm.com",),
            "phonepe": ("phonepe.com",), "npci": ("npci.org.in",), "incometax": ("incometax.gov.in",), "gst": ("gst.gov.in",),
            "uidai": ("uidai.gov.in",), "aadhaar": ("uidai.gov.in",), "epfo": ("epfindia.gov.in",), "digilocker": ("digilocker.gov.in",),
            "indiapost": ("indiapost.gov.in",), "irctc": ("irctc.co.in",), "rbi": ("rbi.org.in",), "sebi": ("sebi.gov.in",)}
CRED_WORDS = re.compile(r"(?i)(log-?in|sign-?in|verify|verification|secure|update|account|password|wallet|kyc|unlock|suspend|confirm|billing|otp|refund)")
DL_EXT = re.compile(r"(?i)\.(exe|scr|msi|js|jse|vbs|hta|ps1|bat|cmd|iso|img|lnk|apk|jar|zip|rar|7z|docm|xlsm)(\?|$)")
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def analyze_url(url: str) -> List[Finding]:
    out: List[Finding] = []
    u = url.strip()
    lowu = u.lower()
    if lowu.startswith(("javascript:", "data:", "vbscript:")):
        return [Finding("SBX-URL-001", "Script / data URI link", "HIGH", 0.85, "url",
                        "The link executes script or embeds content instead of navigating to a site.", u[:200], "T1204.001",
                        "Runs script in the browser when clicked.")]
    if lowu.startswith("hxxp"):
        u = "http" + u[4:]
    try:
        sp = urlsplit(u if "://" in u else "http://" + u)
    except ValueError:
        return [Finding("SBX-URL-002", "Malformed URL", "LOW", 0.5, "url", "URL cannot be parsed.", u[:200])]
    host = (sp.hostname or "").lower().rstrip(".")
    netloc = sp.netloc
    path_q = unquote(sp.path + ("?" + sp.query if sp.query else ""))

    if sp.scheme == "http":
        out.append(Finding("SBX-URL-003", "Unencrypted HTTP link", "LOW", 0.5, "url",
                           "Link does not use TLS.", u[:200]))
    try:
        ipaddress.ip_address(host)
        out.append(Finding("SBX-URL-004", "Raw IP-address host", "HIGH", 0.8, "url",
                           "Legitimate organisations link to domain names, not bare IP addresses.", host, "T1583.003",
                           "Victim connects directly to attacker infrastructure."))
    except ValueError:
        pass
    if "@" in netloc:
        out.append(Finding("SBX-URL-005", "Credential-style '@' in URL", "HIGH", 0.85, "url",
                           "Everything before '@' is ignored by the browser — 'https://paypal.com@evil.tld' goes to evil.tld.",
                           netloc[:200], "T1036"))
    if "xn--" in host:
        out.append(Finding("SBX-URL-006", "Punycode / IDN homograph host", "HIGH", 0.8, "url",
                           "Internationalised domain can visually imitate a real brand using look-alike Unicode letters.",
                           host, "T1583.001"))
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        out.append(Finding("SBX-URL-007", f"High-abuse TLD .{tld}", "MEDIUM", 0.6, "url",
                           f"The .{tld} TLD is disproportionately used for phishing/malware.", host))
    if len(labels) >= 5:
        out.append(Finding("SBX-URL-008", "Excessive sub-domains", "MEDIUM", 0.6, "url",
                           "Deep sub-domain chains hide the real registered domain (e.g. login.microsoft.com.secure-x.xyz).", host))
    if host in SHORTENERS:
        out.append(Finding("SBX-URL-009", "URL shortener", "MEDIUM", 0.6, "url",
                           "Shorteners hide the real destination from the reader and from filters.", host, "T1608.005"))
    if any(host == h or host.endswith("." + h) for h in ABUSED_HOSTING):
        out.append(Finding("SBX-URL-010", "Free / tunnel hosting frequently abused by phishing kits", "MEDIUM", 0.65, "url",
                           "Free hosting and tunnelling services let attackers stand up a login page in minutes.", host, "T1583.006"))
    if sp.port and sp.port not in (80, 443):
        out.append(Finding("SBX-URL-011", "Non-standard port", "MEDIUM", 0.55, "url", f"Link uses port {sp.port}.", netloc))
    squash = host.translate(LEET).replace("-", "")
    offs = ()
    for b in BRAND_TOKENS:
        # brand must start a DNS label (paypal-login.xyz, secure.sbi-kyc.top) — avoids 'pineapple' → 'apple'
        if b not in squash or not re.search(rf"(^|[.\-]){b}", host.translate(LEET)):
            continue
        if len(b) < 4 and not re.search(rf"(^|[.\-]){b}([.\-]|$)", host.translate(LEET)):
            continue
        offs = OFFICIAL.get(b, ())
        if any(host == o or host.endswith("." + o) for o in offs):
            break  # the real brand domain
        if b not in host:
            out.append(Finding("SBX-URL-012", f"Look-alike brand domain ({b})", "HIGH", 0.85, "url",
                               f"Host imitates '{b}' using character substitution (e.g. 0→o, 1→l).", host, "T1583.001"))
        else:
            out.append(Finding("SBX-URL-013", f"Brand name on unrelated domain ({b})", "HIGH", 0.75, "url",
                               f"'{b}' appears in a domain that is not an official {b} domain"
                               + (f" ({', '.join(offs)})" if offs else "") + ".", host, "T1583.001"))
        break
    if not host.endswith(".gov.in") and re.search(r"(gov-in|govin|gov\.in\.|nic-in|india-gov)", host):
        out.append(Finding("SBX-URL-014", "Fake Indian government domain", "CRITICAL", 0.85, "url",
                           "Host imitates a .gov.in / NIC domain without being one.", host, "T1583.001",
                           "Impersonates a government portal to steal data or payments."))
    if DL_EXT.search(sp.path):
        out.append(Finding("SBX-URL-015", "Direct download of risky file type", "HIGH", 0.8, "url",
                           "Link points straight at an executable, script, disk image or archive.", sp.path[-120:], "T1204.002",
                           "Downloads a payload when clicked."))
    qs = parse_qs(sp.query)
    for k, vals in qs.items():
        if k.lower() in ("url", "redirect", "redirect_uri", "next", "r", "u", "dest", "destination", "goto", "target", "continue", "returnurl") \
                and any(v.lower().startswith(("http", "//")) for v in vals):
            out.append(Finding("SBX-URL-016", "Open-redirect parameter", "MEDIUM", 0.7, "url",
                               "A trusted domain is used to bounce the victim to another site.", f"{k}={vals[0][:120]}", "T1204.001"))
            break
    if CRED_WORDS.search(path_q) and (out and any(f.severity in ("MEDIUM", "HIGH", "CRITICAL") for f in out)):
        out.append(Finding("SBX-URL-017", "Credential-lure wording in path", "MEDIUM", 0.6, "url",
                           "Path uses login/verify/KYC-style wording on an already-suspicious host.", path_q[:120], "T1566.002"))
    if "%25" in u or len(u) > 250:
        out.append(Finding("SBX-URL-018", "Obfuscated / overly long URL", "LOW", 0.5, "url",
                           "Double-encoding or very long URLs are used to hide the real destination.", u[:120], "T1027"))
    return out
