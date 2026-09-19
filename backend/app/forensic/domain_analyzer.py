"""
Domain-level analysis: punycode, suspicious TLDs, excessive hyphenation,
and a reusable lookalike/typosquat similarity function.

We deliberately never say "this domain IS malicious" - only report
similarity + evidence + confidence and let the scoring engine / analyst
weigh it. A domain being different from a trusted domain is not, on its
own, malicious.
"""
from __future__ import annotations

import re

from dataclasses import dataclass, field
from typing import List, Optional

from app.forensic.url_analyzer import SUSPICIOUS_TLDS


@dataclass
class DomainFinding:
    domain: str
    role: str  # sender/reply_to/return_path/url/received
    is_punycode: bool = False
    suspicious_tld: bool = False
    excessive_hyphenation: bool = False
    lookalike_of: Optional[str] = None
    similarity_score: float = 0.0  # 0-1, 1 = identical
    risk_score: float = 0.0
    evidence: List[str] = field(default_factory=list)


def levenshtein(a: str, b: str) -> int:
    """Standard edit-distance implementation (pure Python, no dependency)."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def domain_similarity(domain_a: str, domain_b: str) -> float:
    """Returns a normalized similarity score in [0, 1] where 1 = identical.

    Based on normalized Levenshtein distance over the registrable-ish
    domain string (case-insensitive).
    """
    a, b = domain_a.lower().strip("."), domain_b.lower().strip(".")
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    dist = levenshtein(a, b)
    max_len = max(len(a), len(b))
    return max(0.0, 1.0 - (dist / max_len))


# Frequently impersonated brands -> their genuine registrable domains.
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"}, "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "office365": {"office.com", "microsoft.com"}, "outlook": {"outlook.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"}, "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"}, "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.in", "amazonses.com", "amazon.co.uk"}, "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"}, "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"}, "linkedin": {"linkedin.com"}, "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"}, "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"}, "hdfcbank": {"hdfcbank.com", "hdfc.bank.in"},
    "icicibank": {"icicibank.com"}, "axisbank": {"axisbank.com"}, "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"}, "irctc": {"irctc.co.in"}, "incometax": {"incometax.gov.in"}, "uidai": {"uidai.gov.in"},
    "docusign": {"docusign.com", "docusign.net"}, "dropbox": {"dropbox.com"}, "adobe": {"adobe.com"},
    "github": {"github.com"}, "zoom": {"zoom.us"},
}
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


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
        return ".".join(p for p in (ext.domain, ext.suffix) if p)
    except Exception:
        parts = domain.lower().split(".")
        return ".".join(parts[-2:])


def _primary(brand: str) -> str:
    g = BRAND_DOMAINS[brand]
    for d in sorted(g, key=len):
        if d.startswith(brand + "."):
            return d
    return sorted(g)[0]


def brand_impersonation(domain: str):
    """Returns (brand, genuine_domain, evidence) when a domain imitates a well-known brand
    (homoglyph e.g. micros0ft, or brand embedded in a foreign domain e.g. sbi-kyc-update.top)."""
    reg = _registrable(domain.lower())
    label = reg.split(".")[0]
    norm = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand, genuine in BRAND_DOMAINS.items():
        if reg in genuine:
            return None
        if label == brand:
            continue  # e.g. paypal.xyz handled by exact-label rule below
        tokens = re.split(r"[-_.]", norm)
        if norm != label and (norm == brand or brand in tokens):
            return brand, _primary(brand), f"'{reg}' uses look-alike characters to imitate '{brand}' (genuine: {', '.join(sorted(genuine))})"
        if brand in tokens and len(brand) >= 3:
            return brand, _primary(brand), f"'{reg}' embeds the brand name '{brand}' but is not an official {brand} domain"
    if label in BRAND_DOMAINS and reg not in BRAND_DOMAINS[label]:
        genuine = BRAND_DOMAINS[label]
        return label, _primary(brand), f"'{reg}' uses the brand name '{label}' on an unofficial TLD (genuine: {', '.join(sorted(genuine))})"
    return None


def analyze_domain(
    domain: str,
    role: str,
    trusted_domains: Optional[List[str]] = None,
) -> DomainFinding:
    finding = DomainFinding(domain=domain, role=role)
    trusted_domains = trusted_domains or []

    if "xn--" in domain.lower():
        finding.is_punycode = True
        finding.evidence.append("Domain contains punycode (xn--) encoding, often used for homograph/lookalike attacks")

    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        finding.suspicious_tld = True
        finding.evidence.append(f"Uses a top-level domain ('.{tld}') frequently associated with abuse")

    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        finding.excessive_hyphenation = True
        finding.evidence.append(f"Domain contains {hyphen_count} hyphens, a pattern common in brand-impersonation domains")

    # Lookalike detection against configured trusted domains
    best_match: Optional[str] = None
    best_score = 0.0
    for trusted in trusted_domains:
        score = domain_similarity(domain, trusted)
        if domain.lower() == trusted.lower():
            continue  # identical = not a lookalike, it's the real thing
        if score > best_score:
            best_score = score
            best_match = trusted

    brand = brand_impersonation(domain)
    if brand and not (best_match and best_score >= 0.75):
        finding.lookalike_of = brand[1]
        finding.similarity_score = 0.9
        finding.evidence.append(brand[2] + " - possible brand impersonation (similarity observation, not proof of intent).")

    if best_match and best_score >= 0.75:
        finding.lookalike_of = best_match
        finding.similarity_score = round(best_score, 3)
        finding.evidence.append(
            f"Domain is highly similar ({best_score:.0%}) to trusted domain '{best_match}' but is NOT an exact match - "
            "possible typosquat/lookalike. This is a similarity observation, not confirmed malicious intent."
        )

    # risk score purely additive/deterministic
    risk = 0.0
    if finding.is_punycode:
        risk += 30
    if finding.suspicious_tld:
        risk += 15
    if finding.excessive_hyphenation:
        risk += 10
    if finding.lookalike_of:
        risk += 35 * finding.similarity_score
    finding.risk_score = min(100.0, risk)

    return finding
