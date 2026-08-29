"""
Domain-level analysis: punycode, suspicious TLDs, excessive hyphenation,
and a reusable lookalike/typosquat similarity function.

We deliberately never say "this domain IS malicious" - only report
similarity + evidence + confidence and let the scoring engine / analyst
weigh it. A domain being different from a trusted domain is not, on its
own, malicious.
"""
from __future__ import annotations

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
