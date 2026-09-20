"""
SPF / DKIM / DMARC analysis.

We parse the `Authentication-Results` header(s) added by the receiving
mail system (RFC 8601) plus the `DKIM-Signature` header for the signing
domain/selector. We do NOT invent or simulate authentication results:
if the message has no Authentication-Results header, every result is
reported as UNKNOWN with source=INSUFFICIENT_DATA, and this is surfaced
to the user rather than silently guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

VALID_RESULTS = {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "UNKNOWN"}

_SPF_RE = re.compile(r"spf=(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
_SPF_DOMAIN_RE = re.compile(r"spf=\S+\s+.*?(?:smtp\.mailfrom|envelope-from)=(?P<domain>[^\s;]+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"dkim=(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
_DKIM_DOMAIN_RE = re.compile(r"dkim=\S+\s+.*?header\.d=(?P<domain>[^\s;]+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"dmarc=(?P<result>pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r"dmarc=\S+\s+.*?\bp=(?P<policy>none|quarantine|reject)", re.IGNORECASE)

_DKIM_SIG_DOMAIN_RE = re.compile(r"\bd=([^;]+);")
_DKIM_SIG_SELECTOR_RE = re.compile(r"\bs=([^;]+);")


@dataclass
class AuthComponentResult:
    result: str = "UNKNOWN"
    domain: Optional[str] = None
    raw: Optional[str] = None


@dataclass
class AuthenticationAnalysis:
    spf: AuthComponentResult = field(default_factory=AuthComponentResult)
    dkim: AuthComponentResult = field(default_factory=AuthComponentResult)
    dmarc: AuthComponentResult = field(default_factory=AuthComponentResult)
    dmarc_policy: Optional[str] = None

    from_return_path_aligned: Optional[bool] = None
    from_reply_to_aligned: Optional[bool] = None
    dkim_domain_aligned: Optional[bool] = None
    dmarc_alignment_pass: Optional[bool] = None

    raw_authentication_results_header: Optional[str] = None
    source: str = "OBSERVED"  # or INSUFFICIENT_DATA
    notes: List[str] = field(default_factory=list)


def _normalize(result: Optional[str]) -> str:
    if not result:
        return "UNKNOWN"
    r = result.strip().upper()
    return r if r in VALID_RESULTS else "UNKNOWN"


_TLDX_ORG = None


def org_domain(domain):
    """Registrable (organizational) domain: accounts.google.com -> google.com."""
    global _TLDX_ORG
    if not domain:
        return ""
    domain = domain.lower().strip(".")
    try:
        if _TLDX_ORG is None:
            import tldextract
            _TLDX_ORG = tldextract.TLDExtract(suffix_list_urls=())
        ext = _TLDX_ORG(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _domain_suffix_match(a: Optional[str], b: Optional[str]) -> Optional[bool]:
    """Loose organizational-domain alignment: exact match or one is a subdomain of the other."""
    if not a or not b:
        return None
    a, b = a.lower().strip("."), b.lower().strip(".")
    if a == b:
        return True
    if a.endswith("." + b) or b.endswith("." + a):
        return True
    # Relaxed alignment: same organizational domain (e.g. accounts.google.com
    # vs gaia.bounces.google.com) is aligned, exactly as DMARC relaxed mode.
    return bool(org_domain(a)) and org_domain(a) == org_domain(b)


def analyze_authentication(
    authentication_results_raw: List[str],
    dkim_signature_raw: List[str],
    sender_domain: Optional[str],
    reply_to_domain: Optional[str],
    return_path_domain: Optional[str],
) -> AuthenticationAnalysis:
    analysis = AuthenticationAnalysis()

    if not authentication_results_raw and not dkim_signature_raw:
        analysis.source = "INSUFFICIENT_DATA"
        analysis.notes.append(
            "No Authentication-Results or DKIM-Signature header present in this message. "
            "SPF/DKIM/DMARC status cannot be determined and is reported as UNKNOWN "
            "rather than inferred."
        )
        return analysis

    combined_auth_header = " ; ".join(authentication_results_raw)
    analysis.raw_authentication_results_header = combined_auth_header or None

    if authentication_results_raw:
        spf_match = _SPF_RE.search(combined_auth_header)
        spf_domain_match = _SPF_DOMAIN_RE.search(combined_auth_header)
        analysis.spf = AuthComponentResult(
            result=_normalize(spf_match.group("result") if spf_match else None),
            domain=spf_domain_match.group("domain").strip("<>") if spf_domain_match else None,
            raw=combined_auth_header if spf_match else None,
        )

        dkim_match = _DKIM_RE.search(combined_auth_header)
        dkim_domain_match = _DKIM_DOMAIN_RE.search(combined_auth_header)
        analysis.dkim = AuthComponentResult(
            result=_normalize(dkim_match.group("result") if dkim_match else None),
            domain=dkim_domain_match.group("domain").strip("<>") if dkim_domain_match else None,
            raw=combined_auth_header if dkim_match else None,
        )

        dmarc_match = _DMARC_RE.search(combined_auth_header)
        dmarc_policy_match = _DMARC_POLICY_RE.search(combined_auth_header)
        analysis.dmarc = AuthComponentResult(
            result=_normalize(dmarc_match.group("result") if dmarc_match else None),
            domain=sender_domain,
            raw=combined_auth_header if dmarc_match else None,
        )
        analysis.dmarc_policy = dmarc_policy_match.group("policy").upper() if dmarc_policy_match else None
    else:
        analysis.notes.append("No Authentication-Results header; DKIM info derived only from DKIM-Signature (not verified).")

    # If DKIM result missing from Authentication-Results, fall back to signature presence only
    if analysis.dkim.result == "UNKNOWN" and dkim_signature_raw:
        sig = dkim_signature_raw[0]
        d_match = _DKIM_SIG_DOMAIN_RE.search(sig)
        s_match = _DKIM_SIG_SELECTOR_RE.search(sig)
        analysis.dkim.domain = d_match.group(1).strip() if d_match else analysis.dkim.domain
        analysis.notes.append(
            "A DKIM-Signature header is present but no DKIM verification result was found "
            "in Authentication-Results; signature validity was NOT independently verified "
            "in Phase 1 (no cryptographic DKIM verification performed)."
        )

    # --- alignment checks ---------------------------------------------------
    analysis.from_return_path_aligned = _domain_suffix_match(sender_domain, return_path_domain)
    analysis.from_reply_to_aligned = _domain_suffix_match(sender_domain, reply_to_domain)
    analysis.dkim_domain_aligned = _domain_suffix_match(sender_domain, analysis.dkim.domain)

    if analysis.dmarc.result == "PASS":
        analysis.dmarc_alignment_pass = True
    elif analysis.dmarc.result in ("FAIL",):
        analysis.dmarc_alignment_pass = False
    else:
        analysis.dmarc_alignment_pass = None

    return analysis
