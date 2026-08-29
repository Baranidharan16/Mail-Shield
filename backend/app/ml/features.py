"""
Feature engineering (Phase 2, Part 1).

Builds a normalized, DOCUMENTED feature vector on top of the existing
Phase 1 forensic engine output (`ForensicAnalysisResult`). This module
does not re-implement parsing/analysis - it only reshapes Phase 1's
already-computed, evidence-backed findings into a flat numeric/categorical
representation suitable for the ML models in `app/ml/structured_model.py`
and the text model in `app/ml/text_model.py`.

Every feature has a one-line documented meaning in `FEATURE_DOCS` so the
vector is auditable - this is what lets the fusion engine and the model
card explain *why* a score came out the way it did, rather than treating
the model as a black box.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.forensic.engine import ForensicAnalysisResult

FEATURE_VERSION = "1.0.0"

FEATURE_DOCS: Dict[str, str] = {
    # Header features
    "from_replyto_mismatch": "1 if From and Reply-To domains differ, else 0",
    "from_returnpath_mismatch": "1 if From and Return-Path domains differ, else 0",
    "auth_data_available": "1 if the message carried Authentication-Results/DKIM-Signature headers",
    "spf_fail": "1 if SPF result is FAIL",
    "spf_softfail": "1 if SPF result is SOFTFAIL",
    "dkim_fail": "1 if DKIM result is FAIL",
    "dmarc_fail": "1 if DMARC result is FAIL",
    "dkim_domain_misaligned": "1 if DKIM signing domain does not align with From domain",
    "received_hop_count": "number of Received headers observed (relay chain length)",
    "received_hops_missing": "1 if there are zero Received headers",
    "received_hop_ip_unresolved_ratio": "fraction of hops with no extractable IP address",
    "message_id_missing": "1 if Message-ID header absent",
    "message_id_domain_mismatch": "1 if Message-ID domain differs from From domain",
    "header_anomaly_count": "count of header-category deterministic findings",
    "header_anomaly_max_severity": "max severity (0-4) among header-category findings",
    # Sender / identity features
    "display_name_domain_impersonation": "1 if display name embeds a different brand/domain than the From address",
    "exec_title_freemail": "1 if an executive title appears in display name while sender uses a free webmail domain",
    "sender_domain_is_freemail": "1 if sender domain is a known free consumer webmail provider",
    "multiple_unrelated_domains": "1 if From/Reply-To/Return-Path reference 3+ distinct unrelated domains",
    # Domain features (aggregated across sender/reply-to/return-path/url domains)
    "domain_count_analyzed": "number of distinct domains analyzed in this message",
    "any_domain_punycode": "1 if any analyzed domain contains punycode (xn--)",
    "any_domain_suspicious_tld": "1 if any analyzed domain uses a TLD frequently abused in phishing",
    "any_domain_excessive_hyphenation": "1 if any analyzed domain has 2+ hyphens",
    "max_domain_lookalike_similarity": "highest lookalike/typosquat similarity score (0-1) to a trusted domain",
    "avg_domain_risk_score": "mean of individual domain risk scores (0-100)",
    "max_domain_risk_score": "max of individual domain risk scores (0-100)",
    # URL features (aggregated)
    "url_count": "number of URLs extracted from the message",
    "any_url_ip_based": "1 if any URL's host is a raw IP address",
    "any_url_shortened": "1 if any URL uses a known link-shortening service",
    "any_url_punycode": "1 if any URL host contains punycode",
    "any_url_suspicious_tld": "1 if any URL uses a suspicious TLD",
    "any_url_anchor_mismatch": "1 if any URL's displayed anchor text does not match its real destination host",
    "any_url_suspicious_query": "1 if any URL has credential/verification-style query parameters",
    "avg_url_risk_score": "mean of individual URL risk scores (0-100)",
    "max_url_risk_score": "max of individual URL risk scores (0-100)",
    # Text / social-engineering features
    "urgency_present": "1 if urgency language pattern detected",
    "fear_threat_present": "1 if fear/threat language pattern detected",
    "credential_request_present": "1 if credential-request language pattern detected",
    "payment_request_present": "1 if payment-request language pattern detected",
    "account_verification_present": "1 if account-verification pretext language detected",
    "password_reset_pressure_present": "1 if password-reset-pressure language detected",
    "executive_impersonation_present": "1 if executive-impersonation conversational pattern detected",
    "invoice_payment_diversion_present": "1 if invoice/payment-diversion language detected",
    "suspicious_cta_present": "1 if a suspicious call-to-action (click/open/enable macros) detected",
    "social_engineering_indicator_count": "total number of distinct social-engineering indicator types matched",
    "social_engineering_max_confidence": "highest confidence (0-1) among matched social-engineering indicators",
    # Infrastructure features
    "any_hop_ip_private": "1 if any Received-hop IP is a private/reserved address (unusual for internet-transited mail)",
    "ip_address_count": "number of distinct IP addresses observed (hops + IP-based URLs)",
}

FEATURE_NAMES: List[str] = list(FEATURE_DOCS.keys())

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class FeatureVector:
    version: str
    values: Dict[str, float] = field(default_factory=dict)

    def as_ordered_list(self) -> List[float]:
        return [float(self.values.get(name, 0.0)) for name in FEATURE_NAMES]

    def as_dict(self) -> Dict[str, float]:
        return dict(self.values)


def build_feature_vector(result: ForensicAnalysisResult) -> FeatureVector:
    """Pure function: Phase 1 analysis result -> documented feature vector.
    Deterministic - same input always yields the same output."""
    v: Dict[str, float] = {}
    parsed = result.parsed_email
    auth = result.authentication

    # --- header features ---
    v["from_replyto_mismatch"] = float(bool(parsed.sender_domain and parsed.reply_to_domain and parsed.sender_domain != parsed.reply_to_domain))
    v["from_returnpath_mismatch"] = float(bool(parsed.sender_domain and parsed.return_path_domain and parsed.sender_domain != parsed.return_path_domain))
    v["auth_data_available"] = float(auth.source == "OBSERVED")
    v["spf_fail"] = float(auth.spf.result == "FAIL")
    v["spf_softfail"] = float(auth.spf.result == "SOFTFAIL")
    v["dkim_fail"] = float(auth.dkim.result == "FAIL")
    v["dmarc_fail"] = float(auth.dmarc.result == "FAIL")
    v["dkim_domain_misaligned"] = float(auth.dkim_domain_aligned is False)
    v["received_hop_count"] = float(len(result.received_hops))
    v["received_hops_missing"] = float(len(result.received_hops) == 0)
    unresolved = sum(1 for h in result.received_hops if not h.ip_address)
    v["received_hop_ip_unresolved_ratio"] = float(unresolved / len(result.received_hops)) if result.received_hops else 0.0
    v["message_id_missing"] = float(not parsed.message_id)

    header_findings = [f for f in result.header_findings if f.category == "header"]
    v["header_anomaly_count"] = float(len(header_findings))
    v["header_anomaly_max_severity"] = float(max((_SEVERITY_ORDER.get(f.severity, 0) for f in header_findings), default=0))
    v["message_id_domain_mismatch"] = float(any(f.rule_id == "HDR-007" for f in result.header_findings))

    # --- sender / identity ---
    v["display_name_domain_impersonation"] = float(any(f.rule_id == "HDR-009" for f in result.header_findings))
    v["exec_title_freemail"] = float(any(f.rule_id == "HDR-010" for f in result.header_findings))
    from app.forensic.header_anomaly import FREEMAIL_DOMAINS
    v["sender_domain_is_freemail"] = float(bool(parsed.sender_domain and parsed.sender_domain in FREEMAIL_DOMAINS))
    v["multiple_unrelated_domains"] = float(any(f.rule_id == "HDR-011" for f in result.header_findings))

    # --- domain features ---
    domains = result.domain_findings
    v["domain_count_analyzed"] = float(len(domains))
    v["any_domain_punycode"] = float(any(d.is_punycode for d in domains))
    v["any_domain_suspicious_tld"] = float(any(d.suspicious_tld for d in domains))
    v["any_domain_excessive_hyphenation"] = float(any(d.excessive_hyphenation for d in domains))
    v["max_domain_lookalike_similarity"] = max((d.similarity_score for d in domains), default=0.0)
    v["avg_domain_risk_score"] = (sum(d.risk_score for d in domains) / len(domains)) if domains else 0.0
    v["max_domain_risk_score"] = max((d.risk_score for d in domains), default=0.0)

    # --- URL features ---
    urls = result.url_findings
    v["url_count"] = float(len(urls))
    v["any_url_ip_based"] = float(any(u.is_ip_based for u in urls))
    v["any_url_shortened"] = float(any(u.is_shortened for u in urls))
    v["any_url_punycode"] = float(any(u.is_punycode for u in urls))
    v["any_url_suspicious_tld"] = float(any(u.has_suspicious_tld for u in urls))
    v["any_url_anchor_mismatch"] = float(any(u.anchor_text_mismatch for u in urls))
    v["any_url_suspicious_query"] = float(any(u.suspicious_query_params for u in urls))
    v["avg_url_risk_score"] = (sum(u.risk_score for u in urls) / len(urls)) if urls else 0.0
    v["max_url_risk_score"] = max((u.risk_score for u in urls), default=0.0)

    # --- text / social-engineering ---
    ind_types = {i.indicator_type for i in result.social_engineering_indicators}
    for key, itype in [
        ("urgency_present", "urgency"),
        ("fear_threat_present", "fear_threat"),
        ("credential_request_present", "credential_request"),
        ("payment_request_present", "payment_request"),
        ("account_verification_present", "account_verification"),
        ("password_reset_pressure_present", "password_reset_pressure"),
        ("executive_impersonation_present", "executive_impersonation"),
        ("invoice_payment_diversion_present", "invoice_payment_diversion"),
        ("suspicious_cta_present", "suspicious_call_to_action"),
    ]:
        v[key] = float(itype in ind_types)
    v["social_engineering_indicator_count"] = float(len(result.social_engineering_indicators))
    v["social_engineering_max_confidence"] = max((i.confidence for i in result.social_engineering_indicators), default=0.0)

    # --- infrastructure ---
    v["any_hop_ip_private"] = float(any(ip.is_private for ip in result.ip_findings if ip.source == "received_hop"))
    v["ip_address_count"] = float(len(result.ip_findings))

    return FeatureVector(version=FEATURE_VERSION, values=v)


def feature_text_blob(result: ForensicAnalysisResult) -> str:
    """Text used by the TF-IDF text model - subject + visible text body only
    (never attachment binary content, never raw headers)."""
    parsed = result.parsed_email
    import re
    html_stripped = re.sub(r"<[^>]+>", " ", parsed.html_body or "")
    return " ".join(filter(None, [parsed.subject or "", parsed.text_body or "", html_stripped]))
