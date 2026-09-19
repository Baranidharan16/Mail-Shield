"""
Deterministic, Explainable Risk-Scoring Engine.

Calculates final severity from complete forensic evidence:
  - Content / Threat Indicators (Threat, Blackmail, Phishing, Credential harvesting, Impersonation, Urgency, Attachments)
  - Email Authentication (SPF, DKIM, DMARC, Sender/Reply-To alignment)
  - Infrastructure / Forensics (Source IP, Domain anomalies, Header anomalies)
  - Combination Bonuses (Threat+Phishing, Phishing+URL, All Auth Fails, Threat+Mismatch, Multiple High-Risk)

Threshold Bands (Configurable):
  0  - 24 : LOW
  25 - 49 : MEDIUM
  50 - 74 : HIGH
  75+     : CRITICAL
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Any

from app.forensic.auth_analyzer import AuthenticationAnalysis
from app.forensic.header_anomaly import Finding as HeaderFinding
from app.forensic.domain_analyzer import DomainFinding
from app.forensic.url_analyzer import URLFinding
from app.forensic.social_engineering import ContentIndicator
from app.forensic.received_parser import ReceivedHop


DEFAULT_BANDS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


def _load_config() -> dict:
    path = os.path.join(os.path.dirname(__file__), "scoring_weights.json")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {
        "classification_bands": {
            "LOW": [0, 24],
            "MEDIUM": [25, 49],
            "HIGH": [50, 74],
            "CRITICAL": [75, 100],
        }
    }


@dataclass
class EvidenceItem:
    name: str
    points: int
    category: str  # CONTENT, AUTHENTICATION, INFRASTRUCTURE, COMBINATION
    detail: str


@dataclass
class DimensionScore:
    name: str
    score: float  # 0-100
    signals: List[str] = field(default_factory=list)


@dataclass
class ThreatScoreResult:
    overall_score: float
    classification: str
    confidence: float
    dimensions: Dict[str, DimensionScore]
    weights_used: Dict[str, float]
    explanation: Dict[str, Any]


def calculate_threat_score(
    *,
    auth: AuthenticationAnalysis,
    header_findings: List[HeaderFinding],
    domain_findings: List[DomainFinding],
    url_findings: List[URLFinding],
    social_engineering_indicators: List[ContentIndicator],
    received_hops: List[ReceivedHop],
    attachments: List[dict] | None = None,
) -> ThreatScoreResult:
    config = _load_config()
    raw_bands = config.get("classification_bands", DEFAULT_BANDS)

    evidence_items: List[EvidenceItem] = []
    indicator_types = {i.indicator_type.lower() for i in social_engineering_indicators}

    # =========================================================================
    # 1. CONTENT / THREAT INDICATORS
    # =========================================================================
    has_explicit_threat = "explicit_threat" in indicator_types
    if has_explicit_threat:
        evidence_items.append(EvidenceItem(
            name="Explicit threat language",
            points=35,
            category="CONTENT",
            detail="Direct threat of violence, physical harm, or severe personal danger",
        ))

    has_blackmail = "blackmail_extortion" in indicator_types
    if has_blackmail:
        evidence_items.append(EvidenceItem(
            name="Blackmail / extortion demand",
            points=30,
            category="CONTENT",
            detail="Extortion, ransomware, or cryptocurrency demand under threat of compromise",
        ))

    has_harassment = "harassment_intimidation" in indicator_types
    if has_harassment:
        evidence_items.append(EvidenceItem(
            name="Harassment / intimidation",
            points=25,
            category="CONTENT",
            detail="Doxxing, coercive intimidation, or public reputation threat",
        ))

    has_phishing = "phishing_social_engineering" in indicator_types or "account_verification" in indicator_types
    if has_phishing:
        evidence_items.append(EvidenceItem(
            name="Phishing / social engineering",
            points=25,
            category="CONTENT",
            detail="Pretext of account suspension, security alert, or urgent verification",
        ))

    has_credential_harvesting = "credential_request" in indicator_types or "credential_harvesting" in indicator_types
    if has_credential_harvesting:
        evidence_items.append(EvidenceItem(
            name="Credential harvesting attempt",
            points=25,
            category="CONTENT",
            detail="Direct request to submit passwords, login PINs, or security tokens",
        ))

    # URL findings check
    suspicious_urls = [u for u in url_findings if u.risk_score > 30 or u.is_ip_based or u.is_shortened or u.has_suspicious_tld or u.anchor_text_mismatch]
    has_suspicious_url = len(suspicious_urls) > 0
    if has_suspicious_url:
        evidence_items.append(EvidenceItem(
            name="Malicious / suspicious URL",
            points=20,
            category="CONTENT",
            detail=f"{len(suspicious_urls)} suspicious URL(s) detected with deceptive traits",
        ))

    has_impersonation = "executive_impersonation" in indicator_types
    if has_impersonation:
        evidence_items.append(EvidenceItem(
            name="Executive / identity impersonation",
            points=20,
            category="CONTENT",
            detail="Conversational framing and authority impersonation characteristic of BEC",
        ))

    has_urgency = "urgency" in indicator_types
    if has_urgency:
        evidence_items.append(EvidenceItem(
            name="Urgent deadline / coercion",
            points=15,
            category="CONTENT",
            detail="High time-pressure language intended to bypass scrutiny",
        ))

    # Attachment checks (critical: executables / double extensions; high: macro, html, archives)
    critical_att, risky_att = [], []
    if attachments:
        import re as _re
        for att in attachments:
            fname = (att.get("filename") or "").lower()
            if _re.search(r"\.(exe|scr|vbs|js|jar|bat|cmd|ps1|msi|lnk|hta|com|pif|wsf)$", fname) or \
               _re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$", fname):
                critical_att.append(fname)
            elif _re.search(r"\.(docm|xlsm|pptm|html?|svg|iso|img|zip|rar|7z)$", fname):
                risky_att.append(fname)
    has_suspicious_attachment = bool(critical_att or risky_att)
    if critical_att:
        evidence_items.append(EvidenceItem(
            name="Executable / disguised attachment",
            points=40,
            category="CONTENT",
            detail=f"Executable or double-extension attachment: {', '.join(critical_att[:3])}",
        ))
    elif risky_att:
        evidence_items.append(EvidenceItem(
            name="Suspicious attachment",
            points=20,
            category="CONTENT",
            detail=f"Macro-enabled, HTML or archive attachment: {', '.join(risky_att[:3])}",
        ))

    has_payment = "payment_fraud" in indicator_types or "invoice_payment_diversion" in indicator_types
    if has_payment:
        evidence_items.append(EvidenceItem(
            name="Payment / invoice pressure",
            points=20,
            category="CONTENT",
            detail="Request to pay, wire funds or change beneficiary bank details",
        ))

    has_pw_reset = "password_reset_pressure" in indicator_types
    if has_pw_reset:
        evidence_items.append(EvidenceItem(
            name="Password-reset / mailbox pretext",
            points=20,
            category="CONTENT",
            detail="Password expiry or mailbox-quota pretext used to harvest credentials",
        ))

    has_spam = "spam_bulk" in indicator_types
    if has_spam and not (has_phishing or has_explicit_threat or has_blackmail):
        evidence_items.append(EvidenceItem(
            name="Spam / bulk indicators",
            points=10,
            category="CONTENT",
            detail="Promotional or mass unsolicited marketing patterns",
        ))

    # =========================================================================
    # 2. EMAIL AUTHENTICATION
    # =========================================================================
    spf_fail = auth.spf.result in ("FAIL", "SOFTFAIL", "PERMERROR")
    if spf_fail:
        evidence_items.append(EvidenceItem(
            name="SPF FAIL",
            points=10,
            category="AUTHENTICATION",
            detail=f"SPF record failed ({auth.spf.result}) for sending host",
        ))

    dkim_fail = auth.dkim.result == "FAIL" or (auth.dkim_domain_aligned is False)
    if dkim_fail:
        evidence_items.append(EvidenceItem(
            name="DKIM FAIL / misaligned",
            points=10,
            category="AUTHENTICATION",
            detail="Cryptographic signature invalid or signing domain not aligned",
        ))

    dmarc_fail = auth.dmarc.result == "FAIL" or (auth.dmarc_alignment_pass is False and auth.dmarc.result not in ("PASS", None))
    if dmarc_fail:
        evidence_items.append(EvidenceItem(
            name="DMARC FAIL",
            points=10,
            category="AUTHENTICATION",
            detail="DMARC policy evaluation failed",
        ))

    identity_mismatch = (auth.from_reply_to_aligned is False) or (auth.from_return_path_aligned is False)
    if identity_mismatch:
        evidence_items.append(EvidenceItem(
            name="Sender / Reply-To mismatch",
            points=10,
            category="AUTHENTICATION",
            detail="From address does not align with Reply-To or Return-Path",
        ))

    # =========================================================================
    # 3. INFRASTRUCTURE / FORENSICS
    # =========================================================================
    import ipaddress
    has_suspicious_ip = False
    for h in received_hops:
        if h.ip_address:
            try:
                if ipaddress.ip_address(h.ip_address).is_private:
                    has_suspicious_ip = True
                    break
            except Exception:
                pass
    if has_suspicious_ip:
        evidence_items.append(EvidenceItem(
            name="Suspicious source IP",
            points=10,
            category="INFRASTRUCTURE",
            detail="Private or unroutable IP address in external relay hop",
        ))

    suspicious_domains = [d for d in domain_findings if d.risk_score > 30 or d.lookalike_of or d.suspicious_tld or d.is_punycode]
    has_domain_anomaly = len(suspicious_domains) > 0
    if has_domain_anomaly:
        evidence_items.append(EvidenceItem(
            name="Domain anomaly / lookalike",
            points=10,
            category="INFRASTRUCTURE",
            detail="Lookalike domain, suspicious TLD, or punycode domain detected",
        ))

    has_header_anomaly = len([f for f in header_findings if f.severity in ("HIGH", "CRITICAL", "MEDIUM")]) > 0
    if has_header_anomaly:
        evidence_items.append(EvidenceItem(
            name="Header anomaly",
            points=10,
            category="INFRASTRUCTURE",
            detail="Malformed, missing, or spoofed email headers detected",
        ))

    if len(evidence_items) >= 3:
        evidence_items.append(EvidenceItem(
            name="Multiple suspicious indicators",
            points=10,
            category="INFRASTRUCTURE",
            detail=f"{len(evidence_items)} distinct suspicious forensic signals present",
        ))

    # =========================================================================
    # 4. COMBINATION BONUSES
    # =========================================================================
    combination_bonuses: List[EvidenceItem] = []

    # Threat + Phishing
    if (has_explicit_threat or has_blackmail) and (has_phishing or has_credential_harvesting):
        combination_bonuses.append(EvidenceItem(
            name="Threat + Phishing",
            points=15,
            category="COMBINATION",
            detail="Compound threat: coercive threat coupled with credential harvesting/phishing",
        ))

    # Phishing + Suspicious URL
    if (has_phishing or has_credential_harvesting) and has_suspicious_url:
        combination_bonuses.append(EvidenceItem(
            name="Phishing + Suspicious URL",
            points=10,
            category="COMBINATION",
            detail="Social engineering pretext paired with deceptive/shortened URL link",
        ))

    # SPF + DKIM + DMARC all fail
    if spf_fail and dkim_fail and dmarc_fail:
        combination_bonuses.append(EvidenceItem(
            name="SPF + DKIM + DMARC all fail",
            points=15,
            category="COMBINATION",
            detail="Complete authentication breakdown — sender domain totally unverified",
        ))

    # BEC: payment request + mismatched reply identity or executive impersonation
    if has_payment and (identity_mismatch or has_impersonation):
        combination_bonuses.append(EvidenceItem(
            name="Payment request + identity deception (BEC)",
            points=15,
            category="COMBINATION",
            detail="Payment/bank-change request combined with Reply-To mismatch or executive impersonation",
        ))

    # Credential request + brand look-alike domain
    if (has_credential_harvesting or has_pw_reset or has_phishing) and any(d.lookalike_of for d in domain_findings):
        combination_bonuses.append(EvidenceItem(
            name="Credential lure + look-alike domain",
            points=15,
            category="COMBINATION",
            detail="Credential/verification pretext sent from or linking to a brand look-alike domain",
        ))

    # Threat + Identity Mismatch
    if (has_explicit_threat or has_blackmail) and identity_mismatch:
        combination_bonuses.append(EvidenceItem(
            name="Threat + Identity mismatch",
            points=10,
            category="COMBINATION",
            detail="Threatening payload delivered via spoofed sender identity",
        ))

    # Multiple high-risk indicators
    high_risk_items = [e for e in evidence_items if e.points >= 20]
    if len(high_risk_items) >= 3:
        combination_bonuses.append(EvidenceItem(
            name="Multiple high-risk indicators",
            points=10,
            category="COMBINATION",
            detail="3 or more severe threat vectors corroborated across evidence",
        ))

    # =========================================================================
    # 5. FINAL SCORE & CLASSIFICATION
    # =========================================================================
    total_raw_score = sum(e.points for e in evidence_items) + sum(c.points for c in combination_bonuses)
    final_score = round(min(100.0, max(0.0, float(total_raw_score))), 1)

    # Determine classification band
    classification = "LOW"
    for band_name, band_range in raw_bands.items():
        lo, hi = band_range[0], band_range[1]
        if lo <= final_score <= hi:
            classification = band_name
            break
    if final_score >= 75:
        classification = "CRITICAL"
    elif final_score >= 50:
        classification = "HIGH"
    elif final_score >= 25:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    # Confidence calculation: grounded in evidence volume & clarity
    evidence_breadth = 0
    evidence_breadth += 1 if auth.source == "OBSERVED" else 0
    evidence_breadth += 1 if received_hops else 0
    evidence_breadth += 1 if url_findings else 0
    evidence_breadth += 1 if domain_findings else 0
    evidence_breadth += 1 if social_engineering_indicators else 0

    if final_score >= 75:
        confidence = round(min(0.99, 0.88 + 0.02 * evidence_breadth), 2)
    elif final_score >= 50:
        confidence = round(min(0.95, 0.82 + 0.02 * evidence_breadth), 2)
    elif final_score >= 25:
        confidence = round(min(0.90, 0.75 + 0.02 * evidence_breadth), 2)
    else:
        confidence = round(min(0.95, 0.70 + 0.04 * evidence_breadth), 2)

    # Build dimension scores for visualization
    content_score = min(100.0, sum(e.points for e in evidence_items if e.category == "CONTENT") * 1.5)
    auth_score = min(100.0, sum(e.points for e in evidence_items if e.category == "AUTHENTICATION") * 2.5)
    infra_score = min(100.0, sum(e.points for e in evidence_items if e.category == "INFRASTRUCTURE") * 2.5)
    url_score = 80.0 if has_suspicious_url else (20.0 if url_findings else 0.0)
    domain_score = 80.0 if has_domain_anomaly else (15.0 if domain_findings else 0.0)

    dims = {
        "authentication": DimensionScore("authentication", round(auth_score, 1), [e.detail for e in evidence_items if e.category == "AUTHENTICATION"]),
        "header": DimensionScore("header", 80.0 if has_header_anomaly else 0.0, ["Header anomalies detected" if has_header_anomaly else "No header anomalies"]),
        "sender_identity": DimensionScore("sender_identity", 80.0 if identity_mismatch else 0.0, ["Sender/Reply-To mismatch" if identity_mismatch else "Sender headers aligned"]),
        "domain": DimensionScore("domain", round(domain_score, 1), [d.domain for d in suspicious_domains]),
        "url": DimensionScore("url", round(url_score, 1), [u.url for u in suspicious_urls]),
        "social_engineering": DimensionScore("social_engineering", round(content_score, 1), [i.explanation for i in social_engineering_indicators]),
        "infrastructure": DimensionScore("infrastructure", round(infra_score, 1), [f"{len(received_hops)} relay hops analyzed"]),
    }

    # Human-readable severity reasons
    severity_reasons: List[str] = [
        f"{e.name} (+{e.points} pts): {e.detail}" for e in evidence_items
    ] + [
        f"Combination: {c.name} (+{c.points} pts): {c.detail}" for c in combination_bonuses
    ]

    total_raw = sum(dims[name].score for name in dims)
    if total_raw > 0:
        dim_breakdown = {}
        accum = 0.0
        names = list(dims.keys())
        for i, name in enumerate(names):
            if i == len(names) - 1:
                contrib = round(final_score - accum, 2)
            else:
                contrib = round((dims[name].score / total_raw) * final_score, 2)
                accum += contrib
            dim_breakdown[name] = {
                "score": dims[name].score,
                "weight": round(dims[name].score / total_raw, 4),
                "weighted_contribution": contrib,
                "signals": dims[name].signals,
            }
    else:
        dim_breakdown = {
            name: {
                "score": dims[name].score,
                "weight": 0.0,
                "weighted_contribution": 0.0,
                "signals": dims[name].signals,
            }
            for name in dims
        }

    explanation = {
        "formula": "overall_score = min(100, sum(evidence_points) + sum(combination_bonuses))",
        "total_score": final_score,
        "classification": classification,
        "evidence_items": [
            {"name": e.name, "points": e.points, "category": e.category, "detail": e.detail}
            for e in evidence_items
        ],
        "combination_bonuses": [
            {"name": c.name, "points": c.points, "detail": c.detail}
            for c in combination_bonuses
        ],
        "severity_reasons": severity_reasons,
        "dimension_breakdown": dim_breakdown,
    }

    return ThreatScoreResult(
        overall_score=final_score,
        classification=classification,
        confidence=confidence,
        dimensions=dims,
        weights_used={"evidence_aggregation": 1.0},
        explanation=explanation,
    )
