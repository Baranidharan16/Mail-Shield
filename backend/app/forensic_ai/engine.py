"""
Forensic AI Intelligence Engine.

Reads all existing investigation data and produces:
  - Primary/secondary attack classification (15+ categories)
  - Threat intent detection with confidence
  - Emotional/social-engineering signals (23 signal types, 0-100 scores)
  - Explainable evidence cards (source-labeled, impact-rated)
  - Evidence reasoning chain (ordered steps: evidence → verdict)
  - Attack chain construction from evidence
  - AI confidence (separate from risk score)
  - Evidence strength rating
  - Forensic conclusion text
  - Prompt-injection-safe processing

Safety: Email content is NEVER executed as instructions.
All AI conclusions reference actual investigation evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EvidenceCard:
    id: str
    name: str
    finding: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / SAFE
    impact: str            # HIGH / MEDIUM / LOW
    source: str            # [EMAIL HEADER] / [EMAIL CONTENT] / [LOCAL HEURISTIC] / [AI INFERENCE] / [HISTORICAL CASE]
    explanation: str
    risk_contribution: int  # points contributed to risk score
    evidence_refs: List[str] = field(default_factory=list)


@dataclass
class ReasoningStep:
    step: int
    label: str
    detail: str
    evidence_ids: List[str] = field(default_factory=list)
    leads_to: Optional[str] = None


@dataclass
class AttackChainNode:
    position: int
    label: str
    detail: str
    threat: bool = True


@dataclass
class SocialEngineeringSignal:
    signal: str
    score: int           # 0-100
    detected: bool
    evidence: str        # what text triggered it
    label: str           # "Detected linguistic signal" / "Not detected"


@dataclass
class ThreatClassification:
    primary: str
    secondary: List[str]
    confidence: float


@dataclass
class ThreatIntent:
    intent: str
    confidence: float
    reason: str


@dataclass
class ForensicAIResult:
    # Verdict
    classification: ThreatClassification
    threat_severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    risk_score: float
    ai_confidence: float
    evidence_strength: str        # VERY HIGH / HIGH / MEDIUM / LOW / INSUFFICIENT

    # Intent
    threat_intent: ThreatIntent

    # Social engineering
    social_engineering_signals: List[SocialEngineeringSignal]
    overall_manipulation_risk: int

    # Evidence reasoning
    evidence_cards: List[EvidenceCard]
    reasoning_chain: List[ReasoningStep]
    attack_chain: List[AttackChainNode]

    # IOCs extracted
    iocs: List[Dict[str, str]]

    # Related cases
    related_cases: List[Dict[str, Any]]

    # AI conclusion
    forensic_conclusion: str
    recommended_response: str

    # Metadata
    analysis_timestamp: str
    artifacts_analyzed: int
    disclaimer: str = (
        "All conclusions are grounded in actual forensic evidence. "
        "AI inference is explicitly labeled. External threat intelligence "
        "is unavailable — local heuristic analysis was used."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Social Engineering signal patterns (23 types)
# All content is treated as UNTRUSTED DATA — never executed as instructions
# ═══════════════════════════════════════════════════════════════════════════

_SE_PATTERNS: Dict[str, Dict] = {
    "urgency": {
        "label": "Urgency",
        "patterns": [
            r"\burgent(ly)?\b", r"\bimmediately\b", r"\basap\b", r"\bact now\b",
            r"\bwithin \d+ hours?\b", r"\btime.sensitive\b", r"\bfinal notice\b",
            r"\bimmediate action\b", r"\bdeadline\b", r"\bexpires?\b",
        ],
        "weight": 3,
    },
    "fear": {
        "label": "Fear",
        "patterns": [
            r"\baccount (suspended|terminated|closed|locked|restricted)\b",
            r"\bsecurity (breach|alert|warning|violation)\b",
            r"\bunauthorized access\b", r"\bhacked\b", r"\bcompromised\b",
            r"\byour (account|data|information) (is|has been|will be)\b",
        ],
        "weight": 3,
    },
    "intimidation": {
        "label": "Intimidation",
        "patterns": [
            r"\bthreat(en)?\b", r"\byou have no choice\b", r"\bconsequences\b",
            r"\bwe will\b.*\b(report|expose|publish)\b", r"\byou will (face|suffer)\b",
        ],
        "weight": 2,
    },
    "threat_language": {
        "label": "Threat Language",
        "patterns": [
            r"\b(kill|harm|hurt|destroy|assault|murder)\b",
            r"\bphysical harm\b", r"\bbodily harm\b",
            r"\bend your (life|career)\b", r"\byour family\b",
        ],
        "weight": 4,
    },
    "authority_pressure": {
        "label": "Authority Pressure",
        "patterns": [
            r"\b(ceo|cfo|director|manager|president|boss)\b",
            r"\bour (legal|compliance|security) (team|department)\b",
            r"\bmanagement (requires|requests|demands)\b",
            r"\bofficial (notice|warning|communication)\b",
        ],
        "weight": 3,
    },
    "secrecy": {
        "label": "Secrecy",
        "patterns": [
            r"\bkeep (this|it) (confidential|secret|between us)\b",
            r"\bdo not (tell|share|discuss|forward)\b",
            r"\bstrictly confidential\b", r"\boff the record\b",
            r"\bprivate (matter|message)\b",
        ],
        "weight": 3,
    },
    "curiosity_baiting": {
        "label": "Curiosity Baiting",
        "patterns": [
            r"\byou won\b", r"\bclaim (your |)prize\b", r"\bsee what (happened|you won)\b",
            r"\bcheck (the |)attachment\b", r"\bview (the |)document\b",
            r"\bcuriosity\b", r"\bexclusive (offer|access)\b",
        ],
        "weight": 2,
    },
    "reward_greed": {
        "label": "Reward / Greed",
        "patterns": [
            r"\b(100%|completely) free\b", r"\b\$[\d,]+ (prize|reward|cash|bonus)\b",
            r"\blottery (winner|selected)\b", r"\bcongratulations you (have|'ve) won\b",
            r"\binheritance\b", r"\bmillion(s)? dollar\b",
        ],
        "weight": 2,
    },
    "panic": {
        "label": "Panic",
        "patterns": [
            r"\bact (before|within)\b", r"\blast (chance|warning|notice)\b",
            r"\bdont (wait|delay|ignore)\b", r"\bdo not ignore\b",
            r"\bfinal (warning|notice|opportunity)\b",
        ],
        "weight": 2,
    },
    "trust_exploitation": {
        "label": "Trust Exploitation",
        "patterns": [
            r"\bwe (care|value|protect) (you|your)\b",
            r"\byour (trusted|official|verified) (partner|provider|bank|service)\b",
            r"\byour (account|privacy|security) (matters|is important)\b",
        ],
        "weight": 2,
    },
    "sympathy_manipulation": {
        "label": "Sympathy / Emotional Manipulation",
        "patterns": [
            r"\bi (need|require) your (help|assistance|support)\b",
            r"\bstranded\b", r"\btrapped\b", r"\bin (desperate|urgent) need\b",
            r"\bmy (life|family|health)\b.*\b(danger|risk|trouble)\b",
        ],
        "weight": 2,
    },
    "financial_pressure": {
        "label": "Financial Pressure",
        "patterns": [
            r"\bpay(ment)? (immediately|now|urgently|overdue)\b",
            r"\boverdue (invoice|payment|balance)\b",
            r"\byou owe\b", r"\bpay (or|before)\b", r"\bbalance due\b",
            r"\bfunds? transfer\b",
        ],
        "weight": 3,
    },
    "account_suspension_fear": {
        "label": "Account Suspension Fear",
        "patterns": [
            r"\baccount (will be|has been|is) (suspended|deleted|locked|terminated)\b",
            r"\b(24|48|72) hours? (to|or your account)\b",
            r"\bverify (your account|your identity|now) (to avoid|or)\b",
        ],
        "weight": 3,
    },
    "legal_threat": {
        "label": "Legal Consequence Threat",
        "patterns": [
            r"\blegal (action|proceedings|consequences)\b",
            r"\b(law enforcement|police|authorities) (will|have been)\b",
            r"\bcriminal (charges|complaint|action)\b",
            r"\bprosecute\b", r"\blawsuit\b",
        ],
        "weight": 3,
    },
    "deadline_pressure": {
        "label": "Deadline Pressure",
        "patterns": [
            r"\bdeadline (is|of)\b", r"\bexpires? (on|at|in)\b",
            r"\brespond (by|before|within)\b",
            r"\b(today|tonight|tomorrow) (is|by)\b.*\bdeadline\b",
        ],
        "weight": 2,
    },
    "impersonation": {
        "label": "Impersonation",
        "patterns": [
            r"\b(microsoft|google|apple|amazon|paypal|netflix|facebook|instagram|bank of)\b",
            r"\bofficial (team|support|security|notification)\b",
            r"\bthis is (your|a) (bank|service|provider) (notice|message)\b",
        ],
        "weight": 3,
    },
    "secret_action_request": {
        "label": "Request for Secret Action",
        "patterns": [
            r"\bdon'?t (tell|mention|inform|let) (anyone|your|the)\b",
            r"\bjust between (us|you and me)\b",
            r"\bno one (else|other) should know\b",
        ],
        "weight": 3,
    },
    "credential_request": {
        "label": "Credential Request",
        "patterns": [
            r"\b(enter|provide|submit|confirm) (your )?(password|username|login|credentials)\b",
            r"\b(verify|re-?enter) (your )?(password|pin|passcode|token)\b",
            r"\bsign (in|into) (to verify|to confirm)\b",
        ],
        "weight": 4,
    },
    "otp_request": {
        "label": "OTP / 2FA Request",
        "patterns": [
            r"\b(one.time|otp|verification) (code|password|pin)\b",
            r"\benter (the|your) (code|otp|verification code)\b",
            r"\btwo.factor\b", r"\b2fa\b",
        ],
        "weight": 4,
    },
    "payment_request": {
        "label": "Payment Request",
        "patterns": [
            r"\b(make|send|complete) (a |the )?payment\b",
            r"\bpay (now|immediately|this invoice)\b",
            r"\bremittance\b", r"\btransfer (funds|money|payment)\b",
        ],
        "weight": 3,
    },
    "gift_card_request": {
        "label": "Gift Card Request",
        "patterns": [
            r"\bgift card(s)?\b",
            r"\b(apple|google play|amazon|steam|itunes) (gift )?(card|voucher)\b",
            r"\bpurchase (gift card|voucher|prepaid card)\b",
        ],
        "weight": 4,
    },
    "wire_transfer": {
        "label": "Wire Transfer Request",
        "patterns": [
            r"\bwire transfer\b", r"\bwire (the |)funds\b",
            r"\bnew (bank|payment) (account|details|information)\b",
            r"\bswift( code)?\b", r"\biban\b", r"\bremit\b",
        ],
        "weight": 4,
    },
    "sensitive_info_request": {
        "label": "Sensitive Information Request",
        "patterns": [
            r"\b(send|provide|share) (your )?(ssn|social security|passport|id number|date of birth)\b",
            r"\bpersonal (information|data|details) (required|needed)\b",
            r"\bidentity (verification|confirmation)\b",
        ],
        "weight": 3,
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Attack classification taxonomy
# ═══════════════════════════════════════════════════════════════════════════

_CLASSIFICATION_RULES = [
    # (classification, required_conditions_fn, secondary_conditions_fn, priority)
    ("Credential Phishing",
     lambda d: d["has_credential_request"] and d["has_phishing_pretext"],
     lambda d: ["Social Engineering", "Brand Impersonation"] if d["has_impersonation"] else ["Social Engineering"],
     10),
    ("Spear Phishing",
     lambda d: d["has_exec_impersonation"] and d["has_phishing_pretext"] and not d["has_payment_request"],
     lambda d: ["Social Engineering", "Impersonation"],
     9),
    ("Business Email Compromise",
     lambda d: d["has_exec_impersonation"] and (d["has_payment_request"] or d["has_wire_transfer"] or d["has_gift_card"]),
     lambda d: ["CEO Fraud", "Payment Fraud", "Social Engineering"],
     10),
    ("CEO Fraud",
     lambda d: d["has_exec_impersonation"] and d["has_secrecy"] and not d["has_explicit_threat"],
     lambda d: ["Business Email Compromise", "Social Engineering"],
     8),
    ("Invoice Fraud",
     lambda d: d["has_payment_request"] and d["has_financial_pressure"] and not d["has_exec_impersonation"],
     lambda d: ["Payment Redirection", "Financial Fraud"],
     7),
    ("Payment Redirection",
     lambda d: d["has_wire_transfer"] and d["has_financial_pressure"],
     lambda d: ["Invoice Fraud", "Financial Fraud"],
     7),
    ("Malicious Attachment",
     lambda d: d["has_suspicious_attachment"],
     lambda d: ["Malware Delivery"] if d["has_suspicious_url"] else [],
     8),
    ("Malware Delivery",
     lambda d: d["has_suspicious_url"] and d["has_suspicious_attachment"],
     lambda d: ["Malicious Attachment"],
     9),
    ("Account Takeover",
     lambda d: d["has_credential_request"] and d["has_otp_request"],
     lambda d: ["Credential Phishing", "Social Engineering"],
     9),
    ("Social Engineering",
     lambda d: d["overall_se_score"] >= 40 and not d["has_credential_request"] and not d["has_payment_request"],
     lambda d: ["Impersonation"] if d["has_impersonation"] else [],
     5),
    ("Impersonation",
     lambda d: d["has_impersonation"] and d["auth_failures"] >= 2,
     lambda d: ["Social Engineering"],
     6),
    ("Extortion",
     lambda d: d["has_explicit_threat"] and d["has_blackmail"],
     lambda d: ["Threatening Email", "Financial Fraud"],
     10),
    ("Threatening Email",
     lambda d: d["has_explicit_threat"] and not d["has_blackmail"],
     lambda d: [],
     8),
    ("Spam",
     lambda d: d["has_spam"] and d["overall_se_score"] < 30 and d["risk_score"] < 25,
     lambda d: [],
     3),
    ("Scam",
     lambda d: d["has_reward"] and not d["has_credential_request"],
     lambda d: ["Spam"],
     4),
    ("Data Exfiltration Attempt",
     lambda d: d["has_sensitive_info_request"] and d["has_phishing_pretext"],
     lambda d: ["Credential Phishing"],
     7),
    ("Phishing",
     lambda d: d["has_phishing_pretext"] or d["has_suspicious_url"],
     lambda d: ["Social Engineering"],
     4),
]

_INTENT_RULES = [
    ("Credential Theft", lambda d: d["has_credential_request"] or d["has_otp_request"],
     lambda d: "The email requests account credentials or one-time codes, directing the user to submit login information to a potentially malicious destination."),
    ("Financial Theft", lambda d: d["has_payment_request"] or d["has_wire_transfer"] or d["has_gift_card"],
     lambda d: "The email attempts to redirect financial transactions, initiate unauthorized payments, or extract monetary value via gift cards or wire transfers."),
    ("Malware Delivery", lambda d: d["has_suspicious_attachment"] and d["has_call_to_action"],
     lambda d: "The email instructs the recipient to open an attachment that may contain malicious code, scripts, or macros."),
    ("Identity Impersonation", lambda d: d["has_exec_impersonation"] or d["has_impersonation"],
     lambda d: "The email impersonates a trusted individual or organization to gain the recipient's compliance."),
    ("Account Takeover", lambda d: d["has_credential_request"] and d["has_account_suspension"],
     lambda d: "The email creates urgency around account security to trick the recipient into surrendering authentication credentials."),
    ("Data Collection", lambda d: d["has_sensitive_info_request"],
     lambda d: "The email requests personally identifiable information (PII) or sensitive data from the recipient."),
    ("Payment Redirection", lambda d: d["has_wire_transfer"] and d["has_financial_pressure"],
     lambda d: "The email attempts to redirect legitimate financial transactions to attacker-controlled bank accounts."),
    ("Extortion", lambda d: d["has_blackmail"] or d["has_explicit_threat"],
     lambda d: "The email demands payment or compliance under threat of harm, embarrassment, or exposure of sensitive material."),
    ("Threat / Intimidation", lambda d: d["has_explicit_threat"] and not d["has_blackmail"],
     lambda d: "The email contains explicit threats of physical harm or severe personal danger."),
    ("Social Engineering", lambda d: d["overall_se_score"] >= 30,
     lambda d: "The email uses psychological manipulation techniques to influence the recipient's behavior."),
    ("Spam Advertising", lambda d: d["has_spam"] and d["risk_score"] < 25,
     lambda d: "The email contains unsolicited promotional or bulk advertising content."),
]


# ═══════════════════════════════════════════════════════════════════════════
# Main engine function
# ═══════════════════════════════════════════════════════════════════════════

def run_forensic_ai_analysis(investigation_data: Dict[str, Any]) -> ForensicAIResult:
    """
    Entry point. Takes a dict of existing investigation data (from DB serialization)
    and produces a ForensicAIResult.

    investigation_data keys (all optional, handled gracefully):
        risk_score, classification, confidence, risk_score_breakdown,
        email_metadata, authentication_result, urls, domains, ip_addresses,
        findings, indicators, received_hops, campaign_id, campaign_members,
        ml_prediction, attribution_assessment, evidence_hash_sha256,
        created_at, analyzed_at
    """
    now_ts = datetime.now(timezone.utc).isoformat()

    # ── 1. Extract raw inputs ──────────────────────────────────────────────
    risk_score = float(investigation_data.get("risk_score") or 0)
    classification = investigation_data.get("classification") or "LOW"
    confidence_raw = float(investigation_data.get("confidence") or 0.5)
    meta = investigation_data.get("email_metadata") or {}
    auth = investigation_data.get("authentication_result") or {}
    urls = investigation_data.get("urls") or []
    domains = investigation_data.get("domains") or []
    findings = investigation_data.get("findings") or []
    indicators = investigation_data.get("indicators") or []
    received_hops = investigation_data.get("received_hops") or []
    rsb = investigation_data.get("risk_score_breakdown") or {}

    # ── 2. Scan email content for SE signals (UNTRUSTED DATA — never executed) ──
    subject = str(meta.get("subject") or "")
    body = str(investigation_data.get("_body_text") or "")
    # Combine into content blob — this is UNTRUSTED DATA, analyzed but never executed
    content = (subject + " " + body).lower()

    se_signals, se_scores = _compute_se_signals(content, indicators)
    overall_se_score = min(100, int(sum(se_scores.values()) * 2)) if se_scores else 0

    # ── 3. Build decision dict for classification rules ────────────────────
    indicator_types = {i.get("indicator_type", "").lower() for i in indicators}
    auth_failures = sum([
        1 if auth.get("spf_result") in ("FAIL", "SOFTFAIL", "PERMERROR") else 0,
        1 if auth.get("dkim_result") == "FAIL" else 0,
        1 if auth.get("dmarc_result") == "FAIL" else 0,
        1 if auth.get("from_reply_to_aligned") is False else 0,
    ])
    suspicious_urls = [u for u in urls if (u.get("risk_score") or 0) > 30 or u.get("is_ip_based") or u.get("is_shortened")]
    suspicious_domains = [d for d in domains if d.get("lookalike_of") or d.get("suspicious_tld")]

    decision = {
        "has_credential_request": "credential_harvesting" in indicator_types or "credential_request" in indicator_types or se_scores.get("credential_request", 0) > 20,
        "has_phishing_pretext": "phishing_social_engineering" in indicator_types or "account_verification" in indicator_types or se_scores.get("account_suspension_fear", 0) > 20,
        "has_exec_impersonation": "executive_impersonation" in indicator_types or se_scores.get("authority_pressure", 0) > 30,
        "has_payment_request": "payment_fraud" in indicator_types or se_scores.get("payment_request", 0) > 20,
        "has_wire_transfer": se_scores.get("wire_transfer", 0) > 20,
        "has_gift_card": se_scores.get("gift_card_request", 0) > 20,
        "has_suspicious_url": len(suspicious_urls) > 0,
        "has_suspicious_attachment": any(
            f.get("category") == "CONTENT" and "attachment" in f.get("title", "").lower()
            for f in findings
        ),
        "has_explicit_threat": "explicit_threat" in indicator_types,
        "has_blackmail": "blackmail_extortion" in indicator_types,
        "has_spam": "spam_bulk" in indicator_types,
        "has_reward": se_scores.get("reward_greed", 0) > 15,
        "has_impersonation": len(suspicious_domains) > 0 or se_scores.get("impersonation", 0) > 20,
        "has_secrecy": se_scores.get("secrecy", 0) > 20,
        "has_financial_pressure": se_scores.get("financial_pressure", 0) > 20,
        "has_sensitive_info_request": se_scores.get("sensitive_info_request", 0) > 20,
        "has_call_to_action": "suspicious_call_to_action" in indicator_types or se_scores.get("curiosity_baiting", 0) > 20,
        "has_otp_request": se_scores.get("otp_request", 0) > 20,
        "has_account_suspension": se_scores.get("account_suspension_fear", 0) > 20,
        "overall_se_score": overall_se_score,
        "auth_failures": auth_failures,
        "risk_score": risk_score,
    }

    # ── 4. Classify threat ─────────────────────────────────────────────────
    threat_classification = _classify_threat(decision, risk_score)

    # ── 5. Detect intent ──────────────────────────────────────────────────
    threat_intent = _detect_intent(decision, threat_classification.primary)

    # ── 6. Build evidence cards ────────────────────────────────────────────
    evidence_cards = _build_evidence_cards(
        auth, urls, domains, findings, indicators,
        suspicious_urls, suspicious_domains, auth_failures,
        rsb, meta, received_hops
    )

    # ── 7. Build reasoning chain ───────────────────────────────────────────
    reasoning_chain = _build_reasoning_chain(
        evidence_cards, threat_classification, threat_intent, risk_score
    )

    # ── 8. Build attack chain ─────────────────────────────────────────────
    attack_chain = _build_attack_chain(decision, threat_classification, evidence_cards)

    # ── 9. Extract IOCs ────────────────────────────────────────────────────
    iocs = _extract_iocs(meta, urls, domains, investigation_data.get("ip_addresses") or [], findings)

    # ── 10. Related cases ──────────────────────────────────────────────────
    related_cases = []
    campaign_members = investigation_data.get("campaign_members") or []
    for m in campaign_members:
        related_cases.append({
            "case_id": m.get("case_id", ""),
            "investigation_id": m.get("investigation_id", ""),
            "similarity_score": m.get("similarity_score", 0),
            "relationship": m.get("relationship_label", ""),
            "reasons": m.get("reasons") or [],
        })

    # ── 11. AI confidence & evidence strength ─────────────────────────────
    ai_confidence = _compute_ai_confidence(evidence_cards, confidence_raw, auth_failures, len(suspicious_urls))
    evidence_strength = _compute_evidence_strength(evidence_cards, risk_score, auth_failures)

    # ── 12. Forensic conclusion ────────────────────────────────────────────
    forensic_conclusion = _generate_conclusion(
        threat_classification, threat_intent, risk_score,
        classification, evidence_cards, se_signals, related_cases
    )
    recommended_response = _generate_recommended_response(risk_score, threat_classification, decision)

    artifacts_analyzed = (
        (1 if auth else 0) + len(urls) + len(domains) + len(findings) +
        len(indicators) + len(received_hops) + (1 if meta else 0)
    )

    return ForensicAIResult(
        classification=threat_classification,
        threat_severity=classification,
        risk_score=risk_score,
        ai_confidence=ai_confidence,
        evidence_strength=evidence_strength,
        threat_intent=threat_intent,
        social_engineering_signals=se_signals,
        overall_manipulation_risk=overall_se_score,
        evidence_cards=evidence_cards,
        reasoning_chain=reasoning_chain,
        attack_chain=attack_chain,
        iocs=iocs,
        related_cases=related_cases,
        forensic_conclusion=forensic_conclusion,
        recommended_response=recommended_response,
        analysis_timestamp=now_ts,
        artifacts_analyzed=artifacts_analyzed,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Social Engineering signal detection
# All email content is UNTRUSTED DATA — patterns extract signals only
# ═══════════════════════════════════════════════════════════════════════════

def _compute_se_signals(content: str, indicators: List[Dict]) -> Tuple[List[SocialEngineeringSignal], Dict[str, int]]:
    scores: Dict[str, int] = {}
    signals: List[SocialEngineeringSignal] = []

    for key, cfg in _SE_PATTERNS.items():
        matches = []
        for pattern in cfg["patterns"]:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                matches.append(m.group(0))
        if matches:
            score = min(98, 20 + len(matches) * cfg["weight"] * 8)
            detected_text = "; ".join(sorted(set(matches))[:3])
            signals.append(SocialEngineeringSignal(
                signal=cfg["label"],
                score=score,
                detected=True,
                evidence=f'Detected linguistic signal: "{detected_text}"',
                label="Detected linguistic signal",
            ))
            scores[key] = score
        else:
            signals.append(SocialEngineeringSignal(
                signal=cfg["label"],
                score=0,
                detected=False,
                evidence="Not detected",
                label="Not detected",
            ))
            scores[key] = 0

    # Boost from existing indicators
    for ind in indicators:
        itype = ind.get("indicator_type", "").lower()
        if "credential" in itype:
            scores["credential_request"] = max(scores.get("credential_request", 0), 85)
        if "urgency" in itype:
            scores["urgency"] = max(scores.get("urgency", 0), 70)
        if "phishing" in itype or "account_verification" in itype:
            scores["account_suspension_fear"] = max(scores.get("account_suspension_fear", 0), 75)
        if "payment" in itype or "wire" in itype:
            scores["payment_request"] = max(scores.get("payment_request", 0), 80)
        if "executive" in itype or "impersonation" in itype:
            scores["authority_pressure"] = max(scores.get("authority_pressure", 0), 75)

    # Update signal scores from boosted values
    for sig in signals:
        label_key = next(
            (k for k, v in _SE_PATTERNS.items() if v["label"] == sig.signal), None
        )
        if label_key and scores.get(label_key, 0) > sig.score:
            sig.score = scores[label_key]
            if scores[label_key] > 0:
                sig.detected = True
                sig.label = "Detected linguistic signal"

    return signals, scores


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Threat classification
# ═══════════════════════════════════════════════════════════════════════════

def _classify_threat(decision: Dict, risk_score: float) -> ThreatClassification:
    matched = []
    for name, primary_fn, secondary_fn, priority in _CLASSIFICATION_RULES:
        try:
            if primary_fn(decision):
                sec = secondary_fn(decision)
                matched.append((name, sec, priority))
        except Exception:
            pass

    if not matched:
        if risk_score >= 50:
            return ThreatClassification(primary="Phishing", secondary=["Social Engineering"], confidence=0.6)
        elif risk_score >= 25:
            return ThreatClassification(primary="Suspicious Email", secondary=[], confidence=0.5)
        return ThreatClassification(primary="Benign / Unknown", secondary=[], confidence=0.7)

    matched.sort(key=lambda x: x[2], reverse=True)
    primary_name, secondary, priority = matched[0]
    other_primaries = [m[0] for m in matched[1:] if m[0] != primary_name]
    all_secondary = list(dict.fromkeys(secondary + other_primaries))[:5]
    confidence = min(0.97, 0.65 + priority * 0.03 + (risk_score / 200))
    return ThreatClassification(primary=primary_name, secondary=all_secondary, confidence=round(confidence, 2))


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Intent detection
# ═══════════════════════════════════════════════════════════════════════════

def _detect_intent(decision: Dict, primary_classification: str) -> ThreatIntent:
    for intent_name, cond_fn, reason_fn in _INTENT_RULES:
        try:
            if cond_fn(decision):
                confidence = min(0.97, 0.65 + decision["risk_score"] / 200)
                return ThreatIntent(
                    intent=intent_name,
                    confidence=round(confidence, 2),
                    reason=reason_fn(decision),
                )
        except Exception:
            pass
    return ThreatIntent(
        intent="Unknown",
        confidence=0.4,
        reason="Insufficient evidence to determine clear attack intent. Analyst review recommended.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Evidence cards
# ═══════════════════════════════════════════════════════════════════════════

def _build_evidence_cards(
    auth, urls, domains, findings, indicators,
    suspicious_urls, suspicious_domains, auth_failures,
    rsb, meta, received_hops
) -> List[EvidenceCard]:
    cards: List[EvidenceCard] = []
    card_id = 0

    def next_id():
        nonlocal card_id
        card_id += 1
        return f"ev_{card_id:02d}"

    # SPF
    spf = auth.get("spf_result") or "UNKNOWN"
    spf_fail = spf in ("FAIL", "SOFTFAIL", "PERMERROR")
    cards.append(EvidenceCard(
        id=next_id(), name="SPF", finding=spf, severity="HIGH" if spf_fail else "SAFE",
        impact="HIGH" if spf_fail else "LOW", source="[EMAIL HEADER]",
        explanation=(f"SPF authentication {spf} — the sending server is not authorized by the claimed domain's SPF record. This is a strong indicator of sender spoofing or phishing infrastructure."
                     if spf_fail else f"SPF {spf} — sender server is authorized to send on behalf of the claimed domain."),
        risk_contribution=10 if spf_fail else 0,
        evidence_refs=[auth.get("raw_authentication_results_header") or "Authentication-Results header"],
    ))

    # DKIM
    dkim = auth.get("dkim_result") or "UNKNOWN"
    dkim_aligned = auth.get("dkim_domain_aligned")
    dkim_fail = dkim == "FAIL" or dkim_aligned is False
    cards.append(EvidenceCard(
        id=next_id(), name="DKIM", finding=dkim if not dkim_fail else "FAIL",
        severity="HIGH" if dkim_fail else "SAFE",
        impact="HIGH" if dkim_fail else "LOW", source="[EMAIL HEADER]",
        explanation=(f"DKIM cryptographic signature {'failed' if dkim == 'FAIL' else 'domain misaligned'} — the email cannot be cryptographically verified as originating from the claimed domain. Content may have been tampered with in transit."
                     if dkim_fail else "DKIM signature valid — message authenticated cryptographically."),
        risk_contribution=10 if dkim_fail else 0,
    ))

    # DMARC
    dmarc = auth.get("dmarc_result") or "UNKNOWN"
    dmarc_fail = dmarc == "FAIL" or auth.get("dmarc_alignment_pass") is False
    cards.append(EvidenceCard(
        id=next_id(), name="DMARC", finding=dmarc if not dmarc_fail else "FAIL",
        severity="HIGH" if dmarc_fail else "SAFE",
        impact="HIGH" if dmarc_fail else "LOW", source="[EMAIL HEADER]",
        explanation=(f"DMARC policy evaluation failed — neither SPF nor DKIM alignment was achieved. Domain owner policy could not be enforced. Combined with SPF/DKIM failures, this is a complete authentication breakdown."
                     if dmarc_fail else "DMARC alignment passed — message satisfies domain owner's published policy."),
        risk_contribution=10 if dmarc_fail else 0,
    ))

    # All auth fails bonus
    if auth_failures >= 3:
        cards.append(EvidenceCard(
            id=next_id(), name="AUTHENTICATION BREAKDOWN",
            finding="SPF + DKIM + DMARC all FAIL",
            severity="CRITICAL", impact="HIGH", source="[EMAIL HEADER]",
            explanation="Complete authentication breakdown. All three email authentication mechanisms failed simultaneously. The sender domain is entirely unverified. This is a hallmark of spoofed or hijacked sender identity.",
            risk_contribution=15,
        ))

    # Sender / Reply-To mismatch
    from_reply_aligned = auth.get("from_reply_to_aligned")
    from_return_aligned = auth.get("from_return_path_aligned")
    sender_domain = meta.get("sender_domain") or ""
    reply_domain = meta.get("reply_to_domain") or ""

    if from_reply_aligned is False:
        cards.append(EvidenceCard(
            id=next_id(), name="REPLY-TO MISMATCH",
            finding=f"From: {sender_domain} ≠ Reply-To: {reply_domain}",
            severity="HIGH", impact="HIGH", source="[EMAIL HEADER]",
            explanation="The visible From address domain differs from the Reply-To domain. Replies will be sent to a different address than the apparent sender. This is consistent with impersonation or phishing infrastructure designed to intercept replies.",
            risk_contribution=10,
            evidence_refs=[f"From domain: {sender_domain}", f"Reply-To domain: {reply_domain}"],
        ))

    if from_return_aligned is False:
        cards.append(EvidenceCard(
            id=next_id(), name="RETURN-PATH MISMATCH",
            finding="From ≠ Return-Path domain",
            severity="MEDIUM", impact="MEDIUM", source="[EMAIL HEADER]",
            explanation="Return-Path domain does not match the From address domain. This misalignment is often observed in email spoofing and can bypass naive spam filters.",
            risk_contribution=5,
        ))

    # Suspicious URLs
    for i, url in enumerate(suspicious_urls[:5]):
        reasons = ", ".join((url.get("risk_reasons") or [])[:3])
        cards.append(EvidenceCard(
            id=next_id(), name=f"SUSPICIOUS URL {i + 1}",
            finding=url.get("url", "")[:80],
            severity="HIGH" if (url.get("risk_score") or 0) >= 60 else "MEDIUM",
            impact="HIGH", source="[EMAIL CONTENT]",
            explanation=f"URL exhibits deceptive characteristics: {reasons or 'shortened/obfuscated link, suspicious TLD, or IP-based URL'}. This type of URL is commonly used to redirect victims to phishing pages or malware distribution sites.",
            risk_contribution=int(min(20, (url.get("risk_score") or 30) / 3)),
            evidence_refs=[url.get("url", "")],
        ))

    # Lookalike domains
    for d in suspicious_domains[:3]:
        lookalike = d.get("lookalike_of") or ""
        sim = d.get("similarity_score") or 0
        cards.append(EvidenceCard(
            id=next_id(), name="LOOKALIKE DOMAIN",
            finding=f"{d.get('domain')} → impersonates {lookalike}",
            severity="HIGH", impact="HIGH", source="[LOCAL HEURISTIC]",
            explanation=f"Domain '{d.get('domain')}' is a typosquatting or lookalike variant of '{lookalike}' ({sim:.0%} similarity). This is a classic brand impersonation technique used in phishing campaigns.",
            risk_contribution=10,
            evidence_refs=[d.get("domain", "")],
        ))

    # Content indicators
    for ind in indicators:
        itype = ind.get("indicator_type", "").replace("_", " ").upper()
        sev = ind.get("severity", "MEDIUM")
        cards.append(EvidenceCard(
            id=next_id(), name=itype,
            finding=ind.get("matched_evidence") or "Pattern matched",
            severity=sev,
            impact="HIGH" if sev in ("CRITICAL", "HIGH") else "MEDIUM",
            source="[EMAIL CONTENT]",
            explanation=ind.get("explanation") or "Social engineering pattern detected in email content.",
            risk_contribution=15 if sev in ("CRITICAL", "HIGH") else 8,
            evidence_refs=[ind.get("matched_evidence") or ""],
        ))

    # Header findings
    for f in findings[:5]:
        sev = f.get("severity", "MEDIUM")
        if sev in ("CRITICAL", "HIGH", "MEDIUM"):
            cards.append(EvidenceCard(
                id=next_id(), name=f.get("title", "HEADER ANOMALY"),
                finding=f.get("explanation", "")[:100],
                severity=sev,
                impact="HIGH" if sev == "CRITICAL" else "MEDIUM",
                source="[EMAIL HEADER]",
                explanation=f.get("explanation") or "Header anomaly detected.",
                risk_contribution=8 if sev in ("CRITICAL", "HIGH") else 3,
                evidence_refs=f.get("evidence") or [],
            ))

    return cards


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Reasoning chain
# ═══════════════════════════════════════════════════════════════════════════

def _build_reasoning_chain(
    evidence_cards: List[EvidenceCard],
    classification: ThreatClassification,
    intent: ThreatIntent,
    risk_score: float,
) -> List[ReasoningStep]:
    steps = []
    step = 1

    # Group evidence by type
    auth_cards = [c for c in evidence_cards if c.source == "[EMAIL HEADER]" and c.severity in ("CRITICAL", "HIGH")]
    content_cards = [c for c in evidence_cards if c.source == "[EMAIL CONTENT]"]
    url_cards = [c for c in evidence_cards if "URL" in c.name]
    domain_cards = [c for c in evidence_cards if "DOMAIN" in c.name or "LOOKALIKE" in c.name]

    if auth_cards:
        steps.append(ReasoningStep(
            step=step, label="Authentication Failure",
            detail=f"{len(auth_cards)} authentication mechanism(s) failed: " + ", ".join(c.name for c in auth_cards[:3]),
            evidence_ids=[c.id for c in auth_cards],
            leads_to="Sender Identity Anomaly",
        ))
        step += 1

    if any("MISMATCH" in c.name for c in evidence_cards):
        steps.append(ReasoningStep(
            step=step, label="Sender Identity Anomaly",
            detail="From address domain does not align with Reply-To or Return-Path. Indicates sender impersonation.",
            evidence_ids=[c.id for c in evidence_cards if "MISMATCH" in c.name],
            leads_to="Attack Vector Identified",
        ))
        step += 1

    if url_cards:
        steps.append(ReasoningStep(
            step=step, label="Suspicious URL Detected",
            detail=f"{len(url_cards)} suspicious URL(s) identified with deceptive characteristics.",
            evidence_ids=[c.id for c in url_cards],
            leads_to="Content Analysis",
        ))
        step += 1

    if domain_cards:
        steps.append(ReasoningStep(
            step=step, label="Domain Impersonation",
            detail=f"Lookalike or typosquatted domain detected — brand impersonation infrastructure.",
            evidence_ids=[c.id for c in domain_cards],
            leads_to="Attack Classification",
        ))
        step += 1

    if content_cards:
        steps.append(ReasoningStep(
            step=step, label="Content Analysis — Social Engineering",
            detail=f"{len(content_cards)} social engineering pattern(s) detected in email content.",
            evidence_ids=[c.id for c in content_cards],
            leads_to="Intent Classification",
        ))
        step += 1

    steps.append(ReasoningStep(
        step=step, label=f"Intent: {intent.intent}",
        detail=intent.reason,
        evidence_ids=[],
        leads_to="Threat Classification",
    ))
    step += 1

    steps.append(ReasoningStep(
        step=step, label=f"Classification: {classification.primary}",
        detail=f"Primary threat classification based on combined evidence. Secondary: {', '.join(classification.secondary) or 'None'}.",
        evidence_ids=[],
        leads_to="Risk Assessment",
    ))
    step += 1

    severity_word = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"
    steps.append(ReasoningStep(
        step=step, label=f"Risk Score: {risk_score:.0f}/100 — {severity_word}",
        detail=f"Final risk score aggregated from {len(evidence_cards)} evidence items across authentication, content, infrastructure, and behavioral dimensions.",
        evidence_ids=[c.id for c in evidence_cards],
        leads_to=None,
    ))

    return steps


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Attack chain
# ═══════════════════════════════════════════════════════════════════════════

def _build_attack_chain(
    decision: Dict, classification: ThreatClassification, evidence_cards: List[EvidenceCard]
) -> List[AttackChainNode]:
    chains = {
        "Credential Phishing": [
            ("Attacker", "Threat actor prepares spoofed sender identity and phishing infrastructure", False),
            ("Spoofed Identity", "From address impersonates a trusted entity; authentication fails", True),
            ("Phishing Email", "Email delivered with urgency pretext (account suspension, security alert)", True),
            ("Social Engineering", "Psychological pressure applied to bypass recipient's skepticism", True),
            ("Suspicious URL", "Link directs victim to fake login page mimicking legitimate service", True),
            ("Credential Harvesting", "Victim submits credentials to attacker-controlled form", True),
            ("Account Takeover", "Attacker uses stolen credentials to access victim's account", True),
        ],
        "Business Email Compromise": [
            ("Attacker", "Threat actor researches target organization and key personnel", False),
            ("Executive Impersonation", "Email spoofs CEO/CFO identity using display name manipulation", True),
            ("Urgent Request", "Message creates time pressure around confidential financial transaction", True),
            ("Social Engineering", "Secrecy requested — 'keep this between us'", True),
            ("Payment / Wire Transfer", "Victim redirects funds to attacker-controlled account", True),
            ("Financial Fraud", "Organization suffers financial loss", True),
        ],
        "Malicious Attachment": [
            ("Attacker", "Threat actor crafts malicious document payload", False),
            ("Phishing Email", "Email delivered with pretext to open attachment", True),
            ("Social Engineering", "Urgency or curiosity baiting used to prompt action", True),
            ("Malicious Attachment", "Victim opens document — macros or scripts execute", True),
            ("Malware Delivery", "Malicious code runs in victim environment", True),
            ("System Compromise", "Attacker establishes foothold or exfiltrates data", True),
        ],
        "Extortion": [
            ("Attacker", "Threat actor fabricates or possesses damaging material", False),
            ("Threatening Email", "Email claims to have compromising information about victim", True),
            ("Blackmail Demand", "Payment demanded (cryptocurrency) under threat of exposure", True),
            ("Financial Coercion", "Victim pressured to comply or face reputational/personal harm", True),
        ],
        "Spam": [
            ("Sender", "Bulk email sender distributes promotional content", False),
            ("Spam Email", "Unsolicited commercial or promotional message", True),
            ("Recipient", "Message delivered to recipient's inbox", False),
        ],
    }

    key = classification.primary
    chain_def = chains.get(key) or chains.get("Credential Phishing")

    return [
        AttackChainNode(position=i + 1, label=label, detail=detail, threat=is_threat)
        for i, (label, detail, is_threat) in enumerate(chain_def)
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Helper: IOC extraction
# ═══════════════════════════════════════════════════════════════════════════

def _extract_iocs(meta, urls, domains, ip_addresses, findings) -> List[Dict[str, str]]:
    iocs = []
    seen = set()

    sender = meta.get("from_address") or ""
    if sender and sender not in seen:
        seen.add(sender)
        iocs.append({"type": "EMAIL", "value": sender, "source": "[EMAIL HEADER]", "confidence": "HIGH"})

    reply_to = meta.get("reply_to") or ""
    if reply_to and reply_to not in seen and reply_to != sender:
        seen.add(reply_to)
        iocs.append({"type": "EMAIL", "value": reply_to, "source": "[EMAIL HEADER]", "confidence": "HIGH"})

    for url in urls:
        u = url.get("url") or ""
        if u and u not in seen and (url.get("risk_score") or 0) > 20:
            seen.add(u)
            iocs.append({"type": "URL", "value": u[:120], "source": "[EMAIL CONTENT]", "confidence": "MEDIUM"})
        hostname = url.get("hostname") or ""
        if hostname and hostname not in seen:
            seen.add(hostname)
            iocs.append({"type": "DOMAIN", "value": hostname, "source": "[EMAIL CONTENT]", "confidence": "MEDIUM"})

    for d in domains:
        dom = d.get("domain") or ""
        if dom and dom not in seen and (d.get("risk_score") or 0) > 20:
            seen.add(dom)
            iocs.append({"type": "DOMAIN", "value": dom, "source": "[EMAIL HEADER]", "confidence": "HIGH" if d.get("lookalike_of") else "MEDIUM"})

    for ip in ip_addresses:
        addr = ip.get("ip_address") or ""
        if addr and addr not in seen and not ip.get("is_private"):
            seen.add(addr)
            iocs.append({"type": "IP", "value": addr, "source": "[EMAIL HEADER]", "confidence": "MEDIUM"})

    return iocs[:20]


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Confidence & strength
# ═══════════════════════════════════════════════════════════════════════════

def _compute_ai_confidence(evidence_cards, confidence_raw, auth_failures, suspicious_url_count) -> float:
    base = confidence_raw
    bonus = 0.0
    if auth_failures >= 3:
        bonus += 0.05
    if suspicious_url_count > 0:
        bonus += 0.03
    if len(evidence_cards) >= 5:
        bonus += 0.03
    return round(min(0.98, base + bonus), 2)


def _compute_evidence_strength(evidence_cards, risk_score, auth_failures) -> str:
    critical_count = sum(1 for c in evidence_cards if c.severity == "CRITICAL")
    high_count = sum(1 for c in evidence_cards if c.severity == "HIGH")
    if critical_count >= 2 or (high_count >= 4 and risk_score >= 70):
        return "VERY HIGH"
    elif high_count >= 3 or risk_score >= 60:
        return "HIGH"
    elif high_count >= 1 or risk_score >= 35:
        return "MEDIUM"
    elif len(evidence_cards) > 0:
        return "LOW"
    return "INSUFFICIENT"


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Conclusion generation
# ═══════════════════════════════════════════════════════════════════════════

def _generate_conclusion(classification, intent, risk_score, severity, evidence_cards, se_signals, related_cases) -> str:
    high_se = [s for s in se_signals if s.detected and s.score >= 50]
    parts = [
        f"Forensic AI analysis of this investigation determined the primary threat classification to be "
        f"**{classification.primary}** with **{classification.confidence:.0%} confidence**.",
    ]
    if classification.secondary:
        parts.append(f"Secondary classifications include: {', '.join(classification.secondary)}.")
    parts.append(
        f"The deterministic risk engine assigned a risk score of **{risk_score:.0f}/100** ({severity}), "
        f"based on {len(evidence_cards)} evidence items."
    )
    if intent.intent != "Unknown":
        parts.append(f"The likely attack intent is **{intent.intent}** — {intent.reason}")
    if high_se:
        se_names = ", ".join(s.signal for s in high_se[:4])
        parts.append(
            f"Significant emotional manipulation signals were detected: {se_names}. "
            "These are assessed as linguistic manipulation patterns (not psychological certainty)."
        )
    if related_cases:
        parts.append(
            f"This investigation correlates with {len(related_cases)} previous case(s), "
            "suggesting a coordinated campaign or repeated threat actor infrastructure."
        )
    parts.append(
        "Note: External threat intelligence was unavailable — analysis relies on "
        "local heuristic, deterministic forensic evidence, and AI inference."
    )
    return " ".join(parts)


def _generate_recommended_response(risk_score, classification, decision) -> str:
    if risk_score >= 75:
        return (
            "CRITICAL threat detected. Recommended actions (require human approval): "
            "1) Quarantine the email immediately. "
            "2) Block sender domain and all identified malicious URLs. "
            "3) Preserve all forensic evidence. "
            "4) Escalate to SOC Tier 2. "
            "5) Search for similar emails across the organization. "
            "6) Notify affected user and conduct credential reset if credential phishing confirmed."
        )
    elif risk_score >= 50:
        return (
            "HIGH threat detected. Recommended actions (require human approval): "
            "1) Quarantine the email. "
            "2) Block identified malicious URLs. "
            "3) Create or update the SOC incident. "
            "4) Analyst review of all evidence before action."
        )
    elif risk_score >= 25:
        return (
            "MEDIUM threat — analyst review recommended. "
            "Monitor for related activity. Verify sender through out-of-band channel. "
            "No destructive action required without further confirmation."
        )
    else:
        return (
            "LOW threat level — no significant malicious evidence detected. "
            "No automated action required. Standard monitoring applies."
        )
