"""
Deterministic header-anomaly / forensic rule engine.

Every rule returns zero or one Finding with: rule_id, title, category,
severity, explanation (the WHY), evidence, confidence. No rule ever
outputs a bare "suspicious" label without justification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.forensic.email_parser import ParsedEmail
from app.forensic.auth_analyzer import AuthenticationAnalysis

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "aol.com", "protonmail.com", "mail.com", "gmx.com",
}

EXEC_TITLES = {"ceo", "cfo", "cto", "president", "director", "vp", "vice president", "founder", "manager", "hr"}


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str  # INFO/LOW/MEDIUM/HIGH/CRITICAL
    explanation: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.6


def _domain_mismatch(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    return a != b and not a.endswith("." + b) and not b.endswith("." + a)


def run_header_anomaly_rules(
    parsed: ParsedEmail,
    auth: AuthenticationAnalysis,
    received_hop_count: int,
) -> List[Finding]:
    findings: List[Finding] = []

    # RULE 1: From vs Reply-To domain mismatch
    if _domain_mismatch(parsed.sender_domain, parsed.reply_to_domain):
        findings.append(Finding(
            rule_id="HDR-001",
            title="From / Reply-To domain mismatch",
            category="header",
            severity="MEDIUM",
            explanation=(
                "The visible From address domain differs from the Reply-To address domain. "
                "This is a common technique in phishing and BEC where replies are silently "
                "routed to an attacker-controlled mailbox while the From address looks legitimate."
            ),
            evidence=[f"From domain: {parsed.sender_domain}", f"Reply-To domain: {parsed.reply_to_domain}"],
            confidence=0.7,
        ))

    # RULE 2: From vs Return-Path mismatch
    if _domain_mismatch(parsed.sender_domain, parsed.return_path_domain):
        findings.append(Finding(
            rule_id="HDR-002",
            title="From / Return-Path domain mismatch",
            category="header",
            severity="LOW",
            explanation=(
                "The From domain differs from the envelope Return-Path domain. This can occur "
                "legitimately (mailing lists, marketing platforms) but is also seen when a "
                "message is relayed through infrastructure unrelated to the claimed sender."
            ),
            evidence=[f"From domain: {parsed.sender_domain}", f"Return-Path domain: {parsed.return_path_domain}"],
            confidence=0.5,
        ))

    # RULE 3: suspicious Received chain inconsistencies (very short or missing chain on external mail)
    if received_hop_count == 0:
        findings.append(Finding(
            rule_id="HDR-003",
            title="No Received headers present",
            category="header",
            severity="MEDIUM",
            explanation=(
                "The message contains no Received headers at all, which is unusual for mail "
                "that traversed the internet and may indicate the headers were stripped or the "
                "file was fabricated/edited rather than being a genuine delivered message."
            ),
            evidence=["Received header count: 0"],
            confidence=0.55,
        ))

    # RULE 4/5: missing expected authentication information
    if auth.source == "INSUFFICIENT_DATA":
        findings.append(Finding(
            rule_id="HDR-004",
            title="Missing authentication information",
            category="authentication",
            severity="LOW",
            explanation=(
                "No Authentication-Results header was found, so SPF/DKIM/DMARC status could not "
                "be determined from this message alone. This does not confirm the message is "
                "malicious, but it does mean authenticity cannot be verified from headers."
            ),
            evidence=["Authentication-Results header: absent"],
            confidence=0.4,
        ))
    else:
        if auth.spf.result in ("FAIL", "SOFTFAIL"):
            findings.append(Finding(
                rule_id="HDR-005",
                title=f"SPF check did not pass ({auth.spf.result})",
                category="authentication",
                severity="HIGH" if auth.spf.result == "FAIL" else "MEDIUM",
                explanation=(
                    "SPF validates whether the sending mail server is authorized to send on "
                    "behalf of the claimed domain. A FAIL/SOFTFAIL result means the sending "
                    "server was not listed as authorized, a strong spoofing indicator."
                ),
                evidence=[f"SPF result: {auth.spf.result}", f"SPF domain: {auth.spf.domain}"],
                confidence=0.75,
            ))
        if auth.dmarc.result == "FAIL":
            findings.append(Finding(
                rule_id="HDR-006",
                title="DMARC check failed",
                category="authentication",
                severity="HIGH",
                explanation=(
                    "DMARC failure means the message failed the sending domain's own published "
                    "policy for SPF/DKIM alignment, indicating the message likely did not "
                    "originate from infrastructure authorized by the claimed domain."
                ),
                evidence=[f"DMARC result: {auth.dmarc.result}", f"DMARC policy: {auth.dmarc_policy}"],
                confidence=0.8,
            ))

    # RULE 7: suspicious Message-ID patterns
    if parsed.message_id:
        mid_domain_match = re.search(r"@([^>\s]+)>?$", parsed.message_id)
        if mid_domain_match:
            mid_domain = mid_domain_match.group(1).lower()
            if _domain_mismatch(parsed.sender_domain, mid_domain):
                findings.append(Finding(
                    rule_id="HDR-007",
                    title="Message-ID domain does not match sender domain",
                    category="header",
                    severity="LOW",
                    explanation=(
                        "The domain portion of the Message-ID header does not match the From "
                        "domain. This can be benign (relay/mailing-list rewriting) but is also "
                        "observed when messages are generated by tooling unrelated to the "
                        "claimed sending organization."
                    ),
                    evidence=[f"Message-ID domain: {mid_domain}", f"From domain: {parsed.sender_domain}"],
                    confidence=0.35,
                ))
    else:
        findings.append(Finding(
            rule_id="HDR-008",
            title="Missing Message-ID header",
            category="header",
            severity="LOW",
            explanation=(
                "The message has no Message-ID header. Legitimate mail transfer agents "
                "virtually always assign one; its absence can indicate a hand-crafted or "
                "script-generated message."
            ),
            evidence=["Message-ID: absent"],
            confidence=0.4,
        ))

    # RULE 9: display-name impersonation pattern (display name contains a different domain / brand-like string with mismatched address)
    if parsed.from_display_name and parsed.from_address:
        display_lower = parsed.from_display_name.lower()
        domain_in_display = re.search(r"([a-zA-Z0-9-]+\.(?:com|net|org|co|io|gov|example))", display_lower)
        if domain_in_display and parsed.sender_domain and domain_in_display.group(1) not in parsed.sender_domain:
            findings.append(Finding(
                rule_id="HDR-009",
                title="Display name impersonates a different domain",
                category="header",
                severity="HIGH",
                explanation=(
                    "The From display name itself contains a domain/brand name that does not "
                    "match the actual sending address domain - a classic display-name spoofing "
                    "technique designed to deceive users who only glance at the sender name."
                ),
                evidence=[f"Display name: {parsed.from_display_name}", f"Actual From address: {parsed.from_address}"],
                confidence=0.65,
            ))
        exec_title_hit = [t for t in EXEC_TITLES if t in display_lower]
        if exec_title_hit and parsed.sender_domain and parsed.sender_domain in FREEMAIL_DOMAINS:
            findings.append(Finding(
                rule_id="HDR-010",
                title="Executive title in display name sent from a free webmail domain",
                category="header",
                severity="HIGH",
                explanation=(
                    "The display name suggests an executive/authority role, but the message was "
                    "sent from a free consumer webmail domain rather than a corporate domain - a "
                    "common Business Email Compromise (BEC) executive-impersonation pattern."
                ),
                evidence=[f"Display name: {parsed.from_display_name}", f"Sending domain: {parsed.sender_domain}", f"Matched title(s): {', '.join(exec_title_hit)}"],
                confidence=0.6,
            ))

    # RULE: multiple unrelated domains within the message (from/reply-to/return-path all different)
    domains_present = {d for d in (parsed.sender_domain, parsed.reply_to_domain, parsed.return_path_domain) if d}
    if len(domains_present) >= 3:
        findings.append(Finding(
            rule_id="HDR-011",
            title="Multiple unrelated domains referenced across sender headers",
            category="header",
            severity="MEDIUM",
            explanation=(
                "From, Reply-To, and Return-Path each reference a distinct, unrelated domain. "
                "While mailing-list and marketing infrastructure can cause this legitimately, "
                "it is also a pattern seen in phishing infrastructure that separates the "
                "'presented' identity from the reply and bounce-handling infrastructure."
            ),
            evidence=[f"Domains observed: {', '.join(sorted(domains_present))}"],
            confidence=0.45,
        ))

    return findings
