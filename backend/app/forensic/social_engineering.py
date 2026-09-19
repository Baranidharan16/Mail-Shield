"""
Deterministic baseline social-engineering and threat content analyzer.
Detects urgency, phishing, credential harvesting, impersonation, explicit threats,
blackmail, extortion, and harassment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_PATTERNS = {
    "explicit_threat": {
        "severity": "CRITICAL",
        "patterns": [
            r"\b(kill|harm|murder|assault|hurt|destroy|swat)\b",
            r"\b(hunt you down|end your life|cause you harm|physically harm|break your)\b",
            r"\b(harm (your|you)|consequences for you and your family)\b",
            r"\b(watch your back|pay with your life|grave consequences)\b",
        ],
        "explanation": "Direct language threatening physical violence, bodily harm, or severe personal danger.",
    },
    "blackmail_extortion": {
        "severity": "CRITICAL",
        "patterns": [
            r"\b(blackmail|extort(ion)?|ransom(ware)?)\b",
            r"\b(recorded you|video of you|webcam|adult (site|video|content))\b",
            r"\b(send (bitcoin|btc|crypto|monero|funds|money)|wallet address)\b",
            r"\b(send to this (btc|bitcoin|crypto) address|transfer btc)\b",
            r"\b(leak (your|these) (photos|videos|data|secrets|passwords))\b",
            r"\b(send (the |)payment or (i will|we will|i'll) release)\b",
            r"\b(hacked your (device|computer|phone|camera|system))\b",
        ],
        "explanation": "Extortion or sextortion demanding cryptocurrency/payment under threat of releasing sensitive materials.",
    },
    "harassment_intimidation": {
        "severity": "HIGH",
        "patterns": [
            r"\b(doxx(ing)?|ruin your (reputation|career|life)|humiliate you)\b",
            r"\b(spread rumors|publish your private|expose you)\b",
            r"\b(you have no choice|i am watching you|nowhere to hide)\b",
        ],
        "explanation": "Coercive intimidation, doxxing, or harassment intended to instill fear and compliance.",
    },
    "credential_harvesting": {
        "severity": "HIGH",
        "patterns": [
            r"\bverify your (password|account|identity|credentials)\b",
            r"\bconfirm your (password|login|account|identity)\b",
            r"\bre-?enter your password\b",
            r"\bupdate your (login|credentials|security details)\b",
            r"\bclick here to (verify|login|sign in|authenticate)\b",
            r"\benter your (pin|passcode|secret code|two-factor)\b",
            r"\bconfirm your (credentials|login details|account details)\b",
            r"\bsign in (to|and) (confirm|verify|keep|continue|restore)\b",
            r"\b(log ?in|sign in) to (verify|confirm|restore|unlock|reactivate)\b",
            r"\bkeep (your )?current password\b",
            r"\bvalidate your (account|mailbox|email)\b",
            r"\breply with your (current )?password\b",
            r"\b(send|provide|share) (me |us )?(your )?(otp|one[- ]time password|password|pin|cvv)\b",
        ],
        "explanation": "Directly requests the recipient to input or re-authenticate login credentials.",
    },
    "phishing_social_engineering": {
        "severity": "HIGH",
        "patterns": [
            r"\baccount (will be |is |has been )?(suspended|locked|terminated|disabled|restricted)\b",
            r"\bunauthorized (access|login|activity|transaction)\b",
            r"\bsecurity breach\b",
            r"\bverify your account\b",
            r"\bunusual sign-?in activity\b",
            r"\baccount verification required\b",
            r"\bfailure to (verify|respond|update) will result\b",
            r"\b(kyc|pan|aadhaar)( details)? (is |are )?(not )?(updated|expired|pending|incomplete)\b",
            r"\bwill be (blocked|deactivated|closed|suspended)\b",
            r"\bparcel (is )?(on hold|held)\b",
            r"\b(customs|delivery|redelivery) fee\b",
            r"\btax refund\b",
        ],
        "explanation": "Pretext regarding account suspension or security breach to prompt hasty submission to a phishing page.",
    },
    "executive_impersonation": {
        "severity": "HIGH",
        "patterns": [
            r"\bare you (available|at your desk)\??\b",
            r"\bi need you to handle (a |this )task\b",
            r"\bkeep this (confidential|between us|strictly confidential)\b",
            r"\bcan you do me a favou?r\b",
            r"\bi'?m (currently |)in a meeting and can'?t talk\b",
            r"\bpurchase (apple|google play|amazon|steam) gift cards?\b",
            r"\bcannot take (any )?calls\b",
        ],
        "explanation": "Conversational phrasing and secrecy requests characteristic of CEO/Executive BEC fraud.",
    },
    "payment_fraud": {
        "severity": "HIGH",
        "patterns": [
            r"\bwire transfer\b",
            r"\bwire the (funds|money|payment)\b",
            r"\bupdated (bank|banking|payment) (details|information|account)\b",
            r"\bnew (bank|payment) account\b",
            r"\bremit(tance)? (to|address)\b",
            r"\binvoice attached\b",
            r"\bchange (the )?beneficiary\b",
            r"\bbeneficiary (bank )?(details|account)\b",
            r"\bprocess a (wire|payment|fund) transfer\b",
            r"\boverdue invoice\b",
        ],
        "explanation": "Requests urgent financial transactions or redirects banking details (invoice fraud).",
    },
    "urgency": {
        "severity": "MEDIUM",
        "patterns": [
            r"\burgent(ly)?\b",
            r"\bimmediately\b",
            r"\bas soon as possible\b",
            r"\basap\b",
            r"\bact now\b",
            r"\bwithin (24|48|12) hours\b",
            r"\btime[- ]sensitive\b",
            r"\bfinal notice\b",
            r"\bimmediate action required\b",
        ],
        "explanation": "Language creating artificial time pressure to induce compliance without careful verification.",
    },
    "suspicious_call_to_action": {
        "severity": "MEDIUM",
        "patterns": [
            r"\bclick (the |)link below\b",
            r"\bdownload the attachment\b",
            r"\benable (macros|content|editing)\b",
            r"\bopen the attached (file|document|archive|zip)\b",
            r"\bview document online\b",
        ],
        "explanation": "Directs recipient toward opening untrusted attachments or clicking outbound links.",
    },
    "password_reset_pressure": {
        "severity": "HIGH",
        "patterns": [
            r"\bpassword (will )?(expire[sd]?|expiring)\b",
            r"\byour password (has )?expired\b",
            r"\breset your password (now|immediately|today|within)\b",
            r"\bmailbox (is )?(full|over quota)\b",
            r"\bexceeded (its|your) (storage|quota)\b",
        ],
        "explanation": "Pressures the recipient into a password reset / mailbox-quota action — a common credential-phishing pretext.",
    },
    "spam_bulk": {
        "severity": "LOW",
        "patterns": [
            r"\b(100% free|congratulations you won|lottery winner|claim your prize)\b",
            r"\b(online casino|viagra|cialis|weight loss pill|crypto giveaway)\b",
            r"\b(you have been selected|claim your reward|unsubscribe here)\b",
        ],
        "explanation": "Promotional or bulk marketing indicators commonly associated with spam distribution.",
    },
}


@dataclass
class ContentIndicator:
    indicator_type: str
    severity: str
    matched_evidence: str
    explanation: str
    confidence: float = 0.55


def analyze_social_engineering(text_body: str, html_body: str, subject: str = "") -> List[ContentIndicator]:
    combined = " ".join(filter(None, [subject, text_body, re.sub(r"<[^>]+>", " ", html_body or "")]))
    combined_lower = combined.lower()

    indicators: List[ContentIndicator] = []
    for indicator_type, cfg in _PATTERNS.items():
        matches = []
        for pattern in cfg["patterns"]:
            m = re.search(pattern, combined_lower, re.IGNORECASE)
            if m:
                matches.append(m.group(0))
        if matches:
            confidence = min(0.95, 0.6 + 0.1 * len(matches))
            matched_str = "; ".join(sorted(set(matches)))
            indicators.append(ContentIndicator(
                indicator_type=indicator_type,
                severity=cfg["severity"],
                matched_evidence=matched_str,
                explanation=cfg["explanation"],
                confidence=round(confidence, 2),
            ))
            # Also emit canonical aliases expected across forensic tests
            if indicator_type == "credential_harvesting":
                indicators.append(ContentIndicator(
                    indicator_type="credential_request",
                    severity=cfg["severity"],
                    matched_evidence=matched_str,
                    explanation=cfg["explanation"],
                    confidence=round(confidence, 2),
                ))
            elif indicator_type == "phishing_social_engineering":
                indicators.append(ContentIndicator(
                    indicator_type="account_verification", severity=cfg["severity"], matched_evidence=matched_str,
                    explanation=cfg["explanation"], confidence=round(confidence, 2)))
            elif indicator_type in ("explicit_threat", "blackmail_extortion", "harassment_intimidation"):
                indicators.append(ContentIndicator(
                    indicator_type="fear_threat", severity=cfg["severity"], matched_evidence=matched_str,
                    explanation=cfg["explanation"], confidence=round(confidence, 2)))
            elif indicator_type == "payment_fraud":
                indicators.append(ContentIndicator(
                    indicator_type="invoice_payment_diversion",
                    severity=cfg["severity"],
                    matched_evidence=matched_str,
                    explanation=cfg["explanation"],
                    confidence=round(confidence, 2),
                ))
                indicators.append(ContentIndicator(
                    indicator_type="payment_request",
                    severity=cfg["severity"],
                    matched_evidence=matched_str,
                    explanation=cfg["explanation"],
                    confidence=round(confidence, 2),
                ))

    return indicators
