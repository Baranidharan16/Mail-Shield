"""
MailShield - Deterministic Risk Scoring Engine
Combines ML predictions, NLP threat patterns, and forensic artifacts into a transparent 0-100 score.
"""
from __future__ import annotations

from typing import List, Tuple
from schemas.analysis import MLAnalysisResult, NLPAnalysisResult, ForensicAnalysisResult, RiskResult


DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".iso", ".img", ".hta", ".wsf"}


def calculate_risk_score(
    ml: MLAnalysisResult,
    nlp: NLPAnalysisResult,
    forensics: ForensicAnalysisResult
) -> RiskResult:
    """Calculates deterministic risk score (0-100) and assigns risk level.
    
    Formula:
    - ML Component: up to 35 points
    - NLP Component: up to 35 points
    - Forensic Evidence: up to 30 points
    Total is bounded [0, 100].
    """
    factors: List[str] = []
    total_score: float = 0.0

    # 1. ML Contribution (0 to 35 points)
    ml_pts = ml.phishing_probability * 35.0
    total_score += ml_pts
    if ml.phishing_probability >= 0.70:
        factors.append(f"ML Classifier high phishing probability ({ml.phishing_probability*100:.1f}%) [+ {ml_pts:.1f} pts]")
    elif ml.phishing_probability >= 0.40:
        factors.append(f"ML Classifier moderate suspicion ({ml.phishing_probability*100:.1f}%) [+ {ml_pts:.1f} pts]")

    # 2. NLP Threat Patterns Contribution (0 to 35 points)
    nlp_patterns = {
        "urgency": nlp.urgency,
        "credential_request": nlp.credential_request,
        "financial_manipulation": nlp.financial_manipulation,
        "impersonation": nlp.impersonation,
        "threat_language": nlp.threat_language,
        "suspicious_action": nlp.suspicious_action,
    }
    
    max_nlp_label = max(nlp_patterns, key=nlp_patterns.get)
    max_nlp_val = nlp_patterns[max_nlp_label]
    avg_nlp_val = sum(nlp_patterns.values()) / len(nlp_patterns)

    # Weighted: 20 pts from peak pattern, 15 pts from breadth across patterns
    nlp_pts = (max_nlp_val * 20.0) + (avg_nlp_val * 15.0)
    total_score += nlp_pts

    for label, val in nlp_patterns.items():
        if val >= 0.65:
            clean_name = label.replace("_", " ").title()
            factors.append(f"NLP detected strong pattern: {clean_name} ({val*100:.1f}%)")

    # 3. Forensic Evidence Contribution (0 to 30 points)
    forensic_pts = 0.0

    # SPF verdict
    if forensics.spf in ["FAIL", "PERMERROR"]:
        forensic_pts += 8.0
        factors.append(f"SPF authentication failed ({forensics.spf}) [+8.0 pts]")
    elif forensics.spf in ["SOFTFAIL", "NEUTRAL"]:
        forensic_pts += 4.0
        factors.append(f"SPF authentication unverified ({forensics.spf}) [+4.0 pts]")

    # DMARC verdict
    if forensics.dmarc in ["FAIL", "REJECT", "QUARANTINE"]:
        forensic_pts += 8.0
        factors.append(f"DMARC policy failed ({forensics.dmarc}) [+8.0 pts]")

    # Reply-To Mismatch
    if forensics.reply_to_mismatch:
        forensic_pts += 8.0
        factors.append("Reply-To domain differs from From domain (domain mismatch) [+8.0 pts]")

    # Suspicious URLs
    if forensics.suspicious_url_count > 0:
        url_add = min(12.0, forensics.suspicious_url_count * 4.0)
        forensic_pts += url_add
        factors.append(f"{forensics.suspicious_url_count} suspicious URL characteristics detected [+{url_add:.1f} pts]")

    # Dangerous attachments
    for att in forensics.attachments:
        for ext in DANGEROUS_EXTENSIONS:
            if att.lower().endswith(ext):
                forensic_pts += 10.0
                factors.append(f"High-risk executable attachment detected: {att} [+10.0 pts]")
                break

    # Cap forensic component at 30 points
    forensic_pts = min(30.0, forensic_pts)
    total_score += forensic_pts

    # Final bounded score
    final_score = int(round(min(100.0, max(0.0, total_score))))

    # Risk level classification
    if final_score >= 81:
        level = "CRITICAL"
    elif final_score >= 61:
        level = "HIGH"
    elif final_score >= 31:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not factors:
        factors.append("No significant malicious indicators detected across ML, NLP, or header forensics.")

    return RiskResult(
        score=final_score,
        level=level,
        contributing_factors=factors,
    )
