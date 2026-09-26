"""Finding model + scoring shared by every sandbox analyzer.

Every finding carries a rule ID, severity, confidence, explanation and the
evidence that triggered it (never a bare label). Scores are combined with a
noisy-OR so many weak signals and one strong signal both push the score up
without a single hard-coded "magic" threshold per rule.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

SEVERITY_WEIGHT: Dict[str, float] = {"INFO": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str            # INFO / LOW / MEDIUM / HIGH / CRITICAL
    confidence: float        # 0..1
    category: str            # file_type / macro / script / pdf / archive / html / url / ioc / executable / reputation
    explanation: str
    evidence: str = ""
    mitre: Optional[str] = None          # MITRE ATT&CK technique id
    behavior: Optional[str] = None       # predicted runtime behaviour (static inference, never executed)

    def weight(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 0.0) * max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = (self.evidence or "")[:400]
        return d


@dataclass
class Verdict:
    verdict: str             # SAFE / SUSPICIOUS / MALICIOUS
    score: float             # 0..100
    reasons: List[str] = field(default_factory=list)


def noisy_or(findings: List[Finding]) -> float:
    p = 1.0
    for f in findings:
        p *= (1.0 - f.weight())
    return round((1.0 - p) * 100.0, 1)


def decide(findings: List[Finding]) -> Verdict:
    """Noisy-OR score + a severity override: any near-certain CRITICAL finding
    (known-bad hash, executable disguised as a document, auto-exec macro that
    launches a shell ...) is MALICIOUS regardless of the aggregate."""
    score = noisy_or(findings)
    ranked = sorted(findings, key=lambda f: f.weight(), reverse=True)
    reasons = [f"[{f.rule_id}] {f.title} — {f.explanation}" for f in ranked if f.severity != "INFO"][:8]
    critical = any(f.severity == "CRITICAL" and f.confidence >= 0.85 for f in findings)
    if critical or score >= 75:
        v = "MALICIOUS"
    elif score >= 35:
        v = "SUSPICIOUS"
    else:
        v = "SAFE"
    if not reasons:
        reasons = ["No malicious or suspicious static indicators were found."]
    return Verdict(verdict=v, score=score, reasons=reasons)
