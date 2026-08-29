"""Attribution confidence ladder (Phase 2 Part 14 / Phase 3 Part 12) - LEVEL 0-6, never claims identity."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

LEVELS = {
    0: "Insufficient evidence",
    1: "Suspicious email detected",
    2: "Suspicious infrastructure identified",
    3: "Related indicators identified",
    4: "Campaign correlation established",
    5: "Infrastructure cluster identified",
    6: "External attribution evidence available (not applicable in this platform)",
}


@dataclass
class AttributionAssessment:
    level: int
    level_label: str
    detection_confidence: float
    infrastructure_confidence: float
    campaign_confidence: float
    attribution_confidence: float
    explanation: List[str] = field(default_factory=list)


def assess_attribution(risk_score: float, has_infra_indicators: bool, campaign_matches: list) -> AttributionAssessment:
    explanation = []
    detection_conf = min(1.0, risk_score / 100.0)

    level = 0
    if risk_score >= 31:
        level = 1
        explanation.append("Deterministic + ML evidence indicates a suspicious email.")
    infra_conf = 0.0
    if has_infra_indicators and level >= 1:
        level = 2
        infra_conf = 0.5
        explanation.append("Suspicious sending infrastructure (domain/IP/URL) was observed.")

    campaign_conf = 0.0
    likely = [m for m in campaign_matches if m.relationship_label == "likely related"]
    possible = [m for m in campaign_matches if m.relationship_label == "possibly related"]
    if possible and level >= 2:
        level = 3
        campaign_conf = 0.4
        explanation.append(f"{len(possible)} possibly-related prior case(s) identified.")
    if likely:
        level = 4
        campaign_conf = 0.7
        explanation.append(f"{len(likely)} likely-related prior case(s) identified - possible campaign.")
    if len(likely) >= 3:
        level = 5
        campaign_conf = 0.85
        explanation.append("3+ likely-related cases suggest an infrastructure cluster.")

    explanation.append("Attribution to a specific threat actor is NOT established by this platform.")

    return AttributionAssessment(
        level=level, level_label=LEVELS[level],
        detection_confidence=round(detection_conf, 2),
        infrastructure_confidence=round(infra_conf, 2),
        campaign_confidence=round(campaign_conf, 2),
        attribution_confidence=0.0,  # this platform never establishes actor-level attribution
        explanation=explanation,
    )
