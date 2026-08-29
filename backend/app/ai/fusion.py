"""
Threat Fusion Engine (Phase 2, Part 3/4).

Combines:
  1. deterministic Phase 1 forensic score (`ForensicAnalysisResult.threat_score`)
  2. ML structured-feature classification (Model A)
  3. ML text classification (Model B)
  4. threat-intelligence risk contribution (IP/domain/URL enrichment, Part 5)

into one explainable 0-100 `overall_risk_score` + `classification` +
`confidence`, with a fully itemized `risk_breakdown` and human-readable
`reasons` list built ONLY from evidence actually present in this
investigation (never invented).

Design choice: this is a second, small, transparent weighted-sum layer on
top of already-explainable inputs - not a black box. Each contributor's
weight is a documented constant below (not hard-coded inline in the
maths), matching the "must be explainable" and "do not claim certainty
when evidence is incomplete" requirements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.forensic.engine import ForensicAnalysisResult
from app.ml.model_provider import ModelPrediction

# Fusion weights: how much each layer contributes to the final 0-100 score.
# The deterministic Phase 1 score already IS a weighted composite of
# authentication/header/domain/url/social-engineering/infrastructure risk,
# so it anchors the fusion; ML and threat intel adjust it up/down based on
# corroborating or conflicting evidence.
FUSION_WEIGHTS = {
    "deterministic_forensic_score": 0.55,
    "ml_structured_score": 0.20,
    "ml_text_score": 0.10,
    "threat_intel_score": 0.15,
}

# Maps a model's predicted label to an implied risk level (0-100) purely
# for fusion-scoring purposes; LEGITIMATE/SUSPICIOUS/etc. are always
# reported verbatim elsewhere (this mapping never overwrites the label).
_LABEL_RISK = {
    "LEGITIMATE": 5,
    "SUSPICIOUS": 40,
    "PHISHING": 90,
    "BUSINESS_EMAIL_COMPROMISE": 88,
    "IMPERSONATION": 80,
    "CREDENTIAL_HARVESTING": 92,
    "FRAUD": 85,
    "MALWARE_SUSPECTED": 90,
}

CLASSIFICATION_BANDS = {"LOW": (0, 24), "MEDIUM": (25, 49), "HIGH": (50, 74), "CRITICAL": (75, 100)}


@dataclass
class FusionResult:
    overall_risk_score: float
    classification: str
    confidence: float
    risk_breakdown: Dict[str, Dict[str, object]]
    reasons: List[str]
    ml_structured_label: Optional[str]
    ml_text_label: Optional[str]
    evidence_completeness: float  # 0-1, how much of the intended evidence was actually available


def _label_to_score(pred: ModelPrediction) -> Optional[float]:
    if not pred.available or not pred.predicted_label:
        return None
    return float(_LABEL_RISK.get(pred.predicted_label, 50))


def fuse(
    forensic: ForensicAnalysisResult,
    structured_pred: ModelPrediction,
    text_pred: ModelPrediction,
    threat_intel_score: Optional[float] = None,
    threat_intel_reasons: Optional[List[str]] = None,
) -> FusionResult:
    reasons: List[str] = []
    components: Dict[str, Dict[str, object]] = {}
    weighted_sum = 0.0
    weight_used_total = 0.0
    evidence_points = 0
    evidence_possible = 4

    # --- 1. deterministic forensic score (always available) ---
    det_score = forensic.threat_score.overall_score
    w = FUSION_WEIGHTS["deterministic_forensic_score"]
    weighted_sum += det_score * w
    weight_used_total += w
    evidence_points += 1
    components["deterministic_forensic_score"] = {
        "score": det_score, "weight": w, "weighted_contribution": round(det_score * w, 2),
        "classification": forensic.threat_score.classification,
    }
    reasons.append(
        f"Deterministic forensic analysis scored {det_score:.0f}/100 ({forensic.threat_score.classification}) "
        f"from authentication, header, domain, URL, and content evidence."
    )
    for f in forensic.header_findings:
        if f.severity in ("HIGH", "CRITICAL"):
            reasons.append(f"{f.title} ({f.severity}).")

    # --- 2. ML structured model ---
    struct_score = _label_to_score(structured_pred)
    if struct_score is not None:
        w = FUSION_WEIGHTS["ml_structured_score"]
        weighted_sum += struct_score * w
        weight_used_total += w
        evidence_points += 1
        components["ml_structured_score"] = {
            "score": struct_score, "weight": w, "weighted_contribution": round(struct_score * w, 2),
            "predicted_label": structured_pred.predicted_label, "confidence": structured_pred.confidence,
            "model_version": structured_pred.model_metadata.model_version if structured_pred.model_metadata else None,
        }
        reasons.append(
            f"Structured ML model classified this message as {structured_pred.predicted_label} "
            f"(confidence {structured_pred.confidence:.0%})."
        )
    else:
        components["ml_structured_score"] = {"available": False, "note": structured_pred.note}

    # --- 3. ML text model ---
    text_score = _label_to_score(text_pred)
    if text_score is not None:
        w = FUSION_WEIGHTS["ml_text_score"]
        weighted_sum += text_score * w
        weight_used_total += w
        evidence_points += 1
        components["ml_text_score"] = {
            "score": text_score, "weight": w, "weighted_contribution": round(text_score * w, 2),
            "predicted_label": text_pred.predicted_label, "confidence": text_pred.confidence,
            "model_version": text_pred.model_metadata.model_version if text_pred.model_metadata else None,
        }
        reasons.append(
            f"Text/NLP model classified the message content as {text_pred.predicted_label} "
            f"(confidence {text_pred.confidence:.0%})."
        )
    else:
        components["ml_text_score"] = {"available": False, "note": text_pred.note}

    # --- 4. threat intelligence ---
    if threat_intel_score is not None:
        w = FUSION_WEIGHTS["threat_intel_score"]
        weighted_sum += threat_intel_score * w
        weight_used_total += w
        evidence_points += 1
        components["threat_intel_score"] = {
            "score": threat_intel_score, "weight": w, "weighted_contribution": round(threat_intel_score * w, 2),
        }
        for r in (threat_intel_reasons or []):
            reasons.append(r)
    else:
        components["threat_intel_score"] = {"available": False, "note": "No threat-intelligence enrichment available for this investigation's indicators."}

    # Renormalize by weight actually used, anchored by deterministic evidence
    if det_score >= 50:
        # High or Critical forensic evidence must not be diluted by missing external models
        overall = max(det_score, (weighted_sum / weight_used_total) if weight_used_total > 0 else det_score)
    else:
        overall = (weighted_sum / weight_used_total) if weight_used_total > 0 else det_score

    overall = round(min(100.0, max(0.0, overall)), 1)

    classification = "LOW"
    if overall >= 75:
        classification = "CRITICAL"
    elif overall >= 50:
        classification = "HIGH"
    elif overall >= 25:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    evidence_completeness = round(evidence_points / evidence_possible, 2)
    # Confidence reflects both model confidences (when available) and how
    # much evidence backed the fusion - never overstates certainty.
    model_confidences = [p.confidence for p in (structured_pred, text_pred) if p.available and p.predicted_label]
    base_conf = (sum(model_confidences) / len(model_confidences)) if model_confidences else 0.5
    confidence = round(min(1.0, 0.3 + 0.4 * evidence_completeness + 0.3 * base_conf), 2)

    if evidence_completeness < 0.75:
        reasons.append(
            f"Note: only {evidence_points}/{evidence_possible} intended evidence sources were available "
            f"for this investigation; confidence is adjusted downward accordingly."
        )

    return FusionResult(
        overall_risk_score=overall,
        classification=classification,
        confidence=confidence,
        risk_breakdown=components,
        reasons=reasons,
        ml_structured_label=structured_pred.predicted_label if structured_pred.available else None,
        ml_text_label=text_pred.predicted_label if text_pred.available else None,
        evidence_completeness=evidence_completeness,
    )
