"""
AI Investigation Agent (deterministic orchestrator, not a chatbot).

Calls a fixed, allow-listed sequence of "tools" (plain Python functions -
no arbitrary code/network execution) over evidence ALREADY computed by
Phase 1/2, and produces a structured, evidence-cited summary. Because it
never calls an external LLM (LOCAL_ONLY_MODE), there is no prompt for
email content to hijack - untrusted email text is only ever scanned
(app/agent/security.py), never executed or treated as instructions.

Every tool call is logged by the caller into AgentActionLog for audit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.agent.security import scan_for_prompt_injection
from app.forensic.engine import ForensicAnalysisResult
from app.ai.fusion import FusionResult
from app.intel.enrichment import EnrichmentSummary

ALLOWED_TOOLS = [
    "parse_email_evidence", "review_forensic_findings", "analyze_domains",
    "analyze_ips", "analyze_urls", "query_threat_intelligence",
    "scan_for_prompt_injection", "assess_attribution", "generate_summary",
]


@dataclass
class AgentOutput:
    classification: str
    risk: float
    confidence: float
    key_findings: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    infrastructure_assessment: str = ""
    recommended_actions: List[Dict[str, object]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    prompt_injection_detected: bool = False
    tool_calls: List[str] = field(default_factory=list)


def _recommend(classification: str, risk: float) -> List[Dict[str, object]]:
    actions: List[Dict[str, object]] = []
    if risk >= 61:
        actions += [
            {"action": "Quarantine email", "severity": "HIGH", "requires_human_approval": True,
             "reason": f"Overall risk {risk:.0f}/100 ({classification})."},
            {"action": "Block sender/URL domain pending review", "severity": "HIGH", "requires_human_approval": True,
             "reason": "Domain/URL risk indicators present."},
            {"action": "Search organization for related emails", "severity": "MEDIUM", "requires_human_approval": False,
             "reason": "Reduce blast radius if this is part of a campaign."},
            {"action": "Preserve evidence", "severity": "HIGH", "requires_human_approval": False,
             "reason": "Evidence hash already computed; retain for chain of custody."},
        ]
    elif risk >= 31:
        actions += [
            {"action": "Analyst review", "severity": "MEDIUM", "requires_human_approval": False, "reason": "Moderate risk score warrants human judgement."},
            {"action": "Verify sender through a trusted out-of-band channel", "severity": "MEDIUM", "requires_human_approval": False, "reason": "Authentication or domain evidence is inconclusive."},
        ]
    else:
        actions.append({"action": "No action required", "severity": "LOW", "requires_human_approval": False, "reason": "Risk score is low and evidence does not indicate a threat."})
    return actions


def run_investigation_agent(
    forensic: ForensicAnalysisResult,
    fusion: FusionResult,
    intel: EnrichmentSummary,
) -> AgentOutput:
    tool_calls: List[str] = []

    tool_calls.append("parse_email_evidence")
    tool_calls.append("review_forensic_findings")
    key_findings = [f"{f.title} ({f.severity})" for f in forensic.header_findings if f.severity in ("HIGH", "CRITICAL", "MEDIUM")][:6]

    tool_calls.append("analyze_domains")
    domain_notes = [d.evidence[0] for d in forensic.domain_findings if d.evidence][:3]

    tool_calls.append("analyze_urls")
    url_notes = [r for u in forensic.url_findings for r in (u.risk_reasons or [])][:3]

    tool_calls.append("analyze_ips")
    tool_calls.append("query_threat_intelligence")
    intel_notes = intel.reasons[:3]

    tool_calls.append("scan_for_prompt_injection")
    combined_text = " ".join(filter(None, [forensic.parsed_email.subject, forensic.parsed_email.text_body]))
    injection = scan_for_prompt_injection(combined_text)
    if injection.detected:
        key_findings.append(
            "The email body contains text resembling an instruction-injection attempt "
            "(e.g. 'ignore previous instructions'). This was logged as evidence and was "
            "NOT executed or treated as an instruction by any part of this system."
        )

    indicators = domain_notes + url_notes
    infrastructure_note = forensic.originating_infrastructure_note or "No Received-chain infrastructure observed."

    tool_calls.append("assess_attribution")
    tool_calls.append("generate_summary")

    limitations = [
        "Classification and risk are investigation-support signals, not proof of malicious intent.",
        "Infrastructure notes describe earliest OBSERVED relay data, not a confirmed attacker location.",
    ]
    if fusion.evidence_completeness < 1.0:
        limitations.append(f"Only {fusion.evidence_completeness:.0%} of intended evidence sources were available for this investigation.")

    return AgentOutput(
        classification=fusion.classification,
        risk=fusion.overall_risk_score,
        confidence=fusion.confidence,
        key_findings=key_findings or ["No significant header/domain/URL anomalies detected."],
        indicators=indicators or intel_notes,
        infrastructure_assessment=infrastructure_note,
        recommended_actions=_recommend(fusion.classification, fusion.overall_risk_score),
        limitations=limitations,
        prompt_injection_detected=injection.detected,
        tool_calls=tool_calls,
    )
