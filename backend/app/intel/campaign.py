"""
Campaign correlation engine (Phase 2 Part 8 / Phase 3 Part 11).

Compares one investigation against prior COMPLETED investigations using:
  - shared sender/reply-to/return-path/URL domains
  - shared observed IPs
  - subject+body text similarity (TF-IDF cosine, app/intel/similarity.py)

Produces a bounded 0-1 similarity score per candidate and a cautious
label - never an absolute "same campaign" claim.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from app.intel.similarity import compute_similarity


@dataclass
class CampaignMatch:
    investigation_id: str
    case_id: str
    similarity_score: float
    relationship_label: str  # "likely related" / "possibly related" / "no significant relationship detected"
    reasons: List[str] = field(default_factory=list)


def _label(score: float) -> str:
    if score >= 0.7:
        return "likely related"
    if score >= 0.4:
        return "possibly related"
    return "no significant relationship detected"


def find_campaign_matches(
    target_domains: set, target_ips: set, target_text: str,
    candidates: List[dict],  # [{investigation_id, case_id, domains:set, ips:set, text:str}]
) -> List[CampaignMatch]:
    if not candidates:
        return []
    texts = [c["text"] for c in candidates]
    text_sims = compute_similarity(target_text, texts)

    matches = []
    for cand, text_sim in zip(candidates, text_sims):
        shared_domains = target_domains & cand["domains"]
        shared_ips = target_ips & cand["ips"]
        infra_score = 0.0
        reasons = []
        if shared_domains:
            infra_score += 0.5
            reasons.append(f"Shared domain(s): {', '.join(sorted(shared_domains))}")
        if shared_ips:
            infra_score += 0.4
            reasons.append(f"Shared observed IP(s): {', '.join(sorted(shared_ips))}")
        if text_sim > 0.3:
            reasons.append(f"Text similarity {text_sim:.0%} (subject/body)")

        combined = min(1.0, 0.6 * infra_score + 0.4 * text_sim)
        label = _label(combined)
        if label != "no significant relationship detected":
            matches.append(CampaignMatch(
                investigation_id=cand["investigation_id"], case_id=cand["case_id"],
                similarity_score=round(combined, 3), relationship_label=label, reasons=reasons,
            ))
    matches.sort(key=lambda m: m.similarity_score, reverse=True)
    return matches
