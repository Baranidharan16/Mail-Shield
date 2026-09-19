from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.forensic.engine import run_forensic_analysis
from app.ml.features import build_feature_vector, feature_text_blob
from app.ml.structured_model import get_structured_model
from app.ml.text_model import get_text_model
from app.ai.fusion import fuse
from app.intel.enrichment import enrich_investigation
from app.intel.campaign import find_campaign_matches
from app.intel.graph import build_attack_graph
from app.intel.attribution import assess_attribution
from app.agent.investigation_agent import run_investigation_agent
from app.blockchain.ledger import anchor_evidence
from app.models.investigation import (
    Investigation,
    EmailMetadata,
    EmailHeader,
    ReceivedHop,
    AuthenticationResult,
    URLRecord,
    DomainRecord,
    IPAddressRecord,
    Indicator,
    Finding,
    RiskScoreBreakdown,
    Report,
    MLPrediction,
    ThreatIntelSummary,
    AttackGraph,
    AttributionAssessment,
    Campaign,
    CampaignMember,
    Alert,
    ResponseRecommendation,
    AuditLog,
    AgentActionLog,
)
from app.utils.storage import (
    save_evidence_file,
    sanitize_original_filename,
    generate_case_id,
    validate_extension,
    validate_size,
)

logger = logging.getLogger("forensic_platform")
settings = get_settings()


def create_investigation(
    db: Session,
    raw_bytes: bytes,
    original_filename: str,
    mime_type: Optional[str],
    created_by: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Investigation:
    """Validates + stores the uploaded evidence and creates a QUEUED investigation row.
    Does NOT run analysis - that happens in `run_analysis` (typically via a
    background task) so the API can respond immediately with a job id.
    """
    safe_name = sanitize_original_filename(original_filename)
    validate_extension(safe_name)
    validate_size(len(raw_bytes))

    stored_filename, _abs_path = save_evidence_file(raw_bytes, safe_name)

    import hashlib
    evidence_hash = hashlib.sha256(raw_bytes).hexdigest()

    investigation = Investigation(
        case_id=generate_case_id(),
        filename=stored_filename,
        original_filename=safe_name,
        evidence_hash_sha256=evidence_hash,
        file_size_bytes=len(raw_bytes),
        mime_type=mime_type or "message/rfc822",
        status="QUEUED",
        created_by=created_by,
        user_id=user_id,
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)

    # Logging without sensitive email content (per SECURITY requirements)
    logger.info("Investigation created: case_id=%s id=%s size=%d", investigation.case_id, investigation.id, len(raw_bytes))

    return investigation


def run_analysis(db: Session, investigation_id: str, raw_bytes: bytes) -> None:
    """Runs the full forensic + AI/ML + threat-intel + correlation +
    agent pipeline and persists every result. Progresses through real,
    granular processing_stage values so the frontend never shows fake
    progress:
        QUEUED -> FORENSIC_ANALYSIS -> AI_ANALYSIS -> THREAT_INTELLIGENCE
               -> CORRELATION -> AGENT_INVESTIGATION -> COMPLETED
    Safe to call from a FastAPI BackgroundTask. Never raises to the
    caller - failures are recorded on the investigation row with
    status=FAILED.
    """
    investigation = db.get(Investigation, investigation_id)
    if investigation is None:
        logger.error("run_analysis called for missing investigation_id=%s", investigation_id)
        return

    def _set_stage(stage: str):
        investigation.status = "PROCESSING"
        investigation.processing_stage = stage
        db.add(investigation)
        db.commit()

    _set_stage("FORENSIC_ANALYSIS")

    try:
        result = run_forensic_analysis(raw_bytes, trusted_domains=settings.TRUSTED_ORG_DOMAINS)

        # --- persist Phase 1 tables (unchanged from Phase 1) ---
        parsed = result.parsed_email
        db.add(EmailMetadata(
            investigation_id=investigation.id,
            from_address=parsed.from_address, from_display_name=parsed.from_display_name,
            to_addresses=parsed.to_addresses, cc_addresses=parsed.cc_addresses, bcc_addresses=parsed.bcc_addresses,
            subject=parsed.subject, date_raw=parsed.date_raw, date_parsed=parsed.date_parsed,
            reply_to=parsed.reply_to, return_path=parsed.return_path, message_id=parsed.message_id,
            mime_version=parsed.mime_version, content_type=parsed.content_type,
            x_mailer=parsed.x_mailer, user_agent=parsed.user_agent,
            sender_domain=parsed.sender_domain, reply_to_domain=parsed.reply_to_domain, return_path_domain=parsed.return_path_domain,
            attachments=[{"filename": a.filename, "content_type": a.content_type, "size_bytes": a.size_bytes, "sha256": a.sha256} for a in parsed.attachments],
        ))
        for idx, h in enumerate(parsed.raw_headers):
            db.add(EmailHeader(investigation_id=investigation.id, name=h["name"], value=h["value"], order_index=idx))
        for hop in result.received_hops:
            db.add(ReceivedHop(
                investigation_id=investigation.id, hop_index=hop.hop_index, raw_header=hop.raw_header,
                from_host=hop.from_host, by_host=hop.by_host, with_protocol=hop.with_protocol,
                ip_address=hop.ip_address, timestamp_raw=hop.timestamp_raw, timestamp_parsed=hop.timestamp_parsed,
            ))
        auth = result.authentication
        db.add(AuthenticationResult(
            investigation_id=investigation.id, spf_result=auth.spf.result, spf_domain=auth.spf.domain, spf_raw=auth.spf.raw,
            dkim_result=auth.dkim.result, dkim_domain=auth.dkim.domain, dkim_raw=auth.dkim.raw,
            dmarc_result=auth.dmarc.result, dmarc_policy=auth.dmarc_policy, dmarc_raw=auth.dmarc.raw,
            from_return_path_aligned=auth.from_return_path_aligned, from_reply_to_aligned=auth.from_reply_to_aligned,
            dkim_domain_aligned=auth.dkim_domain_aligned, dmarc_alignment_pass=auth.dmarc_alignment_pass,
            raw_authentication_results_header=auth.raw_authentication_results_header, source=auth.source,
        ))
        for u in result.url_findings:
            db.add(URLRecord(
                investigation_id=investigation.id, url=u.url, hostname=u.hostname, scheme=u.scheme,
                source_location=u.source_location, anchor_text=u.anchor_text, is_https=u.is_https, is_ip_based=u.is_ip_based,
                is_shortened=u.is_shortened, is_punycode=u.is_punycode, has_suspicious_tld=u.has_suspicious_tld,
                excessive_subdomains=u.excessive_subdomains, has_encoded_chars=u.has_encoded_chars,
                suspicious_query_params=u.suspicious_query_params, anchor_text_mismatch=u.anchor_text_mismatch,
                url_length=u.url_length, risk_score=u.risk_score, risk_reasons=u.risk_reasons,
            ))
        for d in result.domain_findings:
            db.add(DomainRecord(
                investigation_id=investigation.id, domain=d.domain, role=d.role, is_punycode=d.is_punycode,
                suspicious_tld=d.suspicious_tld, excessive_hyphenation=d.excessive_hyphenation,
                lookalike_of=d.lookalike_of, similarity_score=d.similarity_score, risk_score=d.risk_score, evidence=d.evidence,
            ))
        for ip in result.ip_findings:
            db.add(IPAddressRecord(investigation_id=investigation.id, ip_address=ip.ip_address, ip_version=ip.ip_version, source=ip.source, is_private=ip.is_private, hop_index=ip.hop_index))
        for ind in result.social_engineering_indicators:
            db.add(Indicator(investigation_id=investigation.id, indicator_type=ind.indicator_type, severity=ind.severity, matched_evidence=ind.matched_evidence, explanation=ind.explanation, confidence=ind.confidence))
        for f in result.header_findings:
            db.add(Finding(investigation_id=investigation.id, rule_id=f.rule_id, title=f.title, category=f.category, severity=f.severity, explanation=f.explanation, evidence=f.evidence, confidence=f.confidence))
        ts = result.threat_score
        db.add(RiskScoreBreakdown(
            investigation_id=investigation.id, overall_score=ts.overall_score, classification=ts.classification, confidence=ts.confidence,
            authentication_score=ts.dimensions["authentication"].score, header_score=ts.dimensions["header"].score,
            sender_identity_score=ts.dimensions["sender_identity"].score, domain_score=ts.dimensions["domain"].score,
            url_score=ts.dimensions["url"].score, social_engineering_score=ts.dimensions["social_engineering"].score,
            infrastructure_score=ts.dimensions["infrastructure"].score, weights_used=ts.weights_used, explanation=ts.explanation,
        ))
        db.commit()
        _log_audit(db, investigation.id, "FORENSIC_ANALYSIS_COMPLETE", f"score={ts.overall_score}")

        # =========================================================
        # PHASE 2: AI_ANALYSIS (ML + fusion)
        # =========================================================
        _set_stage("AI_ANALYSIS")
        fv = build_feature_vector(result)
        text_blob = feature_text_blob(result)
        struct_pred = get_structured_model().predict(fv)
        text_pred = get_text_model().predict(text_blob)

        # =========================================================
        # PHASE 2: THREAT_INTELLIGENCE
        # =========================================================
        _set_stage("THREAT_INTELLIGENCE")
        intel_summary = enrich_investigation(db, result)

        fusion = fuse(
            result, struct_pred, text_pred,
            threat_intel_score=intel_summary.aggregate_score,
            threat_intel_reasons=intel_summary.reasons,
        )

        db.add(MLPrediction(
            investigation_id=investigation.id,
            structured_available=struct_pred.available, structured_label=struct_pred.predicted_label,
            structured_confidence=struct_pred.confidence, structured_probabilities=struct_pred.class_probabilities,
            structured_model_version=struct_pred.model_metadata.model_version if struct_pred.model_metadata else None,
            structured_top_features=struct_pred.top_features,
            text_available=text_pred.available, text_label=text_pred.predicted_label,
            text_confidence=text_pred.confidence, text_probabilities=text_pred.class_probabilities,
            text_model_version=text_pred.model_metadata.model_version if text_pred.model_metadata else None,
            text_top_features=text_pred.top_features,
            feature_version=fv.version, feature_vector=fv.as_dict(),
            fused_overall_score=fusion.overall_risk_score, fused_classification=fusion.classification,
            fused_confidence=fusion.confidence, fused_breakdown=fusion.risk_breakdown, fused_reasons=fusion.reasons,
        ))
        db.add(ThreatIntelSummary(
            investigation_id=investigation.id, ip_results=intel_summary.ip_results, domain_results=intel_summary.domain_results,
            url_results=intel_summary.url_results, aggregate_score=intel_summary.aggregate_score,
            reasons=intel_summary.reasons, providers_used=intel_summary.providers_used,
        ))
        db.commit()

        # =========================================================
        # PHASE 2/3: CORRELATION (campaign + attack graph)
        # =========================================================
        _set_stage("CORRELATION")
        target_domains = {d.domain for d in result.domain_findings}
        target_ips = {ip.ip_address for ip in result.ip_findings}
        candidates = _build_campaign_candidates(db, exclude_id=investigation.id, user_id=investigation.user_id)
        campaign_matches = find_campaign_matches(target_domains, target_ips, text_blob, candidates)
        _persist_campaign_matches(db, investigation, campaign_matches)

        graph = build_attack_graph(result, investigation.case_id, fusion.overall_risk_score, fusion.classification)
        db.add(AttackGraph(investigation_id=investigation.id, graph_json=graph))

        attribution = assess_attribution(fusion.overall_risk_score, bool(target_domains or target_ips), campaign_matches)
        db.add(AttributionAssessment(
            investigation_id=investigation.id, level=attribution.level, level_label=attribution.level_label,
            detection_confidence=attribution.detection_confidence, infrastructure_confidence=attribution.infrastructure_confidence,
            campaign_confidence=attribution.campaign_confidence, attribution_confidence=attribution.attribution_confidence,
            explanation=attribution.explanation,
        ))
        db.commit()

        # =========================================================
        # PHASE 2/3: AGENT_INVESTIGATION
        # =========================================================
        _set_stage("AGENT_INVESTIGATION")
        agent_output = run_investigation_agent(result, fusion, intel_summary)
        for tool in agent_output.tool_calls:
            db.add(AgentActionLog(investigation_id=investigation.id, tool_name=tool, succeeded=True))
        for rec in agent_output.recommended_actions:
            db.add(ResponseRecommendation(
                investigation_id=investigation.id, action=rec["action"], severity=rec["severity"],
                reason=rec["reason"], requires_human_approval=rec.get("requires_human_approval", True),
            ))
        db.commit()

        # --- alerts for HIGH/CRITICAL ---
        reasons_list = result.threat_score.explanation.get("severity_reasons", [])
        top_reason = "; ".join(reasons_list[:2]) if reasons_list else (fusion.reasons[0] if fusion.reasons else "Elevated risk detected.")

        if fusion.classification in ("HIGH", "CRITICAL"):
            db.add(Alert(
                investigation_id=investigation.id,
                severity=fusion.classification,
                threat_score=fusion.overall_risk_score,
                classification=fusion.classification,
                key_reason=top_reason,
            ))
            db.commit()

        # --- finalize ---
        investigation.status = "COMPLETED"
        investigation.processing_stage = "COMPLETED"
        investigation.classification = fusion.classification
        investigation.risk_score = fusion.overall_risk_score
        investigation.confidence = fusion.confidence
        investigation.severity = fusion.classification
        investigation.analyzed_at = datetime.now(timezone.utc)

        # Update RiskScoreBreakdown to match authoritative fused score and full explanation
        if investigation.risk_score_breakdown:
            investigation.risk_score_breakdown.overall_score = fusion.overall_risk_score
            investigation.risk_score_breakdown.classification = fusion.classification
            investigation.risk_score_breakdown.confidence = fusion.confidence
            investigation.risk_score_breakdown.explanation = result.threat_score.explanation
            db.add(investigation.risk_score_breakdown)

        report_json = build_report_json(investigation, result, fusion, intel_summary, graph, attribution, campaign_matches, agent_output)
        db.add(Report(investigation_id=investigation.id, report_json=report_json))
        db.add(investigation)
        db.commit()

        # --- blockchain evidence anchor (Phase 3) ---
        from app.blockchain.ledger import canonical_report_hash
        report_hash = canonical_report_hash(report_json)
        anchor_evidence(db, investigation.case_id, investigation.evidence_hash_sha256, report_hash)
        _log_audit(db, investigation.id, "EVIDENCE_ANCHORED", f"report_hash={report_hash[:16]}...")

        logger.info("Analysis completed: case_id=%s score=%s classification=%s", investigation.case_id, fusion.overall_risk_score, fusion.classification)

    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Analysis failed for investigation_id=%s", investigation_id)
        investigation = db.get(Investigation, investigation_id)
        if investigation:
            investigation.status = "FAILED"
            investigation.processing_stage = "FAILED"
            investigation.error_message = f"{type(exc).__name__}: {exc}"
            db.add(investigation)
            db.commit()


def _log_audit(db: Session, investigation_id: str, action: str, detail: str = "") -> None:
    db.add(AuditLog(investigation_id=investigation_id, actor="system", action=action, detail=detail))
    db.commit()


def _build_campaign_candidates(db: Session, exclude_id: str, user_id: Optional[str] = None) -> list:
    """Only the SAME user's investigations are correlated (no cross-tenant leakage)."""
    candidates = []
    if not user_id:
        return candidates
    prior = (
        db.query(Investigation)
        .filter(
            Investigation.status == "COMPLETED",
            Investigation.id != exclude_id,
            Investigation.user_id == user_id,
        )
        .order_by(Investigation.created_at.desc())
        .limit(50)
        .all()
    )
    for inv in prior:
        domains = {d.domain for d in inv.domains}
        ips = {ip.ip_address for ip in inv.ip_addresses}
        text = f"{inv.email_metadata.subject if inv.email_metadata else ''}"
        candidates.append({"investigation_id": inv.id, "case_id": inv.case_id, "domains": domains, "ips": ips, "text": text})
    return candidates


def _persist_campaign_matches(db: Session, investigation: Investigation, matches: list) -> None:
    if not matches:
        return
    likely = [m for m in matches if m.relationship_label == "likely related"]
    if not likely:
        return
    # Reuse an existing campaign if any matched investigation already belongs to one, else create one.
    campaign = None
    for m in likely:
        other = db.get(Investigation, m.investigation_id)
        if other and other.campaign_id:
            campaign = db.get(Campaign, other.campaign_id)
            break
    if campaign is None:
        import uuid as _uuid
        campaign = Campaign(campaign_code=f"CAMPAIGN-{_uuid.uuid4().hex[:8].upper()}", name=f"Campaign related to {investigation.case_id}")
        db.add(campaign)
        db.commit()
        db.refresh(campaign)

    investigation.campaign_id = campaign.id
    db.add(CampaignMember(campaign_id=campaign.id, investigation_id=investigation.id, similarity_score=1.0, relationship_label="anchor", reasons=["This investigation."]))
    for m in likely:
        db.add(CampaignMember(campaign_id=campaign.id, investigation_id=m.investigation_id, similarity_score=m.similarity_score, relationship_label=m.relationship_label, reasons=m.reasons))
        other = db.get(Investigation, m.investigation_id)
        if other:
            other.campaign_id = campaign.id
            db.add(other)
    db.commit()


def build_report_json(investigation: Investigation, result, fusion=None, intel_summary=None, graph=None, attribution=None, campaign_matches=None, agent_output=None) -> dict:
    parsed = result.parsed_email
    return {
        "case_id": investigation.case_id,
        "investigation_id": investigation.id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "original_filename": investigation.original_filename,
            "sha256": investigation.evidence_hash_sha256,
            "size_bytes": investigation.file_size_bytes,
        },
        "email_summary": {
            "from": parsed.from_address,
            "from_display_name": parsed.from_display_name,
            "to": parsed.to_addresses,
            "subject": parsed.subject,
            "date": parsed.date_raw,
            "sender_domain": parsed.sender_domain,
        },
        "received_chain": {
            "hop_count": len(result.received_hops),
            "originating_infrastructure_note": result.originating_infrastructure_note,
            "hops": [
                {
                    "hop_index": h.hop_index, "from_host": h.from_host, "by_host": h.by_host,
                    "ip_address": h.ip_address, "timestamp": h.timestamp_raw,
                }
                for h in result.received_hops
            ],
        },
        "authentication": {
            "source": result.authentication.source,
            "spf": {"result": result.authentication.spf.result, "domain": result.authentication.spf.domain},
            "dkim": {"result": result.authentication.dkim.result, "domain": result.authentication.dkim.domain},
            "dmarc": {"result": result.authentication.dmarc.result, "policy": result.authentication.dmarc_policy},
            "alignment": {
                "from_return_path_aligned": result.authentication.from_return_path_aligned,
                "from_reply_to_aligned": result.authentication.from_reply_to_aligned,
                "dkim_domain_aligned": result.authentication.dkim_domain_aligned,
            },
        },
        "findings": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity, "explanation": f.explanation, "evidence": f.evidence, "confidence": f.confidence}
            for f in result.header_findings
        ],
        "urls": [
            {"url": u.url, "risk_score": u.risk_score, "risk_reasons": u.risk_reasons}
            for u in result.url_findings
        ],
        "domains": [
            {"domain": d.domain, "role": d.role, "risk_score": d.risk_score, "evidence": d.evidence}
            for d in result.domain_findings
        ],
        "ip_addresses": [
            {"ip_address": ip.ip_address, "source": ip.source, "is_private": ip.is_private}
            for ip in result.ip_findings
        ],
        "social_engineering_indicators": [
            {"type": i.indicator_type, "severity": i.severity, "evidence": i.matched_evidence, "explanation": i.explanation, "confidence": i.confidence}
            for i in result.social_engineering_indicators
        ],
        "threat_score": {
            "overall_score": result.threat_score.overall_score,
            "classification": result.threat_score.classification,
            "confidence": result.threat_score.confidence,
            "breakdown": result.threat_score.explanation["dimension_breakdown"],
        },
        "ai_ml_analysis": {
            "fused_overall_score": fusion.overall_risk_score if fusion else None,
            "fused_classification": fusion.classification if fusion else None,
            "fused_confidence": fusion.confidence if fusion else None,
            "reasons": fusion.reasons if fusion else [],
            "risk_breakdown": fusion.risk_breakdown if fusion else {},
        },
        "threat_intelligence": {
            "aggregate_score": intel_summary.aggregate_score if intel_summary else None,
            "providers_used": intel_summary.providers_used if intel_summary else [],
            "ip_results": intel_summary.ip_results if intel_summary else [],
            "domain_results": intel_summary.domain_results if intel_summary else [],
            "url_results": intel_summary.url_results if intel_summary else [],
        },
        "attack_graph_summary": {
            "node_count": graph.get("node_count") if graph else 0,
            "edge_count": graph.get("edge_count") if graph else 0,
        },
        "campaign_correlation": [
            {"case_id": m.case_id, "similarity_score": m.similarity_score, "relationship": m.relationship_label, "reasons": m.reasons}
            for m in (campaign_matches or [])
        ],
        "attribution": {
            "level": attribution.level if attribution else 0,
            "level_label": attribution.level_label if attribution else "Insufficient evidence",
            "detection_confidence": attribution.detection_confidence if attribution else 0,
            "infrastructure_confidence": attribution.infrastructure_confidence if attribution else 0,
            "campaign_confidence": attribution.campaign_confidence if attribution else 0,
            "attribution_confidence": attribution.attribution_confidence if attribution else 0,
            "explanation": attribution.explanation if attribution else [],
        },
        "ai_investigation_summary": {
            "classification": agent_output.classification if agent_output else None,
            "risk": agent_output.risk if agent_output else None,
            "key_findings": agent_output.key_findings if agent_output else [],
            "indicators": agent_output.indicators if agent_output else [],
            "infrastructure_assessment": agent_output.infrastructure_assessment if agent_output else "",
            "recommended_actions": agent_output.recommended_actions if agent_output else [],
            "limitations": agent_output.limitations if agent_output else [],
            "prompt_injection_detected": agent_output.prompt_injection_detected if agent_output else False,
        },
        "disclaimers": [
            "Received-chain infrastructure reflects the earliest OBSERVED hop in message headers, not a confirmed attacker location.",
            "IP addresses are not geolocated to a physical attacker location in Phase 1.",
            "No outbound requests were made to any URL found in this message during analysis.",
        ],
    }


def run_analysis_in_new_session(investigation_id: str, raw_bytes: bytes) -> None:
    """Background-task entry point: uses its OWN database session (the request's
    session is closed by the time a FastAPI background task runs)."""
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        run_analysis(db, investigation_id, raw_bytes)
    finally:
        db.close()


def analyze_email_for_user(raw_bytes: bytes, original_filename: str, user_id: str, created_by: str,
                           source: str = "UPLOAD") -> str:
    """Synchronous end-to-end analysis in a dedicated session. Returns investigation id.
    Used by the direct-analysis API and the real-time Gmail monitor."""
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        name = original_filename if original_filename.lower().endswith(".eml") else f"{original_filename}.eml"
        inv = create_investigation(db, raw_bytes, name, "message/rfc822", created_by=created_by, user_id=user_id)
        db.add(AuditLog(investigation_id=inv.id, actor=created_by or "system", action="EVIDENCE_ACQUIRED",
                        detail=f"source={source}"))
        db.commit()
        run_analysis(db, inv.id, raw_bytes)
        return inv.id
    finally:
        db.close()
