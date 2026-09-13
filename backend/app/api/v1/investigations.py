from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_caller
from app.core.config import get_settings
from app.database.session import get_db
from app.models.investigation import Investigation
from app.models.user import User
from app.schemas.investigation import (
    InvestigationCreateResponse,
    InvestigationDetail,
    InvestigationSummary,
)
from app.services import investigation_service
from app.utils.storage import FileTooLargeError, UnsupportedFileTypeError
from utils.auth_deps import get_optional_current_user


logger = logging.getLogger("forensic_platform")
settings = get_settings()

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.post("", response_model=InvestigationCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Upload a .eml file and create a new investigation (status=QUEUED).
    Automatically associates investigation with the authenticated user.
    """
    raw_bytes = await file.read()

    resolved_caller = current_user.email if current_user else caller
    resolved_user_id = current_user.id if current_user else None

    try:
        investigation = investigation_service.create_investigation(
            db,
            raw_bytes,
            file.filename or "upload.eml",
            file.content_type,
            created_by=resolved_caller,
            user_id=resolved_user_id,
        )
    except UnsupportedFileTypeError as exc:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(exc))
    except FileTooLargeError as exc:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc))
    except Exception:
        logger.exception("Failed to create investigation")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process uploaded file")

    # Kick off analysis in the background immediately (real-time processing requirement)
    background_tasks.add_task(investigation_service.run_analysis, db, investigation.id, raw_bytes)

    return InvestigationCreateResponse(
        id=investigation.id,
        case_id=investigation.case_id,
        status=investigation.status,
        message="Investigation created. Analysis has been queued.",
    )


def _check_investigation_access(investigation: Investigation, current_user: Optional[User]) -> None:
    """Strict user isolation: if an investigation is owned by a user, only that user may access it."""
    if investigation.user_id:
        if not current_user or current_user.id != investigation.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have permission to access this investigation.",
            )


@router.post("/{investigation_id}/analyze", response_model=InvestigationCreateResponse)
async def trigger_analyze(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Explicitly (re)triggers analysis for an existing investigation. Enforces user ownership."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    _check_investigation_access(investigation, current_user)

    from pathlib import Path
    storage_path = Path(settings.UPLOAD_STORAGE_DIR).resolve() / investigation.filename
    if not storage_path.exists():
        raise HTTPException(status_code=500, detail="Evidence file missing from storage")

    raw_bytes = storage_path.read_bytes()
    background_tasks.add_task(investigation_service.run_analysis, db, investigation.id, raw_bytes)

    return InvestigationCreateResponse(
        id=investigation.id, case_id=investigation.case_id, status="PROCESSING",
        message="Analysis (re)triggered.",
    )


@router.get("", response_model=List[InvestigationSummary])
def list_investigations(
    db: Session = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    limit = max(1, min(limit, 200))
    q = db.query(Investigation)

    if current_user:
        # User A only sees User A's investigations
        q = q.filter(Investigation.user_id == current_user.id)
    else:
        # Unauthenticated users only see public unassigned demo cases
        q = q.filter(Investigation.user_id.is_(None))

    rows = (
        q.order_by(Investigation.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows


@router.get("/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    _check_investigation_access(investigation, current_user)

    detail = InvestigationDetail.model_validate(investigation)

    # Enrich with real-time MailShield Keras ML & NLP predictions from trained models
    try:
        from services.ml_service import get_ml_service
        from services.nlp_service import get_nlp_service
        from pathlib import Path

        storage_path = Path(settings.UPLOAD_STORAGE_DIR).resolve() / investigation.filename
        text_content = ""
        if storage_path.exists():
            from services.email_parser import parse_eml_bytes
            parsed = parse_eml_bytes(storage_path.read_bytes())
            text_content = parsed.model_text
        elif investigation.email_metadata:
            text_content = f"{investigation.email_metadata.subject or ''}\n{investigation.email_metadata.from_address or ''}"

        if text_content:
            ml_res = get_ml_service().predict(text_content)
            nlp_res = get_nlp_service().predict(text_content)
            detail.ml_detection = ml_res.model_dump()
            detail.nlp_detection = nlp_res.model_dump()
    except Exception as e:
        logger.warning("Could not compute real-time ML/NLP for investigation detail: %s", e)

    return detail


@router.get("/{investigation_id}/findings")
def get_findings(
    investigation_id: str,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    return investigation.findings


@router.get("/{investigation_id}/indicators")
def get_indicators(
    investigation_id: str,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    return investigation.indicators


@router.get("/{investigation_id}/report")
def get_report(
    investigation_id: str,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if not investigation.report:
        raise HTTPException(status_code=409, detail=f"Report not yet available (status={investigation.status})")
    return investigation.report.report_json


@router.get("/{investigation_id}/graph")
def get_attack_graph(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if not investigation.attack_graph:
        raise HTTPException(status_code=409, detail=f"Graph not yet available (status={investigation.status})")
    return investigation.attack_graph.graph_json


@router.get("/{investigation_id}/campaign")
def get_campaign(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if not investigation.campaign_id:
        return {"campaign": None, "message": "No campaign relationship established for this investigation."}
    from app.models.investigation import Campaign
    campaign = db.get(Campaign, investigation.campaign_id)
    return {
        "campaign_code": campaign.campaign_code,
        "name": campaign.name,
        "members": [
            {"investigation_id": m.investigation_id, "case_id": db.get(Investigation, m.investigation_id).case_id,
             "similarity_score": m.similarity_score, "relationship_label": m.relationship_label, "reasons": m.reasons}
            for m in campaign.members
        ],
    }


@router.get("/{investigation_id}/attribution")
def get_attribution(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if not investigation.attribution_assessment:
        raise HTTPException(status_code=409, detail=f"Attribution not yet available (status={investigation.status})")
    a = investigation.attribution_assessment
    return {
        "level": a.level, "level_label": a.level_label,
        "detection_confidence": a.detection_confidence, "infrastructure_confidence": a.infrastructure_confidence,
        "campaign_confidence": a.campaign_confidence, "attribution_confidence": a.attribution_confidence,
        "explanation": a.explanation,
    }


@router.get("/{investigation_id}/recommendations")
def get_recommendations(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    from app.models.investigation import ResponseRecommendation
    recs = db.query(ResponseRecommendation).filter_by(investigation_id=investigation_id).all()
    return [
        {"id": r.id, "action": r.action, "severity": r.severity, "reason": r.reason,
         "requires_human_approval": r.requires_human_approval, "approval_status": r.approval_status}
        for r in recs
    ]


@router.post("/{investigation_id}/recommendations/{rec_id}/approve")
def approve_recommendation(
    investigation_id: str,
    rec_id: str,
    db: Session = Depends(get_db),
    caller: str | None = Depends(get_current_caller),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    from app.models.investigation import ResponseRecommendation
    rec = db.get(ResponseRecommendation, rec_id)
    if not rec or rec.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    inv = db.get(Investigation, investigation_id)
    if inv:
        _check_investigation_access(inv, current_user)
    from datetime import datetime, timezone
    rec.approval_status = "APPROVED"
    rec.approved_by = caller or "unauthenticated-operator"
    rec.approved_at = datetime.now(timezone.utc)
    db.add(rec)
    db.commit()
    return {"id": rec.id, "approval_status": rec.approval_status, "approved_by": rec.approved_by}


@router.get("/{investigation_id}/evidence/verify")
def verify_evidence(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    from app.blockchain.ledger import verify_evidence_for_case
    return verify_evidence_for_case(db, investigation.case_id, investigation.evidence_hash_sha256)


@router.get("/{investigation_id}/report/pdf")
def download_pdf_report(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Download a professional PDF forensic report."""
    from fastapi.responses import Response
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if not investigation.report:
        raise HTTPException(status_code=409, detail=f"Report not yet available (status={investigation.status})")
    try:
        from app.reports.pdf_report import generate_pdf_report
        pdf_bytes = generate_pdf_report(investigation.report.report_json)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{investigation.case_id}_forensic_report.pdf"'},
        )
    except Exception as exc:
        logger.exception("PDF generation failed for %s", investigation_id)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")


@router.get("/{investigation_id}/geo")
def get_geo_intelligence(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Returns GeoIP data for each public IP in the investigation.
    Results are labeled 'Probable infrastructure geolocation'.
    Never claim attacker location."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    from app.intel.providers import get_geoip_provider
    provider = get_geoip_provider()
    results = []
    for ip_rec in (investigation.ip_addresses or []):
        geo = provider.lookup_geo(ip_rec.ip_address)
        results.append({
            "ip_address": ip_rec.ip_address,
            "source": ip_rec.source,
            "hop_index": ip_rec.hop_index,
            "is_private": ip_rec.is_private,
            "geo": geo,
        })
    return {"investigation_id": investigation_id, "disclaimer": "Probable infrastructure geolocation — reflects observed relay infrastructure, NOT physical attacker location.", "results": results}


@router.get("/{investigation_id}/story")
def get_attack_story(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """AI-generated attack narrative built from actual investigation evidence.
    All claims cite real forensic findings — no fabrication."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if investigation.status != "COMPLETED":
        raise HTTPException(status_code=409, detail=f"Story not available yet (status={investigation.status})")

    meta = investigation.email_metadata
    auth = investigation.authentication_result
    rsb = investigation.risk_score_breakdown
    findings = investigation.findings or []
    urls = investigation.urls or []
    domains = investigation.domains or []
    indicators = investigation.indicators or []
    ml = investigation.ml_prediction
    attr = investigation.attribution_assessment
    campaign = investigation.campaign_id

    score = (ml.fused_overall_score if ml else None) or (rsb.overall_score if rsb else 0)
    cls = (ml.fused_classification if ml else None) or (rsb.classification if rsb else "UNKNOWN")

    steps = []

    # Step 1: Initial observation
    subject_str = f'"{meta.subject}"' if meta and meta.subject else "(no subject)"
    from_str = (meta.from_address or "unknown sender") if meta else "unknown sender"
    steps.append({"step": 1, "title": "Initial Observation",
        "narrative": f"A suspicious email was ingested for investigation. The email claimed to originate from {from_str} with subject {subject_str}. The system immediately queued it for forensic analysis."})

    # Step 2: Sender identity
    sender_domain = (meta.sender_domain or "unknown") if meta else "unknown"
    reply_domain = (meta.reply_to_domain or "") if meta else ""
    mismatch = auth and auth.from_reply_to_aligned is False
    steps.append({"step": 2, "title": "Sender Identity Analysis",
        "narrative": (f"The sender domain is '{sender_domain}'. " +
                      (f"The Reply-To domain '{reply_domain}' is misaligned with the From address — a strong indicator of spoofing or impersonation." if mismatch else
                       "Sender address alignment could not be fully verified — insufficient authentication header data."))})

    # Step 3: Authentication
    if auth:
        spf = auth.spf_result or "UNKNOWN"
        dkim = auth.dkim_result or "UNKNOWN"
        dmarc = auth.dmarc_result or "UNKNOWN"
        steps.append({"step": 3, "title": "Authentication Chain",
            "narrative": f"Email authentication results: SPF={spf}, DKIM={dkim}, DMARC={dmarc}. " +
            ("At least one authentication check failed — the email cannot be cryptographically verified as originating from the claimed domain." if any(r in ("FAIL", "NONE", "SOFTFAIL") for r in [spf, dkim, dmarc]) else
             "Authentication results appear consistent — though header injection remains a possibility.")})

    # Step 4: Infrastructure
    hops = investigation.received_hops or []
    ips = [ip.ip_address for ip in (investigation.ip_addresses or []) if not ip.is_private]
    if hops:
        hop_summary = f"{len(hops)} relay hop(s) observed in the Received chain."
        if ips:
            hop_summary += f" Public infrastructure IPs detected: {', '.join(ips[:3])}."
        steps.append({"step": 4, "title": "Infrastructure Relay Analysis",
            "narrative": hop_summary + " Note: relay IPs reflect observed mail infrastructure, not a confirmed attacker location."})

    # Step 5: Suspicious URLs
    high_risk_urls = [u for u in urls if (u.risk_score or 0) >= 50]
    if high_risk_urls:
        url_summary = f"{len(high_risk_urls)} high-risk URL(s) identified in the email body."
        sample = high_risk_urls[0]
        reasons = ", ".join((sample.risk_reasons or [])[:3])
        steps.append({"step": 5, "title": "Malicious URL Detection",
            "narrative": url_summary + (f" Example: '{sample.url[:80]}' — risk signals: {reasons}." if reasons else "")})

    # Step 6: Domain lookalike
    lookalike = [d for d in domains if d.lookalike_of]
    if lookalike:
        ld = lookalike[0]
        steps.append({"step": 6, "title": "Domain Impersonation",
            "narrative": f"Domain '{ld.domain}' appears to impersonate '{ld.lookalike_of}' with a similarity score of {(ld.similarity_score or 0):.0%}. This is a classic indicator of typosquatting or lookalike domain infrastructure."})

    # Step 7: Social engineering
    high_se = [i for i in indicators if i.severity in ("HIGH", "CRITICAL")]
    if high_se:
        types = ", ".join(set(i.indicator_type.replace("_", " ") for i in high_se[:3]))
        steps.append({"step": 7, "title": "Social Engineering Analysis",
            "narrative": f"The email body exhibits {len(high_se)} high-severity social-engineering pattern(s): {types}. These patterns are consistent with phishing or business email compromise tactics designed to create urgency or fear."})

    # Step 8: Campaign
    if campaign:
        steps.append({"step": 8, "title": "Campaign Correlation",
            "narrative": "This email has been correlated with other investigations sharing similar indicators — suggesting a coordinated attack campaign rather than an isolated incident. This increases the urgency of a broader organizational response."})

    # Step 9: Overall verdict
    verdict_text = {"CRITICAL": "extremely high", "HIGH": "high", "MEDIUM": "moderate", "LOW": "low"}.get(cls, "unknown")
    steps.append({"step": 9, "title": "Investigation Confidence & Verdict",
        "narrative": f"Based on {len(findings)} forensic findings, ML classification, and threat intelligence enrichment, the system assigns a {verdict_text} threat score of {score:.1f}/100 (classification: {cls}). " +
                     (f"Attribution confidence: level {attr.level}/6 ({attr.level_label})." if attr else "Attribution remains at base level — insufficient evidence for infrastructure attribution.")})

    # Step 10: Recommended response
    steps.append({"step": 10, "title": "Recommended Response",
        "narrative": ("Immediate action recommended: quarantine the email, block the identified domains and URLs, preserve evidence, and search for similar emails across the organization. All destructive actions require human analyst approval." if score >= 60 else
                      "Moderate action recommended: analyst review of findings, verify sender through out-of-band channel, and monitor for related activity.")})

    return {
        "investigation_id": investigation_id,
        "case_id": investigation.case_id,
        "classification": cls,
        "risk_score": score,
        "story_steps": steps,
        "disclaimer": "This narrative is generated from actual forensic findings and investigation data. It is an investigation-support tool, not a definitive legal conclusion.",
    }


@router.get("/{investigation_id}/whatif")
def get_whatif_analysis(investigation_id: str, db: Session = Depends(get_db)):
    """Counterfactual what-if analysis (Phase 3 Part 24).
    Recomputes risk score under hypothetical scenarios using the actual scoring engine.
    Clearly labeled as SIMULATED SCENARIO."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if not investigation.risk_score_breakdown:
        raise HTTPException(status_code=409, detail="Score not yet available")

    rsb = investigation.risk_score_breakdown
    auth = investigation.authentication_result
    baseline = rsb.overall_score

    import json as _json
    weights = rsb.weights_used or {}
    breakdown = rsb.explanation.get("dimension_breakdown", {}) if rsb.explanation else {}

    scenarios = []

    # Scenario 1: SPF passes
    spf_fails = auth and auth.spf_result in ("FAIL", "SOFTFAIL", "NONE")
    if spf_fails:
        auth_weight = weights.get("authentication", 0.25)
        current_auth_score = breakdown.get("authentication", {}).get("score", rsb.authentication_score)
        # Simulate SPF passing: reduce auth score by ~40%
        simulated_auth = max(0, current_auth_score * 0.6)
        delta = (simulated_auth - current_auth_score) * auth_weight
        simulated_total = max(0, min(100, baseline + delta))
        scenarios.append({
            "scenario": "SPF authentication passes",
            "description": f"If SPF alignment were valid (current: {auth.spf_result}), the authentication dimension score would decrease.",
            "baseline_score": round(baseline, 1),
            "simulated_score": round(simulated_total, 1),
            "delta": round(simulated_total - baseline, 1),
            "label": "SIMULATED SCENARIO — not a historical fact",
        })

    # Scenario 2: DMARC passes
    dmarc_fails = auth and auth.dmarc_result in ("FAIL", "NONE")
    if dmarc_fails:
        auth_weight = weights.get("authentication", 0.25)
        current_auth_score = breakdown.get("authentication", {}).get("score", rsb.authentication_score)
        simulated_auth = max(0, current_auth_score * 0.5)
        delta = (simulated_auth - current_auth_score) * auth_weight
        simulated_total = max(0, min(100, baseline + delta))
        scenarios.append({
            "scenario": "DMARC alignment valid",
            "description": f"If DMARC alignment were valid (current: {auth.dmarc_result}), the overall risk score would decrease significantly.",
            "baseline_score": round(baseline, 1),
            "simulated_score": round(simulated_total, 1),
            "delta": round(simulated_total - baseline, 1),
            "label": "SIMULATED SCENARIO — not a historical fact",
        })

    # Scenario 3: No suspicious URLs
    url_score = breakdown.get("url", {}).get("score", rsb.url_score)
    if url_score > 20:
        url_weight = weights.get("url", 0.15)
        delta = (0 - url_score) * url_weight
        simulated_total = max(0, min(100, baseline + delta))
        scenarios.append({
            "scenario": "No suspicious URLs present",
            "description": "If the email contained no suspicious URLs, the URL dimension score would be zero.",
            "baseline_score": round(baseline, 1),
            "simulated_score": round(simulated_total, 1),
            "delta": round(simulated_total - baseline, 1),
            "label": "SIMULATED SCENARIO — not a historical fact",
        })

    if not scenarios:
        scenarios.append({
            "scenario": "No meaningful counterfactual scenarios identified",
            "description": "The current evidence does not present clear binary counterfactual pivots for this investigation.",
            "baseline_score": round(baseline, 1),
            "simulated_score": round(baseline, 1),
            "delta": 0.0,
            "label": "SIMULATED SCENARIO",
        })

    return {
        "investigation_id": investigation_id,
        "baseline_score": round(baseline, 1),
        "baseline_classification": rsb.classification,
        "scenarios": scenarios,
        "disclaimer": "All scenarios are SIMULATED using the actual scoring model. They do not represent historical facts.",
    }


# ═══════════════════════════════════════════════════════════════════════════
# FORENSIC AI INTELLIGENCE LAYER — New endpoints (additive, no existing code changed)
# ═══════════════════════════════════════════════════════════════════════════

def _build_investigation_dict(investigation) -> dict:
    """Build a comprehensive dict from the ORM investigation object for the AI engine."""
    meta = investigation.email_metadata
    auth = investigation.authentication_result
    rsb = investigation.risk_score_breakdown

    return {
        "id": investigation.id,
        "case_id": investigation.case_id,
        "status": investigation.status,
        "classification": investigation.classification,
        "risk_score": investigation.risk_score,
        "confidence": investigation.confidence,
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        "analyzed_at": investigation.analyzed_at.isoformat() if investigation.analyzed_at else None,
        "email_metadata": {
            "from_address": meta.from_address if meta else None,
            "from_display_name": meta.from_display_name if meta else None,
            "to_addresses": meta.to_addresses if meta else None,
            "subject": meta.subject if meta else None,
            "date_raw": meta.date_raw if meta else None,
            "date_parsed": meta.date_parsed if meta else None,
            "reply_to": meta.reply_to if meta else None,
            "return_path": meta.return_path if meta else None,
            "message_id": meta.message_id if meta else None,
            "sender_domain": meta.sender_domain if meta else None,
            "reply_to_domain": meta.reply_to_domain if meta else None,
            "return_path_domain": meta.return_path_domain if meta else None,
            "attachments": [
                {"filename": a.filename, "content_type": a.content_type, "size_bytes": a.size_bytes, "sha256": a.sha256}
                for a in (meta.attachments if meta else [])
            ] if meta else [],
        } if meta else {},
        "authentication_result": {
            "spf_result": auth.spf_result if auth else None,
            "spf_domain": auth.spf_domain if auth else None,
            "dkim_result": auth.dkim_result if auth else None,
            "dkim_domain": auth.dkim_domain if auth else None,
            "dmarc_result": auth.dmarc_result if auth else None,
            "dmarc_policy": auth.dmarc_policy if auth else None,
            "from_return_path_aligned": auth.from_return_path_aligned if auth else None,
            "from_reply_to_aligned": auth.from_reply_to_aligned if auth else None,
            "dkim_domain_aligned": auth.dkim_domain_aligned if auth else None,
            "dmarc_alignment_pass": auth.dmarc_alignment_pass if auth else None,
            "raw_authentication_results_header": auth.raw_authentication_results_header if auth else None,
            "source": auth.source if auth else "UNKNOWN",
        } if auth else {},
        "urls": [
            {
                "url": u.url, "hostname": u.hostname, "risk_score": u.risk_score,
                "is_ip_based": u.is_ip_based, "is_shortened": u.is_shortened,
                "has_suspicious_tld": u.has_suspicious_tld, "anchor_text_mismatch": u.anchor_text_mismatch,
                "risk_reasons": u.risk_reasons or [],
            }
            for u in (investigation.urls or [])
        ],
        "domains": [
            {
                "domain": d.domain, "role": d.role, "risk_score": d.risk_score,
                "lookalike_of": d.lookalike_of, "similarity_score": d.similarity_score,
                "suspicious_tld": d.suspicious_tld, "is_punycode": d.is_punycode,
                "evidence": d.evidence or [],
            }
            for d in (investigation.domains or [])
        ],
        "ip_addresses": [
            {"ip_address": ip.ip_address, "source": ip.source, "is_private": ip.is_private, "hop_index": ip.hop_index}
            for ip in (investigation.ip_addresses or [])
        ],
        "findings": [
            {"rule_id": f.rule_id, "title": f.title, "category": f.category, "severity": f.severity, "explanation": f.explanation, "evidence": f.evidence or [], "confidence": f.confidence}
            for f in (investigation.findings or [])
        ],
        "indicators": [
            {"indicator_type": i.indicator_type, "severity": i.severity, "matched_evidence": i.matched_evidence, "explanation": i.explanation, "confidence": i.confidence}
            for i in (investigation.indicators or [])
        ],
        "received_hops": [
            {"hop_index": h.hop_index, "ip_address": h.ip_address, "from_host": h.from_host, "by_host": h.by_host, "timestamp_parsed": h.timestamp_parsed.isoformat() if h.timestamp_parsed else None}
            for h in (investigation.received_hops or [])
        ],
        "risk_score_breakdown": {
            "overall_score": rsb.overall_score if rsb else 0,
            "classification": rsb.classification if rsb else "LOW",
            "confidence": rsb.confidence if rsb else 0.5,
            "explanation": rsb.explanation if rsb else {},
        } if rsb else {},
        "campaign_members": [],  # populated below if campaign exists
        "evidence_hash_sha256": investigation.evidence_hash_sha256,
        "_body_text": "",  # body not stored in DB; content patterns come from indicators
    }


@router.get("/{investigation_id}/forensic-ai")
def get_forensic_ai_analysis(investigation_id: str, db: Session = Depends(get_db)):
    """
    FORENSIC AI INTELLIGENCE LAYER
    Returns full AI analysis: classification, intent, social-engineering signals,
    evidence reasoning cards, reasoning chain, attack chain, IOCs, conclusions.

    Safety: Email content treated as UNTRUSTED DATA — never executed as instructions.
    All conclusions cite actual investigation evidence.
    External threat intelligence unavailable — local heuristic analysis used.
    """
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    inv_dict = _build_investigation_dict(investigation)

    # Include campaign members for related case correlation
    if investigation.campaign_id:
        from app.models.investigation import Campaign
        campaign = db.get(Campaign, investigation.campaign_id)
        if campaign:
            inv_dict["campaign_members"] = [
                {
                    "investigation_id": m.investigation_id,
                    "case_id": (db.get(Investigation, m.investigation_id) or investigation).case_id,
                    "similarity_score": m.similarity_score,
                    "relationship_label": m.relationship_label,
                    "reasons": m.reasons or [],
                }
                for m in campaign.members
                if m.investigation_id != investigation_id
            ]

    from app.forensic_ai.engine import run_forensic_ai_analysis
    result = run_forensic_ai_analysis(inv_dict)

    def card_to_dict(c):
        return {
            "id": c.id, "name": c.name, "finding": c.finding,
            "severity": c.severity, "impact": c.impact, "source": c.source,
            "explanation": c.explanation, "risk_contribution": c.risk_contribution,
            "evidence_refs": c.evidence_refs,
        }

    def step_to_dict(s):
        return {
            "step": s.step, "label": s.label, "detail": s.detail,
            "evidence_ids": s.evidence_ids, "leads_to": s.leads_to,
        }

    def chain_to_dict(n):
        return {"position": n.position, "label": n.label, "detail": n.detail, "threat": n.threat}

    def se_to_dict(s):
        return {"signal": s.signal, "score": s.score, "detected": s.detected, "evidence": s.evidence, "label": s.label}

    return {
        "investigation_id": investigation_id,
        "case_id": investigation.case_id,
        "analysis_timestamp": result.analysis_timestamp,
        "artifacts_analyzed": result.artifacts_analyzed,
        "disclaimer": result.disclaimer,

        # Verdict
        "threat_severity": result.threat_severity,
        "risk_score": result.risk_score,
        "ai_confidence": result.ai_confidence,
        "evidence_strength": result.evidence_strength,

        # Classification
        "classification": {
            "primary": result.classification.primary,
            "secondary": result.classification.secondary,
            "confidence": result.classification.confidence,
        },

        # Intent
        "threat_intent": {
            "intent": result.threat_intent.intent,
            "confidence": result.threat_intent.confidence,
            "reason": result.threat_intent.reason,
        },

        # Social Engineering
        "social_engineering_signals": [se_to_dict(s) for s in result.social_engineering_signals],
        "overall_manipulation_risk": result.overall_manipulation_risk,

        # Evidence
        "evidence_cards": [card_to_dict(c) for c in result.evidence_cards],
        "reasoning_chain": [step_to_dict(s) for s in result.reasoning_chain],
        "attack_chain": [chain_to_dict(n) for n in result.attack_chain],

        # IOCs & Cases
        "iocs": result.iocs,
        "related_cases": result.related_cases,

        # Conclusions
        "forensic_conclusion": result.forensic_conclusion,
        "recommended_response": result.recommended_response,
    }


@router.post("/{investigation_id}/forensic-ai/chat")
def forensic_ai_chat(
    investigation_id: str,
    body: dict,
    db: Session = Depends(get_db),
):
    """
    FORENSIC AI CHAT
    Natural-language Q&A about the investigation.
    Email content is UNTRUSTED DATA — prompt injection is blocked.
    All answers reference actual investigation evidence.
    """
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    question = (body.get("question") or "").strip()
    if not question:
        from app.forensic_ai.chat import SUGGESTED_QUESTIONS
        return {"answer": "Please ask a forensic question about this investigation.", "suggested_followups": SUGGESTED_QUESTIONS[:6]}

    inv_dict = _build_investigation_dict(investigation)

    from app.forensic_ai.chat import answer_question, SUGGESTED_QUESTIONS
    response = answer_question(question, inv_dict)

    return {
        "question": question,
        "answer": response.answer,
        "evidence_refs": response.evidence_refs,
        "suggested_followups": response.suggested_followups,
        "disclaimer": response.disclaimer,
    }


@router.get("/{investigation_id}/forensic-ai/report")
def get_forensic_ai_report(investigation_id: str, db: Session = Depends(get_db)):
    """Comprehensive AI forensic report in JSON format."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    inv_dict = _build_investigation_dict(investigation)

    if investigation.campaign_id:
        from app.models.investigation import Campaign
        campaign = db.get(Campaign, investigation.campaign_id)
        if campaign:
            inv_dict["campaign_members"] = [
                {
                    "investigation_id": m.investigation_id,
                    "case_id": (db.get(Investigation, m.investigation_id) or investigation).case_id,
                    "similarity_score": m.similarity_score,
                    "relationship_label": m.relationship_label,
                    "reasons": m.reasons or [],
                }
                for m in campaign.members if m.investigation_id != investigation_id
            ]

    from app.forensic_ai.engine import run_forensic_ai_analysis
    result = run_forensic_ai_analysis(inv_dict)
    meta = inv_dict.get("email_metadata") or {}
    auth = inv_dict.get("authentication_result") or {}

    return {
        "report_type": "AI Forensic Investigation Report",
        "generated_at": result.analysis_timestamp,
        "case_id": investigation.case_id,
        "investigation_id": investigation_id,
        "status": investigation.status,
        "executive_summary": {
            "threat_severity": result.threat_severity,
            "primary_classification": result.classification.primary,
            "secondary_classifications": result.classification.secondary,
            "risk_score": result.risk_score,
            "ai_confidence": result.ai_confidence,
            "evidence_strength": result.evidence_strength,
            "forensic_conclusion": result.forensic_conclusion,
        },
        "sender_analysis": {
            "from_address": meta.get("from_address"),
            "display_name": meta.get("from_display_name"),
            "sender_domain": meta.get("sender_domain"),
            "reply_to": meta.get("reply_to"),
            "reply_to_domain": meta.get("reply_to_domain"),
            "return_path": meta.get("return_path"),
        },
        "header_analysis": {
            "spf": auth.get("spf_result"),
            "dkim": auth.get("dkim_result"),
            "dmarc": auth.get("dmarc_result"),
            "from_reply_to_aligned": auth.get("from_reply_to_aligned"),
            "from_return_path_aligned": auth.get("from_return_path_aligned"),
        },
        "threat_intent": {
            "intent": result.threat_intent.intent,
            "confidence": result.threat_intent.confidence,
            "reason": result.threat_intent.reason,
        },
        "social_engineering_analysis": {
            "overall_manipulation_risk": result.overall_manipulation_risk,
            "signals": [
                {"signal": s.signal, "score": s.score, "detected": s.detected, "evidence": s.evidence}
                for s in result.social_engineering_signals if s.detected
            ],
        },
        "evidence_reasoning": [
            {
                "id": c.id, "name": c.name, "finding": c.finding,
                "severity": c.severity, "impact": c.impact, "source": c.source,
                "explanation": c.explanation, "risk_contribution": c.risk_contribution,
            }
            for c in result.evidence_cards
        ],
        "attack_chain": [
            {"position": n.position, "label": n.label, "detail": n.detail, "threat": n.threat}
            for n in result.attack_chain
        ],
        "ioc_list": result.iocs,
        "related_cases": result.related_cases,
        "url_analysis": inv_dict.get("urls") or [],
        "domain_analysis": inv_dict.get("domains") or [],
        "attachment_analysis": meta.get("attachments") or [],
        "forensic_timeline_note": "See /investigations/{id}/timeline for full forensic timeline.",
        "evidence_integrity": {
            "sha256": investigation.evidence_hash_sha256,
            "case_id": investigation.case_id,
        },
        "recommended_response": result.recommended_response,
        "ai_recommendation": "Human analyst approval required for all destructive actions.",
        "disclaimer": result.disclaimer,
    }


@router.get("/{investigation_id}/forensic-ai/suggested-questions")
def get_suggested_questions(investigation_id: str, db: Session = Depends(get_db)):
    """Return suggested forensic chat questions for this investigation."""
    from app.forensic_ai.chat import SUGGESTED_QUESTIONS
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"suggested_questions": SUGGESTED_QUESTIONS, "investigation_id": investigation_id}


# ── MailShield AI Agent — Gemini Reasoning + Sarvam 22-Language Voice Engine ─

from pydantic import BaseModel as _BaseModel
from typing import Optional as _Optional

class AgentChatRequest(_BaseModel):
    question: str
    language_code: _Optional[str] = "en-IN"
    language_name: _Optional[str] = None


class AgentVoiceRequest(_BaseModel):
    text: str
    voice: str = "priya"
    language: str = "en-IN"


@router.post("/{investigation_id}/agent/chat")
async def agent_chat(
    investigation_id: str,
    body: AgentChatRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Ask MailShield AI a forensic question about a specific investigation.
    The full forensic context (risk score, findings, auth, URLs, domains) is
    injected into the prompt so the model answers are grounded in evidence.
    Supports multilingual answers across 22 Indian languages.
    """
    from app.forensic_ai.openai_agent import ask_openai
    from app.schemas.investigation import InvestigationDetail

    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)
    if investigation.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="Analysis not yet complete. Please wait for the investigation to finish.")

    # Serialise the investigation ORM model to a plain dict for the AI context
    try:
        inv_schema = InvestigationDetail.model_validate(investigation)
        inv_dict = inv_schema.model_dump()
    except Exception:
        inv_dict = {
            "case_id": investigation.case_id,
            "risk_score": investigation.risk_score,
            "classification": investigation.classification,
            "status": investigation.status,
        }

    result = await ask_openai(
        question=body.question,
        investigation=inv_dict,
        language_code=body.language_code,
        language_name=body.language_name,
    )
    return result


@router.post("/{investigation_id}/agent/voice")
async def agent_voice(
    investigation_id: str,
    body: AgentVoiceRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Convert a forensic AI answer to speech using Sarvam AI TTS (bulbul:v3).
    Supports all 22 Indian languages. Returns base64-encoded WAV audio.
    """
    from app.forensic_ai.sarvam_tts import synthesize_speech

    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)

    result = await synthesize_speech(body.text, voice=body.voice, language=body.language)
    return result


@router.post("/{investigation_id}/agent/transcribe")
async def agent_transcribe(
    investigation_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Transcribe spoken voice query to text using Sarvam AI STT (saaras:v3).
    Analyzes spoken audio, transcribes it, and detects the spoken language
    across 22 Indian languages.
    """
    from app.forensic_ai.sarvam_tts import transcribe_speech

    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)

    audio_bytes = await file.read()
    if not audio_bytes:
        raise HTTPException(status_code=400, detail="Audio recording is empty.")

    result = await transcribe_speech(
        audio_bytes=audio_bytes,
        filename=file.filename or "recording.wav",
        content_type=file.content_type or "audio/wav",
    )
    return result


@router.get("/{investigation_id}/origin-trace")
def get_investigation_origin_trace(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    SIH 26106 LAYER 3: ORIGIN TRACEABILITY ENGINE
    Reconstructs email transmission path across Received headers, detects relay
    anomalies (timestamp inversions, duplicate hops), isolates the EARLIEST
    RELIABLE OBSERVABLE SENDING NODE, and computes infrastructure confidence.
    Adheres strictly to forensic evidentiary guidelines: never claims physical attacker location.
    """
    from dataclasses import asdict
    from app.forensic.origin_tracer import analyze_origin_trace
    from app.intel.providers import get_geoip_provider

    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    _check_investigation_access(investigation, current_user)

    # Reconstruct hop dictionaries
    hops_data = []
    for h in (investigation.received_hops or []):
        hops_data.append({
            "hop_index": h.hop_index,
            "raw_header": h.raw_header,
            "from_host": h.from_host or "",
            "by_host": h.by_host or "",
            "with_protocol": h.with_protocol or "SMTP",
            "ip_address": h.ip_address or "",
            "timestamp_raw": h.timestamp_raw or "",
            "timestamp_parsed": h.timestamp_parsed.isoformat() if h.timestamp_parsed else None,
        })

    # Collect GeoIP lookup for public IPs
    provider = get_geoip_provider()
    geo_results = []
    for ip_rec in (investigation.ip_addresses or []):
        geo = provider.lookup_geo(ip_rec.ip_address)
        geo_results.append({
            "ip_address": ip_rec.ip_address,
            "geo": geo,
        })

    trace_result = analyze_origin_trace(hops_data, geo_results)
    return asdict(trace_result)

