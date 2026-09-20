"""
MailShield - Email Analysis API Routes
Provides /api/analyze-email and /api/analyze-raw with automatic end-to-end execution:
Email Parser -> Keras ML Model -> Keras NLP Model -> Forensic Analyzer -> Risk Engine -> MailShield AI
"""
from __future__ import annotations

import logging
from typing import Optional
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from schemas.analysis import (
    EmailAnalysisResponse,
    EmailMetadata,
    MLAnalysisResult,
    NLPAnalysisResult,
    RawEmailRequest,
    RiskResult,
)
from services.email_parser import ParsedEmailData, parse_eml_bytes
from services.forensic_service import analyze_forensics
from services.gemini_service import get_reasoning_provider
from services.ml_service import get_ml_service
from services.nlp_service import get_nlp_service
from services.risk_engine import calculate_risk_score
from utils.auth_deps import get_optional_current_user
from utils.text_processing import clean_text_for_model, extract_domain, extract_urls

logger = logging.getLogger("mailshield.routes.analysis")

router = APIRouter(tags=["Analysis"])


def _nlp_from_indicators(indicators) -> NLPAnalysisResult:
    """Category scores = strongest matched social-engineering pattern per category
    (rule/pattern based, each backed by a matched phrase stored as evidence).
    Covers all indicator_type values emitted by social_engineering.py."""
    best = {}
    for i in indicators or []:
        best[i.indicator_type] = max(best.get(i.indicator_type, 0.0), float(i.confidence or 0.0))
    g = lambda *k: round(max([best.get(x, 0.0) for x in k] + [0.0]), 4)  # noqa: E731
    return NLPAnalysisResult(
        # urgency indicator_type emitted directly as "urgency"
        urgency=g("urgency"),
        # credential_harvesting + aliases
        credential_request=g(
            "credential_request", "credential_harvesting",
            "account_verification", "password_reset_pressure",
            "phishing_social_engineering",
        ),
        # payment_fraud / invoice fraud maps to financial_manipulation
        financial_manipulation=g(
            "financial_manipulation", "payment_fraud",
            "payment_request", "invoice_payment_diversion",
        ),
        # executive_impersonation is the forensic indicator type
        impersonation=g("impersonation", "executive_impersonation"),
        # explicit threats, blackmail, extortion, harassment map to threat_language
        threat_language=g(
            "threat_language", "fear_threat",
            "explicit_threat", "blackmail_extortion", "harassment_intimidation",
        ),
        # suspicious call-to-action indicator
        suspicious_action=g("suspicious_action", "suspicious_call_to_action", "spam_bulk"),
    )


async def _process_analysis(
    parsed: ParsedEmailData,
    current_user: Optional[User] = None,
    db: Optional[Session] = None,
    filename: Optional[str] = None,
    source: str = "UPLOAD",
) -> EmailAnalysisResponse:
    """
    Runs the ONE canonical MailShield pipeline (same as uploads and the real-time
    Gmail monitor): forensic engine -> ML (structured) -> NLP (text) -> rule engine ->
    threat intel -> fusion -> correlation -> forensic agent -> report -> ledger anchor.
    The investigation is stored under the authenticated user; this response is a
    summary view of those stored results.
    """
    from starlette.concurrency import run_in_threadpool
    from app.models.investigation import Investigation
    from app.services.investigation_service import analyze_email_for_user

    if current_user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    raw = parsed.raw_bytes or b""
    if not raw.strip():
        raise HTTPException(status_code=400, detail="The email is empty.")

    inv_id = await run_in_threadpool(
        analyze_email_for_user, raw, filename or f"analysis_{uuid.uuid4().hex[:8]}.eml",
        current_user.id, current_user.email, source,
    )
    db.expire_all()
    inv = db.get(Investigation, inv_id)
    if inv is None or inv.status != "COMPLETED":
        detail = (inv.error_message if inv else None) or "Analysis failed."
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {detail}")

    mlp = inv.ml_prediction
    p_struct = float((mlp.structured_probabilities or {}).get("PHISHING", 0.0)) if (mlp and mlp.structured_available) else None
    p_text = float((mlp.text_probabilities or {}).get("PHISHING", 0.0)) if (mlp and mlp.text_available) else None
    p = p_struct if p_struct is not None else (p_text if p_text is not None else 0.0)
    label = "phishing" if (mlp and "PHISHING" in (mlp.structured_label, mlp.text_label)) else "legitimate"
    ml_result = MLAnalysisResult(prediction=label, phishing_probability=round(p, 4),
                                 confidence=round(max(p, 1 - p), 4))
    # Rule-based indicator fallback (weakest priority)
    nlp_result = _nlp_from_indicators(inv.indicators)

    # ── Second-priority: use Keras NLP outputs already stored in the investigation
    # by _keras_panel_outputs() during analysis (so we always surface the trained
    # model scores even if the NLP service is not in-memory at response time).
    stored_keras = (mlp.fused_breakdown or {}).get("mailshield_keras_models", {}) if mlp else {}
    stored_nlp = stored_keras.get("nlp")
    if stored_nlp and isinstance(stored_nlp, dict):
        try:
            nlp_result = NLPAnalysisResult(
                urgency=float(stored_nlp.get("urgency", nlp_result.urgency)),
                credential_request=float(stored_nlp.get("credential_request", nlp_result.credential_request)),
                financial_manipulation=float(stored_nlp.get("financial_manipulation", nlp_result.financial_manipulation)),
                impersonation=float(stored_nlp.get("impersonation", nlp_result.impersonation)),
                threat_language=float(stored_nlp.get("threat_language", nlp_result.threat_language)),
                suspicious_action=float(stored_nlp.get("suspicious_action", nlp_result.suspicious_action)),
            )
            logger.debug("NLP panel: loaded from stored keras outputs (investigation %s)", inv.id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not deserialize stored NLP keras outputs: %s", exc)

    # ── First-priority: live inference from the in-memory NLP model (most accurate)
    model_text = getattr(parsed, "model_text", None) or ""
    ml_svc, nlp_svc = get_ml_service(), get_nlp_service()
    if ml_svc.is_loaded():
        try:
            ml_result = ml_svc.predict(model_text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Keras ML panel fell back to structured model: %s", exc)
    if nlp_svc.is_loaded():
        try:
            nlp_result = nlp_svc.predict(model_text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Keras NLP panel fell back to stored/rule indicators: %s", exc)
    forensics_result = analyze_forensics(parsed)
    risk_result = RiskResult(
        score=int(round(inv.risk_score or 0)),
        level=inv.classification or "LOW",
        contributing_factors=list((mlp.fused_reasons if mlp else None) or [])[:10],
    )
    m = inv.email_metadata
    email_meta = EmailMetadata(
        subject=(m.subject if m else parsed.subject) or "",
        sender=(m.from_address if m else parsed.from_header) or "",
        sender_domain=(m.sender_domain if m else parsed.sender_domain) or "",
        reply_to=(m.reply_to if m else parsed.reply_to) or "",
        reply_to_domain=(m.reply_to_domain if m else parsed.reply_to_domain) or "",
        date=(m.date_raw if m else parsed.date) or "",
        message_id=(m.message_id if m else parsed.message_id) or "",
    )
    ai_reasoning = await get_reasoning_provider().generate_explanation(
        email=email_meta, ml=ml_result, nlp=nlp_result, forensics=forensics_result, risk=risk_result,
    )
    return EmailAnalysisResponse(
        analysis_id=inv.id, email=email_meta, ml=ml_result, nlp=nlp_result,
        forensics=forensics_result, risk=risk_result, ai_reasoning=ai_reasoning,
    )


def _compose_rfc822(subject: str, sender: str, reply_to: str, body: str) -> bytes:
    """Wrap pasted text in a minimal RFC 822 message so the forensic engine can run.
    Headers are exactly what the user supplied — nothing is invented."""
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    if sender:
        msg["From"] = sender
    if reply_to and reply_to != sender:
        msg["Reply-To"] = reply_to
    msg["X-MailShield-Source"] = "pasted-text (no transport headers available)"
    msg.set_content(body)
    return bytes(msg)


@router.post("/api/analyze-email", response_model=EmailAnalysisResponse)
@router.post("/api/v1/analyze-email", response_model=EmailAnalysisResponse)
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    reply_to: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Analyzes an uploaded .eml file or raw email content through MailShield.
    Automatically runs ML inference, NLP classification, forensics, and AI reasoning.
    Saves the investigation under the authenticated user.
    """
    try:
        if file is not None:
            content_bytes = await file.read()
            if not content_bytes:
                raise HTTPException(status_code=400, detail="Uploaded file is empty.")
            parsed = parse_eml_bytes(content_bytes)
            return await _process_analysis(parsed, current_user=current_user, db=db,
                                           filename=file.filename or "upload.eml", source="UPLOAD")

        elif raw_text and raw_text.strip():
            sub = subject or "Manual Text Submission"
            sender_hdr = sender or ""
            reply_hdr = reply_to or sender_hdr
            sender_dom = extract_domain(sender_hdr)
            reply_dom = extract_domain(reply_hdr)
            clean_body = clean_text_for_model(raw_text)
            urls = extract_urls(clean_body)
            model_text = f"{sub}\n{clean_body}".strip()

            parsed = ParsedEmailData(
                from_header=sender_hdr,
                to_header="recipient@local.host",
                cc_header="",
                reply_to=reply_hdr,
                subject=sub,
                date="",
                message_id=str(uuid.uuid4()),
                sender_domain=sender_dom,
                reply_to_domain=reply_dom,
                plain_text_body=raw_text,
                html_body="",
                combined_body=raw_text,
                model_text=model_text,
                urls=urls,
                attachments=[],
                attachment_filenames=[],
                received_headers_raw=[],
                authentication_results_raw=[],
                dkim_signatures_raw=[],
                raw_headers={},
                raw_bytes=_compose_rfc822(sub, sender_hdr, reply_hdr, raw_text),
            )
            return await _process_analysis(parsed, current_user=current_user, db=db,
                                           filename="pasted_text.eml", source="PASTED_TEXT")

        else:
            raise HTTPException(
                status_code=400,
                detail="Either an .eml file or raw email text must be provided."
            )

    except HTTPException:
        raise
    except Exception as exc:
        # Log the FULL traceback so the exact upstream error (e.g. Keras shape
        # mismatch, preprocessing failure) is always visible in development logs.
        logger.exception("Unexpected error during email analysis pipeline: %s", exc)
        raise HTTPException(status_code=500, detail="Analysis pipeline error. Please try again.")


@router.post("/api/analyze-raw", response_model=EmailAnalysisResponse)
async def analyze_raw_json(
    payload: RawEmailRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """Accepts a JSON payload with raw email text for analysis."""
    return await analyze_email(
        file=None,
        raw_text=payload.body,
        subject=payload.subject,
        sender=payload.sender,
        reply_to=payload.reply_to,
        db=db,
        current_user=current_user,
    )

