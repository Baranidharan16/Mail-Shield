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
    RawEmailRequest,
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


async def _process_analysis(
    parsed: ParsedEmailData,
    current_user: Optional[User] = None,
    db: Optional[Session] = None,
) -> EmailAnalysisResponse:
    """Executes the complete MailShield forensic & AI pipeline and records user investigation."""
    analysis_id = str(uuid.uuid4())

    # 1. Run ML Phishing Detection Model (mailshield_ml.keras)
    ml_service = get_ml_service()
    if not ml_service.is_loaded():
        logger.warning("ML Service was not loaded; attempting lazy load.")
        ml_service.load()
    ml_result = ml_service.predict(parsed.model_text)

    # 2. Run NLP Threat-Pattern Model (mailshield_nlp.keras)
    nlp_service = get_nlp_service()
    if not nlp_service.is_loaded():
        logger.warning("NLP Service was not loaded; attempting lazy load.")
        nlp_service.load()
    nlp_result = nlp_service.predict(parsed.model_text)

    # 3. Run Forensic Analyzer
    forensics_result = analyze_forensics(parsed)

    # 4. Calculate Deterministic Risk Score (0-100)
    risk_result = calculate_risk_score(ml_result, nlp_result, forensics_result)

    # 5. Format Metadata
    email_meta = EmailMetadata(
        subject=parsed.subject,
        sender=parsed.from_header,
        sender_domain=parsed.sender_domain,
        reply_to=parsed.reply_to,
        reply_to_domain=parsed.reply_to_domain,
        date=parsed.date,
        message_id=parsed.message_id,
    )

    # 6. Generate AI Reasoning via MailShield AI (Gemini with Fallback)
    reasoning_provider = get_reasoning_provider()
    ai_reasoning = await reasoning_provider.generate_explanation(
        email=email_meta,
        ml=ml_result,
        nlp=nlp_result,
        forensics=forensics_result,
        risk=risk_result,
    )

    # Persist investigation into SQLite database linked to current user
    if db is not None:
        try:
            from app.models.investigation import (
                Investigation,
                EmailMetadata as DBEmailMeta,
                MLPrediction as DBMLPred,
                Report as DBReport,
            )
            from app.utils.storage import generate_case_id
            import hashlib

            evidence_hash = hashlib.sha256(parsed.raw_bytes).hexdigest() if parsed.raw_bytes else str(uuid.uuid4())
            user_id = current_user.id if current_user else None
            cls_val = getattr(risk_result, "level", "LOW")
            r_score = float(getattr(risk_result, "score", getattr(risk_result, "risk_score", 0)))

            inv = Investigation(
                id=analysis_id,
                case_id=generate_case_id(),
                filename=f"email_{analysis_id[:8]}.eml",
                original_filename=(parsed.subject[:80] or "email_analysis.eml"),
                evidence_hash_sha256=evidence_hash,
                file_size_bytes=len(parsed.raw_bytes) if parsed.raw_bytes else 1024,
                status="COMPLETED",
                classification=cls_val,
                risk_score=r_score,
                confidence=float(ml_result.confidence),
                created_by=current_user.email if current_user else "anonymous",
                user_id=user_id,
                analyzed_at=datetime.now(timezone.utc),
            )
            db.add(inv)

            # Record Email Metadata
            db_meta = DBEmailMeta(
                investigation_id=analysis_id,
                from_address=parsed.from_header,
                subject=parsed.subject,
                sender_domain=parsed.sender_domain,
                reply_to=parsed.reply_to,
                reply_to_domain=parsed.reply_to_domain,
                date_raw=parsed.date,
                message_id=parsed.message_id,
            )
            db.add(db_meta)

            # Record ML Prediction
            ml_lbl = ml_result.prediction.value if hasattr(ml_result.prediction, "value") else str(ml_result.prediction)
            db_ml = DBMLPred(
                investigation_id=analysis_id,
                text_available=True,
                text_label=ml_lbl,
                text_confidence=float(ml_result.confidence),
                text_probabilities={"phishing": float(ml_result.phishing_probability)},
                text_model_version="mailshield_keras_v1",
                fused_overall_score=r_score,
                fused_classification=cls_val,
                fused_confidence=float(ml_result.confidence),
            )
            db.add(db_ml)

            # Record AI Reasoning Report
            db_report = DBReport(
                investigation_id=analysis_id,
                report_json=ai_reasoning.model_dump() if hasattr(ai_reasoning, "model_dump") else {"summary": ai_reasoning.summary},
            )
            db.add(db_report)

            db.commit()
            logger.info("Investigation %s saved to DB for user %s", analysis_id, user_id)
        except Exception as save_err:
            logger.warning("Could not persist analysis to DB: %s", save_err)
            db.rollback()

    return EmailAnalysisResponse(
        analysis_id=analysis_id,
        email=email_meta,
        ml=ml_result,
        nlp=nlp_result,
        forensics=forensics_result,
        risk=risk_result,
        ai_reasoning=ai_reasoning,
    )


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
            return await _process_analysis(parsed, current_user=current_user, db=db)

        elif raw_text and raw_text.strip():
            sub = subject or "Manual Text Submission"
            sender_hdr = sender or "unknown@local.host"
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
                raw_bytes=raw_text.encode("utf-8"),
            )
            return await _process_analysis(parsed, current_user=current_user, db=db)

        else:
            raise HTTPException(
                status_code=400,
                detail="Either an .eml file or raw email text must be provided."
            )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error during email analysis: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis pipeline error: {str(exc)}"
        )


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

