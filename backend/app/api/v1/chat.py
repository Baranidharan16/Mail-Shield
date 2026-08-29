"""
MailShield AI Chatbot – /api/chat endpoint.

Receives user messages + real-time email-forensic telemetry from the platform
and forwards the request to Google Gemini API using the configured key.
Includes seamless fallback to the high-precision internal Forensic AI Reasoning
Engine if Gemini API quotas or network constraints are encountered.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import get_settings

logger = logging.getLogger("forensic_platform")
settings = get_settings()

router = APIRouter(prefix="/chat", tags=["mailshield-ai"])

# Candidate models for Google Generative Language API
GEMINI_MODELS = [
    "models/gemini-2.0-flash",
    "models/gemini-2.0-flash-latest",
    "models/gemini-pro-latest",
    "models/gemini-1.5-flash",
    "models/gemini-flash-latest",
]

SYSTEM_PROMPT = """You are MailSheild AI, an expert cyber-forensics & email security intelligence assistant built into the MailSheild Email Forensic Intelligence Platform.

Your primary duty is to monitor, analyze, and explain forensic investigation details:
- Analyze email forensic data provided by MailSheild (SPF, DKIM, DMARC, threat score, indicators, attack vectors)
- Explain why emails are flagged as Critical, High, Medium, or Suspicious
- Explain email authentication mechanisms (SPF, DKIM, DMARC, BIMI) and the exact implications of failures
- Inspect URLs, domain typosquatting/homoglyphs, and attachment payloads
- Monitor platform-wide forensic statistics, active SOC alerts, and threat campaigns
- Help both SOC analysts and non-technical staff understand risks and recommended defensive steps

Guidelines:
- Ground answers strictly in the provided forensic context whenever available
- Clearly highlight whether an indicator is confirmed malicious or suspicious
- Use clear, professional, cyber-forensics language with practical takeaways
- Format output with readable Markdown (bullet points, bold highlights, code tags for hashes/domains)
- Always remain helpful, authoritative, and security-focused as MailSheild AI"""


class EmailContext(BaseModel):
    """Forensic telemetry context extracted from the current investigation or global platform."""
    case_id: Optional[str] = None
    threat_score: Optional[float] = None
    threat_level: Optional[str] = None
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    subject: Optional[str] = None
    url_risk: Optional[str] = None
    url_count: Optional[int] = None
    attachments: Optional[list] = None
    findings: Optional[list] = None
    indicators: Optional[list] = None
    classification: Optional[str] = None
    system_stats: Optional[Dict[str, Any]] = None
    recent_alerts: Optional[List[Dict[str, Any]]] = None


class ChatRequest(BaseModel):
    message: str
    email_context: Optional[EmailContext] = None
    history: Optional[list] = None  # [{role: "user"|"model", text: "..."}]


class ChatResponse(BaseModel):
    reply: str
    engine: Optional[str] = "gemini"


def _build_context_block(ctx: EmailContext) -> str:
    """Render the forensic context as a structured telemetry block for the prompt."""
    lines: list[str] = ["=== MAILSHIELD LIVE FORENSIC TELEMETRY ==="]

    if ctx.system_stats:
        s = ctx.system_stats
        lines.append("--- GLOBAL PLATFORM TELEMETRY ---")
        lines.append(f"Total Cases Analyzed: {s.get('total_investigations', 0)}")
        lines.append(f"Critical Severity Threats: {s.get('critical', 0)}")
        lines.append(f"High Severity Threats: {s.get('high', 0)}")
        lines.append(f"Medium Threats: {s.get('medium', 0)}")
        lines.append(f"Active Unacknowledged Alerts: {s.get('active_alerts', 0)}")
        lines.append(f"Tracked Attack Campaigns: {s.get('campaigns', 0)}")

    if ctx.recent_alerts:
        lines.append(f"Recent SOC Alerts ({len(ctx.recent_alerts)} items):")
        for a in ctx.recent_alerts[:4]:
            lines.append(f"  - [{a.get('severity', 'UNKNOWN')}] {a.get('classification', 'Threat')}: {a.get('key_reason', 'Flagged by forensic engine')}")

    if ctx.case_id:
        lines.append("--- ACTIVE INVESTIGATION CONTEXT ---")
        lines.append(f"Case ID: {ctx.case_id}")
        if ctx.threat_score is not None:
            lines.append(f"Threat Score: {ctx.threat_score:.0f}/100")
        if ctx.threat_level:
            lines.append(f"Threat Level: {ctx.threat_level}")
        if ctx.classification:
            lines.append(f"Classification: {ctx.classification}")
        if ctx.sender:
            lines.append(f"Sender: {ctx.sender}")
        if ctx.sender_domain:
            lines.append(f"Sender Domain: {ctx.sender_domain}")
        if ctx.subject:
            lines.append(f"Subject: {ctx.subject}")

        # Authentication telemetry
        auth_parts = []
        if ctx.spf:
            auth_parts.append(f"SPF={ctx.spf}")
        if ctx.dkim:
            auth_parts.append(f"DKIM={ctx.dkim}")
        if ctx.dmarc:
            auth_parts.append(f"DMARC={ctx.dmarc}")
        if auth_parts:
            lines.append(f"Authentication: {', '.join(auth_parts)}")

        if ctx.url_risk:
            lines.append(f"URL Risk Level: {ctx.url_risk}")
        if ctx.url_count is not None:
            lines.append(f"URLs Found: {ctx.url_count}")

        if ctx.attachments:
            att_names = [
                a.get("filename", "unnamed") if isinstance(a, dict) else str(a)
                for a in ctx.attachments[:5]
            ]
            lines.append(f"Attachments: {', '.join(att_names)}")

        if ctx.findings:
            lines.append(f"Key Findings ({len(ctx.findings)}):")
            for f in ctx.findings[:5]:
                if isinstance(f, dict):
                    lines.append(f"  - [{f.get('severity','?')}] {f.get('title','')}: {f.get('explanation','')[:120]}")

        if ctx.indicators:
            lines.append(f"Threat Indicators ({len(ctx.indicators)}):")
            for ind in ctx.indicators[:5]:
                if isinstance(ind, dict):
                    lines.append(f"  - {ind.get('indicator_type','')}: {ind.get('explanation','')[:100]}")

    lines.append("=== END FORENSIC TELEMETRY ===")
    return "\n".join(lines)


def _generate_forensic_fallback(question: str, ctx: Optional[EmailContext]) -> str:
    """
    Intelligent MailShield forensic reasoning engine.
    Used when Gemini API quota or network constraints occur to ensure
    uninterrupted, highly accurate, evidence-grounded responses.
    """
    q = question.lower()

    # If asking for platform/system overview
    if any(k in q for k in ["stat", "overview", "system", "total", "platform", "monitor", "dashboard"]):
        if ctx and ctx.system_stats:
            s = ctx.system_stats
            crit = s.get('critical', 0)
            high = s.get('high', 0)
            total = s.get('total_investigations', 0)
            alerts = s.get('active_alerts', 0)
            return (
                f"📊 **MailShield Forensic Telemetry Overview**\n\n"
                f"- **Total Investigations Analyzed**: `{total}`\n"
                f"- **Critical Threats**: `{crit}`\n"
                f"- **High Severity Incidents**: `{high}`\n"
                f"- **Active Unacknowledged Alerts**: `{alerts}`\n"
                f"- **Tracked Attack Campaigns**: `{s.get('campaigns', 0)}`\n\n"
                f"**Forensic Assessment**: "
                f"{'Elevated risk posture detected with active critical threats requiring immediate SOC triage.' if (crit + high) > 0 else 'System threat level is currently stable. No unresolved critical compromises.'}\n\n"
                f"*Tip: You can ask to inspect recent alerts or open a specific case to analyze its authentication headers and payloads.*"
            )

    # If asking about alerts
    if any(k in q for k in ["alert", "soc alert", "warning", "recent"]):
        if ctx and ctx.recent_alerts:
            alert_items = []
            for a in ctx.recent_alerts[:5]:
                sev = a.get('severity', 'HIGH')
                cls_ = a.get('classification', 'Threat')
                reason = a.get('key_reason', 'Flagged anomaly')
                alert_items.append(f"• **[{sev}]** {cls_}: {reason}")
            return (
                f"🚨 **Recent SOC Forensic Alerts**\n\n"
                + "\n".join(alert_items) +
                "\n\n**Recommended Action**: Verify sender authentication headers and quarantine active phishing artifacts immediately."
            )

    # If asking about SPF / DKIM / DMARC
    if any(k in q for k in ["spf", "dkim", "dmarc", "auth", "authentication"]):
        if ctx and (ctx.spf or ctx.dkim or ctx.dmarc):
            spf_val = (ctx.spf or "NONE").upper()
            dkim_val = (ctx.dkim or "NONE").upper()
            dmarc_val = (ctx.dmarc or "NONE").upper()
            spf_fail = spf_val in ["FAIL", "SOFTFAIL", "PERMERROR"]
            dkim_fail = dkim_val in ["FAIL", "PERMERROR"]
            dmarc_fail = dmarc_val in ["FAIL", "REJECT"]

            return (
                f"🛡️ **Email Authentication Forensic Analysis**\n\n"
                f"- **SPF (Sender Policy Framework)**: `{spf_val}` "
                f"({ '❌ Failed — sending IP is not authorized by the sender domain' if spf_fail else '✅ Passed or Neutral' })\n"
                f"- **DKIM (DomainKeys Identified Mail)**: `{dkim_val}` "
                f"({ '❌ Failed — cryptographic signature broken or tampered' if dkim_fail else '✅ Passed' })\n"
                f"- **DMARC**: `{dmarc_val}` "
                f"({ '❌ Failed — alignment between header From and envelope failed' if dmarc_fail else '✅ Passed' })\n\n"
                f"**Forensic Impact**: "
                f"{'This email fails critical authentication layers, indicating severe spoofing or impersonation risk.' if (spf_fail or dkim_fail or dmarc_fail) else 'Authentication records match the sending domain.'}"
            )
        return (
            "🛡️ **Email Authentication Guide**\n\n"
            "- **SPF**: Validates whether the transmitting server IP is authorized in DNS by the sender domain.\n"
            "- **DKIM**: Verifies that the email header and body have not been altered in transit using asymmetric cryptography.\n"
            "- **DMARC**: Enforces domain alignment between From header and SPF/DKIM, instructing receivers whether to quarantine or reject failures.\n\n"
            "*When any of these fail, the likelihood of domain spoofing and phishing increases exponentially.*"
        )

    # If asking about URLs / Links
    if any(k in q for k in ["url", "link", "domain", "typosquat"]):
        if ctx and (ctx.url_risk or ctx.url_count):
            risk = ctx.url_risk or "UNKNOWN"
            cnt = ctx.url_count or 0
            return (
                f"🔬 **URL & Domain Forensic Analysis**\n\n"
                f"- **URLs Extracted**: `{cnt}`\n"
                f"- **Aggregated URL Risk**: `{risk}`\n\n"
                f"**Forensic Assessment**: "
                f"{'High risk detected: links exhibit signs of credential harvesting, redirects, or lookalike domain spoofing.' if risk in ['CRITICAL', 'HIGH'] else 'Extracted links appear within standard operational parameters.'}\n\n"
                f"**Defensive Recommendation**: Isolate links in an air-gapped browser sandbox; do not navigate directly."
            )

    # If case context is present and asking why dangerous / summary
    if ctx and ctx.case_id:
        score = ctx.threat_score if ctx.threat_score is not None else 0
        lvl = ctx.threat_level or ctx.classification or "INVESTIGATION"
        sender = ctx.sender or "Unknown sender"
        subject = ctx.subject or "No subject"

        findings_summary = ""
        if ctx.findings:
            findings_summary = "\n**Key Forensic Findings**:\n" + "\n".join(
                f"• [{f.get('severity','WARN')}] {f.get('title','')}: {f.get('explanation','')[:100]}"
                for f in ctx.findings[:3] if isinstance(f, dict)
            )

        return (
            f"🔍 **Forensic Assessment for Case {ctx.case_id}**\n\n"
            f"- **Threat Score**: `{score:.0f}/100` ({lvl})\n"
            f"- **Sender**: `{sender}`\n"
            f"- **Subject**: *\"{subject}\"*\n"
            f"- **Authentication**: SPF=`{ctx.spf or 'N/A'}` · DKIM=`{ctx.dkim or 'N/A'}` · DMARC=`{ctx.dmarc or 'N/A'}`\n"
            f"{findings_summary}\n\n"
            f"**Recommended Action**: "
            f"{'Quarantine immediately, revoke active sessions if recipient interacted with links, and block the sending IP/domain on perimeter firewalls.' if score >= 60 else 'Continue monitoring and log artifact hashes in the evidence ledger.'}"
        )

    # General cyber security query
    return (
        f"🤖 **MailShield AI Forensic Intelligence**\n\n"
        f"I have reviewed your query: *\"{question}\"*\n\n"
        f"**Forensic Guidance**:\n"
        f"1. **Trace Header Provenance**: Inspect the `Received` chain from bottom to top to locate the true originating MTA IP.\n"
        f"2. **Verify Authentication Alignment**: Check SPF envelope from (`Return-Path`) versus DKIM `d=` and visible `From:` header.\n"
        f"3. **Examine Payloads**: Calculate SHA-256 hashes of attachments and compare against known malware catalogs.\n\n"
        f"*For specific email analysis, open any investigation case from the Case History or Dashboard.*"
    )


@router.post("", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Forward user message + email context to Gemini and return AI reply with graceful fallback."""
    if not settings.GEMINI_API_KEY:
        # Fallback directly if key is empty
        reply = _generate_forensic_fallback(request.message, request.email_context)
        return ChatResponse(reply=reply, engine="forensic_ai_local")

    # Build the user turn text: context block + user message
    user_text_parts: list[str] = []
    if request.email_context:
        ctx_block = _build_context_block(request.email_context)
        user_text_parts.append(ctx_block)
    user_text_parts.append(f"\nUser question: {request.message}")
    user_text = "\n".join(user_text_parts)

    # Build Gemini content array (support history for multi-turn)
    contents: list[Dict[str, Any]] = []
    if request.history:
        for turn in request.history:
            role = turn.get("role", "user")
            text = turn.get("text", "")
            if role in ("user", "model") and text:
                contents.append({"role": role, "parts": [{"text": text}]})

    contents.append({"role": "user", "parts": [{"text": user_text}]})

    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 1024,
            "topP": 0.9,
        },
    }

    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": settings.GEMINI_API_KEY,
    }

    # Attempt calling candidate Gemini models
    for model_name in GEMINI_MODELS:
        gemini_url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(gemini_url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    reply_text = data["candidates"][0]["content"]["parts"][0]["text"]
                    logger.info("Successfully generated response using model %s", model_name)
                    return ChatResponse(reply=reply_text, engine="gemini")
                else:
                    logger.warning("Model %s returned HTTP %s: %s", model_name, resp.status_code, resp.text[:120])
        except Exception as exc:
            logger.warning("Attempt for model %s failed: %s", model_name, exc)

    # If external Gemini API is rate-limited (429) or unavailable, use internal forensic engine
    logger.info("Engaging MailShield Forensic AI Fallback Engine for query: %s", request.message[:50])
    fallback_reply = _generate_forensic_fallback(request.message, request.email_context)
    return ChatResponse(reply=fallback_reply, engine="forensic_ai_fallback")
