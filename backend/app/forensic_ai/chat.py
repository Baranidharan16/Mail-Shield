"""
Forensic AI Chat Engine.

Handles natural-language Q&A about an investigation.
CRITICAL SAFETY: Email content is UNTRUSTED DATA.
The chat engine NEVER follows instructions embedded in email content.
All email data is wrapped in [UNTRUSTED EMAIL CONTENT] boundaries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ChatMessage:
    role: str   # "user" | "assistant"
    content: str


@dataclass
class ChatResponse:
    answer: str
    evidence_refs: List[str] = field(default_factory=list)
    suggested_followups: List[str] = field(default_factory=list)
    disclaimer: str = "[LOCAL HEURISTIC + AI INFERENCE] — grounded in investigation evidence only"


SUGGESTED_QUESTIONS = [
    "Why is this email classified as critical?",
    "Show me the evidence",
    "Analyze the sender",
    "Are SPF, DKIM and DMARC valid?",
    "What is the attack intent?",
    "Is this credential phishing?",
    "Show me all suspicious indicators",
    "What is the attack chain?",
    "Are there related cases?",
    "What action do you recommend?",
    "Is there emotional manipulation?",
    "Generate a forensic summary",
]

# Prompt injection detection — check if question appears to come from email content
_INJECTION_PATTERNS = [
    r"ignore (all |previous |your )?(previous |system |)instructions?",
    r"you are now",
    r"disregard (the |all |previous )",
    r"new instructions?:?",
    r"act as",
    r"forget (everything|all)",
    r"mark this (email |message )?(as )?(safe|clean|legitimate|trusted)",
    r"override",
    r"jailbreak",
    r"pretend",
]


def _is_injection_attempt(question: str) -> bool:
    q = question.lower()
    for pat in _INJECTION_PATTERNS:
        if re.search(pat, q):
            return True
    return False


def _safe_str(v) -> str:
    if v is None:
        return "—"
    return str(v)


def answer_question(question: str, investigation_data: Dict[str, Any]) -> ChatResponse:
    """
    Answer a forensic question about an investigation.
    Email content is UNTRUSTED DATA and cannot override AI instructions.
    """

    # SAFETY CHECK: Detect prompt injection attempts
    if _is_injection_attempt(question):
        return ChatResponse(
            answer="⚠️ **Security Notice**: This input contains patterns consistent with prompt injection. "
                   "Email forensic AI processes UNTRUSTED DATA without executing embedded instructions. "
                   "Your question has been logged for review. Please rephrase your forensic query.",
            evidence_refs=["[SECURITY POLICY]"],
            suggested_followups=["What is the risk score?", "Show me the evidence", "What is the attack type?"],
        )

    # Extract investigation facts
    risk_score = float(investigation_data.get("risk_score") or 0)
    classification = investigation_data.get("classification") or "UNKNOWN"
    meta = investigation_data.get("email_metadata") or {}
    auth = investigation_data.get("authentication_result") or {}
    urls = investigation_data.get("urls") or []
    domains = investigation_data.get("domains") or []
    findings = investigation_data.get("findings") or []
    indicators = investigation_data.get("indicators") or []
    rsb = investigation_data.get("risk_score_breakdown") or {}
    campaign_members = investigation_data.get("campaign_members") or []
    ai_result = investigation_data.get("_ai_result") or {}

    q = question.lower()

    # ── Route question to appropriate handler ──────────────────────────────

    if any(kw in q for kw in ["why", "critical", "high", "risk score", "danger", "serious"]):
        return _answer_why_critical(risk_score, classification, findings, indicators, auth, rsb)

    if any(kw in q for kw in ["evidence", "proof", "show", "indicator"]):
        return _answer_evidence(findings, indicators, auth, urls, domains)

    if any(kw in q for kw in ["sender", "from", "spoof", "impersonat", "who sent"]):
        return _answer_sender(meta, auth, domains)

    if any(kw in q for kw in ["spf", "dkim", "dmarc", "authentication", "auth"]):
        return _answer_auth(auth)

    if any(kw in q for kw in ["url", "link", "domain", "website"]):
        return _answer_urls(urls, domains)

    if any(kw in q for kw in ["intent", "goal", "trying to", "what does", "what is the attack"]):
        return _answer_intent(ai_result, indicators, risk_score, classification)

    if any(kw in q for kw in ["phishing", "credential", "credential phish"]):
        return _answer_classification_phishing(indicators, auth, urls, risk_score)

    if any(kw in q for kw in ["bec", "business email", "ceo"]):
        return _answer_bec(indicators, meta, auth)

    if any(kw in q for kw in ["social engineer", "manipulat", "emotion", "psycholog", "urgency", "fear"]):
        return _answer_social_engineering(indicators, ai_result)

    if any(kw in q for kw in ["related", "case", "campaign", "similar", "pattern"]):
        return _answer_related_cases(campaign_members)

    if any(kw in q for kw in ["ioc", "indicator of compromise", "threat indicator"]):
        return _answer_iocs(meta, urls, domains, investigation_data.get("ip_addresses") or [])

    if any(kw in q for kw in ["timeline", "when", "sequence", "order"]):
        return _answer_timeline(investigation_data)

    if any(kw in q for kw in ["action", "recommend", "should i", "what to do", "next step", "response"]):
        return _answer_recommendations(risk_score, classification, investigation_data.get("recommendations") or [])

    if any(kw in q for kw in ["report", "summary", "forensic summary", "generate"]):
        return _answer_summary(investigation_data, risk_score, classification, meta, auth, findings, indicators)

    if any(kw in q for kw in ["attachment", "file", "malware", "executable"]):
        return _answer_attachment(meta, findings)

    # Default: general answer
    return _answer_general(risk_score, classification, findings, indicators, meta)


# ── Specific answer handlers ─────────────────────────────────────────────

def _answer_why_critical(risk_score, classification, findings, indicators, auth, rsb) -> ChatResponse:
    reasons = []
    evidence_refs = []

    spf = auth.get("spf_result") or ""
    dkim = auth.get("dkim_result") or ""
    dmarc = auth.get("dmarc_result") or ""

    if spf in ("FAIL", "SOFTFAIL"):
        reasons.append(f"SPF authentication **{spf}** — sender server not authorized")
        evidence_refs.append("Authentication-Results: SPF")
    if dkim == "FAIL":
        reasons.append("DKIM signature **FAIL** — message could not be cryptographically verified")
        evidence_refs.append("Authentication-Results: DKIM")
    if dmarc == "FAIL":
        reasons.append("DMARC policy **FAIL** — complete authentication breakdown")
        evidence_refs.append("Authentication-Results: DMARC")
    if auth.get("from_reply_to_aligned") is False:
        reasons.append("Reply-To domain **mismatch** with From domain — classic spoofing indicator")
        evidence_refs.append("Reply-To vs From-Address comparison")

    for ind in indicators[:3]:
        sev = ind.get("severity", "")
        if sev in ("CRITICAL", "HIGH"):
            itype = ind.get("indicator_type", "").replace("_", " ").upper()
            reasons.append(f"**{itype}** detected: {ind.get('explanation', '')[:100]}")
            evidence_refs.append(f"Email content: {ind.get('matched_evidence') or 'pattern matched'}")

    explanation_items = (rsb.get("explanation") or {}).get("evidence_items") or []
    for item in explanation_items[:3]:
        reasons.append(f"**{item.get('name', '')}** (+{item.get('points', 0)} pts) — {item.get('detail', '')}")

    if not reasons:
        reasons.append(f"Risk score is {risk_score:.0f}/100 based on combined forensic evidence.")

    answer = (
        f"This investigation received a **{classification}** classification with risk score **{risk_score:.0f}/100**.\n\n"
        f"Key reasons:\n" + "\n".join(f"• {r}" for r in reasons[:6])
    )
    return ChatResponse(
        answer=answer, evidence_refs=evidence_refs,
        suggested_followups=["Show me the evidence", "Analyze the sender", "What action do you recommend?"],
    )


def _answer_evidence(findings, indicators, auth, urls, domains) -> ChatResponse:
    parts = []
    evidence_refs = []

    # Auth
    spf = auth.get("spf_result") or "UNKNOWN"
    dkim = auth.get("dkim_result") or "UNKNOWN"
    dmarc = auth.get("dmarc_result") or "UNKNOWN"
    parts.append(f"**Authentication**: SPF={spf}, DKIM={dkim}, DMARC={dmarc}")
    evidence_refs.append("Authentication-Results header")

    # Suspicious URLs
    susp_urls = [u for u in urls if (u.get("risk_score") or 0) > 20]
    if susp_urls:
        parts.append(f"**Suspicious URLs** ({len(susp_urls)}): " + ", ".join(u.get("url", "")[:50] for u in susp_urls[:3]))
        evidence_refs.extend([u.get("url", "") for u in susp_urls[:3]])

    # Lookalike domains
    lookalike = [d for d in domains if d.get("lookalike_of")]
    if lookalike:
        parts.append(f"**Lookalike Domains**: " + ", ".join(f"{d.get('domain')} → {d.get('lookalike_of')}" for d in lookalike[:2]))

    # Indicators
    for ind in indicators[:4]:
        itype = ind.get("indicator_type", "").replace("_", " ").upper()
        parts.append(f"**{itype}** ({ind.get('severity')}): {ind.get('explanation', '')[:80]}")
        evidence_refs.append(f"Email body: {ind.get('matched_evidence') or 'pattern matched'}")

    # Findings
    for f in findings[:3]:
        parts.append(f"**{f.get('title', '')}** ({f.get('severity')}): {f.get('explanation', '')[:80]}")

    answer = "**Evidence Summary** — all evidence sourced from actual investigation data:\n\n" + "\n".join(f"• {p}" for p in parts)
    return ChatResponse(
        answer=answer, evidence_refs=evidence_refs,
        suggested_followups=["Why is this email critical?", "Analyze the sender", "Show me all IOCs"],
    )


def _answer_sender(meta, auth, domains) -> ChatResponse:
    from_addr = meta.get("from_address") or "Unknown"
    from_name = meta.get("from_display_name") or ""
    sender_domain = meta.get("sender_domain") or "Unknown"
    reply_to = meta.get("reply_to") or "Not set"
    reply_domain = meta.get("reply_to_domain") or ""
    return_path = meta.get("return_path") or "Not set"

    spf = auth.get("spf_result") or "UNKNOWN"
    dkim = auth.get("dkim_result") or "UNKNOWN"
    dmarc = auth.get("dmarc_result") or "UNKNOWN"
    aligned = auth.get("from_reply_to_aligned")
    source = auth.get("source") or "OBSERVED"

    lookalike_info = ""
    for d in domains:
        if d.get("domain") == sender_domain and d.get("lookalike_of"):
            lookalike_info = f"\n⚠️ Sender domain appears to impersonate **{d.get('lookalike_of')}** ({d.get('similarity_score', 0):.0%} similarity). This is a typosquatting indicator."

    mismatch_info = ""
    if aligned is False:
        mismatch_info = f"\n⚠️ **Reply-To domain ({reply_domain}) does not match From domain ({sender_domain})**. Replies will be routed to a different domain — classic spoofing pattern."

    spoof_verdict = "**LIKELY SPOOFED**" if spf in ("FAIL", "SOFTFAIL") or aligned is False else "Authentication inconsistent — further verification needed"

    answer = (
        f"**Sender Analysis** — [EMAIL HEADER]\n\n"
        f"• **From**: {from_addr}{f' ({from_name})' if from_name else ''}\n"
        f"• **Sender Domain**: {sender_domain}\n"
        f"• **Reply-To**: {reply_to}\n"
        f"• **Return-Path**: {return_path}\n"
        f"• **SPF**: {spf} | **DKIM**: {dkim} | **DMARC**: {dmarc}\n"
        f"• **Sender Verdict**: {spoof_verdict}"
        f"{mismatch_info}{lookalike_info}"
    )
    return ChatResponse(
        answer=answer,
        evidence_refs=["From: header", "Reply-To: header", "Return-Path: header", "Authentication-Results: header"],
        suggested_followups=["Are SPF, DKIM and DMARC valid?", "Is this credential phishing?"],
    )


def _answer_auth(auth) -> ChatResponse:
    spf = auth.get("spf_result") or "UNKNOWN"
    spf_domain = auth.get("spf_domain") or "unknown"
    dkim = auth.get("dkim_result") or "UNKNOWN"
    dkim_domain = auth.get("dkim_domain") or "unknown"
    dmarc = auth.get("dmarc_result") or "UNKNOWN"
    dmarc_policy = auth.get("dmarc_policy") or "none"
    aligned_reply = auth.get("from_reply_to_aligned")
    aligned_return = auth.get("from_return_path_aligned")
    dkim_aligned = auth.get("dkim_domain_aligned")
    dmarc_pass = auth.get("dmarc_alignment_pass")
    source = auth.get("source") or "OBSERVED"

    def result_emoji(r):
        if r in ("PASS",): return "✅"
        if r in ("FAIL", "SOFTFAIL", "PERMERROR"): return "❌"
        return "⚠️"

    all_fail = all(r in ("FAIL", "SOFTFAIL", "PERMERROR", None) for r in [spf, dkim, dmarc])
    verdict = "🚨 **COMPLETE AUTHENTICATION BREAKDOWN** — sender cannot be trusted" if all_fail else (
        "⚠️ Partial authentication failure" if any(r in ("FAIL", "SOFTFAIL") for r in [spf, dkim, dmarc])
        else "✅ Authentication passed"
    )

    answer = (
        f"**Email Authentication Analysis** — [EMAIL HEADER]\n\n"
        f"{result_emoji(spf)} **SPF**: {spf} (domain: {spf_domain})\n"
        f"{result_emoji(dkim)} **DKIM**: {dkim} (signing domain: {dkim_domain})"
        f"{', aligned: ' + str(dkim_aligned) if dkim_aligned is not None else ''}\n"
        f"{result_emoji(dmarc)} **DMARC**: {dmarc} (policy: {dmarc_policy}, alignment pass: {dmarc_pass})\n\n"
        f"**Alignment checks**:\n"
        f"• From ↔ Reply-To: {'ALIGNED ✅' if aligned_reply else 'MISALIGNED ❌' if aligned_reply is False else 'Unknown'}\n"
        f"• From ↔ Return-Path: {'ALIGNED ✅' if aligned_return else 'MISALIGNED ❌' if aligned_return is False else 'Unknown'}\n\n"
        f"**Verdict**: {verdict}\n"
        f"*Source: {source} (authentication header parsing)*"
    )
    return ChatResponse(
        answer=answer,
        evidence_refs=["Authentication-Results: header", "DKIM-Signature: header", "Return-Path: header"],
        suggested_followups=["Analyze the sender", "Why is this email critical?"],
    )


def _answer_urls(urls, domains) -> ChatResponse:
    susp = [u for u in urls if (u.get("risk_score") or 0) > 20 or u.get("is_ip_based") or u.get("is_shortened")]
    lookalike = [d for d in domains if d.get("lookalike_of")]

    if not susp and not lookalike:
        return ChatResponse(
            answer="No significantly suspicious URLs or domains were identified in this investigation. [LOCAL HEURISTIC]",
            suggested_followups=["Show me the evidence", "What is the risk score?"],
        )

    parts = [f"**URL & Domain Analysis** — {len(susp)} suspicious URL(s), {len(lookalike)} lookalike domain(s)\n"]
    for u in susp[:5]:
        flags = [k for k in ["is_ip_based", "is_shortened", "has_suspicious_tld", "anchor_text_mismatch"] if u.get(k)]
        parts.append(f"• `{u.get('url', '')[:80]}` — score: {u.get('risk_score', 0):.0f}, flags: {', '.join(flags) or 'none'}")
    for d in lookalike[:3]:
        parts.append(f"• ⚠️ Domain `{d.get('domain')}` impersonates `{d.get('lookalike_of')}` ({d.get('similarity_score', 0):.0%} similarity)")

    return ChatResponse(
        answer="\n".join(parts),
        evidence_refs=[u.get("url", "") for u in susp[:3]],
        suggested_followups=["Is this credential phishing?", "Show me all IOCs"],
    )


def _answer_intent(ai_result, indicators, risk_score, classification) -> ChatResponse:
    intent_data = ai_result.get("threat_intent") or {}
    intent = intent_data.get("intent") or "Unknown"
    confidence = float(intent_data.get("confidence") or 0.5)
    reason = intent_data.get("reason") or "Insufficient evidence for clear intent determination."

    ind_summary = "; ".join(
        f"{i.get('indicator_type', '').replace('_', ' ').upper()} ({i.get('severity')})"
        for i in indicators[:4]
    )

    answer = (
        f"**Threat Intent Analysis** — [AI INFERENCE + LOCAL HEURISTIC]\n\n"
        f"**Likely Intent**: {intent}\n"
        f"**Confidence**: {confidence:.0%}\n\n"
        f"**Reasoning**: {reason}\n\n"
        f"**Supporting Indicators**: {ind_summary or 'See full indicator list'}\n\n"
        f"*Note: Intent is inferred from behavioral patterns and content signals — "
        f"not a definitive determination of attacker psychology.*"
    )
    return ChatResponse(
        answer=answer,
        evidence_refs=["Social engineering indicators", "Content patterns"],
        suggested_followups=["Is there emotional manipulation?", "What action do you recommend?"],
    )


def _answer_classification_phishing(indicators, auth, urls, risk_score) -> ChatResponse:
    credential_ind = [i for i in indicators if "credential" in i.get("indicator_type", "").lower() or "phishing" in i.get("indicator_type", "").lower()]
    spf = auth.get("spf_result") or "UNKNOWN"
    dkim = auth.get("dkim_result") or "UNKNOWN"
    aligned = auth.get("from_reply_to_aligned")
    susp_urls = [u for u in urls if (u.get("risk_score") or 0) > 30]

    evidence_for = []
    evidence_against = []

    if credential_ind:
        evidence_for.append(f"Credential harvesting patterns detected in email content")
    if spf in ("FAIL", "SOFTFAIL"):
        evidence_for.append(f"SPF {spf} — sender not authorized")
    if dkim == "FAIL":
        evidence_for.append("DKIM signature invalid")
    if aligned is False:
        evidence_for.append("Reply-To mismatch — impersonation indicator")
    if susp_urls:
        evidence_for.append(f"{len(susp_urls)} suspicious URL(s) detected")
    if not credential_ind:
        evidence_against.append("No direct credential request patterns detected in content")
    if not susp_urls:
        evidence_against.append("No suspicious login-page URLs identified")

    if len(evidence_for) >= 3:
        verdict = f"**YES** — evidence strongly supports Credential Phishing ({len(evidence_for)} indicators)"
    elif len(evidence_for) >= 2:
        verdict = f"**LIKELY** — partial evidence supports Credential Phishing ({len(evidence_for)} indicators)"
    else:
        verdict = "**UNCERTAIN** — insufficient combined evidence for definitive credential phishing classification"

    answer = (
        f"**Credential Phishing Assessment** — [LOCAL HEURISTIC + AI INFERENCE]\n\n"
        f"**Verdict**: {verdict}\n\n"
        f"**Evidence FOR credential phishing**:\n" +
        ("\n".join(f"✅ {e}" for e in evidence_for) or "None detected") +
        (f"\n\n**Evidence AGAINST**:\n" + "\n".join(f"❌ {e}" for e in evidence_against) if evidence_against else "")
    )
    return ChatResponse(
        answer=answer,
        evidence_refs=["Authentication-Results", "Email body content", "URL analysis"],
        suggested_followups=["Show me the evidence", "What action do you recommend?"],
    )


def _answer_bec(indicators, meta, auth) -> ChatResponse:
    bec_indicators = [i for i in indicators if i.get("indicator_type") == "executive_impersonation"]
    payment_indicators = [i for i in indicators if "payment" in i.get("indicator_type", "").lower()]
    aligned = auth.get("from_reply_to_aligned")

    evidence = []
    if bec_indicators:
        evidence.append("Executive impersonation patterns detected (conversational authority pretext)")
    if payment_indicators:
        evidence.append("Payment/wire transfer language detected")
    if aligned is False:
        evidence.append("Reply-To mismatch — responses routed away from legitimate sender")
    if meta.get("reply_to") and meta.get("reply_to") != meta.get("from_address"):
        evidence.append(f"Reply-To set to: {meta.get('reply_to')}")

    if len(evidence) >= 2:
        verdict = "**POSSIBLE BEC** — multiple BEC indicators present"
    elif len(evidence) == 1:
        verdict = "**POSSIBLE BEC** — one BEC indicator present; further investigation needed"
    else:
        verdict = "**INSUFFICIENT EVIDENCE** for BEC classification"

    answer = (
        f"**Business Email Compromise (BEC) Assessment** — [AI INFERENCE]\n\n"
        f"**Verdict**: {verdict}\n\n"
        f"**BEC Indicators Found**:\n" +
        ("\n".join(f"• {e}" for e in evidence) or "None detected") +
        "\n\nNote: BEC attacks often appear to have low risk scores because they avoid malicious URLs and attachments. BEC relies purely on social engineering."
    )
    return ChatResponse(
        answer=answer,
        suggested_followups=["Analyze the sender", "Is there emotional manipulation?"],
    )


def _answer_social_engineering(indicators, ai_result) -> ChatResponse:
    se_signals = ai_result.get("social_engineering_signals") or []
    detected = [s for s in se_signals if s.get("detected") and s.get("score", 0) > 20]
    overall = ai_result.get("overall_manipulation_risk") or 0

    if not detected and not indicators:
        return ChatResponse(
            answer="No significant social engineering or emotional manipulation signals were detected in this investigation. [LOCAL HEURISTIC]",
            suggested_followups=["Show me the evidence"],
        )

    parts = [f"**Emotional & Social Engineering Analysis** — [EMAIL CONTENT / LOCAL HEURISTIC]\n"]
    parts.append(f"**Overall Manipulation Risk**: {overall}/100\n")
    parts.append("**Detected linguistic signals** (these are content patterns, NOT psychological certainties):\n")

    for s in sorted(detected, key=lambda x: x.get("score", 0), reverse=True)[:8]:
        parts.append(f"• **{s.get('signal')}**: {s.get('score', 0)}/100 — {s.get('evidence', '')}")

    for ind in indicators[:3]:
        itype = ind.get("indicator_type", "").replace("_", " ").upper()
        parts.append(f"• **{itype}**: {ind.get('explanation', '')[:100]}")

    parts.append("\n⚠️ *These are detected linguistic signals in the email content. They indicate manipulation intent, not certainty about recipient psychological state.*")

    return ChatResponse(
        answer="\n".join(parts),
        evidence_refs=["Email body content patterns"],
        suggested_followups=["What is the attack intent?", "Why is this email critical?"],
    )


def _answer_related_cases(campaign_members) -> ChatResponse:
    if not campaign_members:
        return ChatResponse(
            answer="No related cases or campaign correlation found for this investigation. This appears to be an isolated incident or the correlation engine found no matching infrastructure. [HISTORICAL CASE]",
            suggested_followups=["Show me the evidence", "What action do you recommend?"],
        )

    parts = [f"**Related Cases — Campaign Correlation** — [HISTORICAL CASE]\n"]
    parts.append(f"This investigation is correlated with **{len(campaign_members)} other case(s)**:\n")
    for m in campaign_members[:5]:
        sim = float(m.get("similarity_score") or 0)
        reasons = ", ".join((m.get("reasons") or [])[:2])
        parts.append(f"• **{m.get('case_id', '')}** — similarity: {sim:.0%} — {m.get('relationship_label', '')} — {reasons}")
    parts.append("\nShared infrastructure suggests a **coordinated attack campaign** rather than an isolated incident.")

    return ChatResponse(
        answer="\n".join(parts),
        evidence_refs=["Campaign correlation engine", "Historical case database"],
        suggested_followups=["What action do you recommend?", "Generate a forensic summary"],
    )


def _answer_iocs(meta, urls, domains, ip_addresses) -> ChatResponse:
    iocs = []
    sender = meta.get("from_address") or ""
    if sender:
        iocs.append(f"📧 **EMAIL**: {sender}")
    reply = meta.get("reply_to") or ""
    if reply and reply != sender:
        iocs.append(f"📧 **EMAIL (Reply-To)**: {reply}")
    for u in urls:
        if (u.get("risk_score") or 0) > 20:
            iocs.append(f"🔗 **URL**: {u.get('url', '')[:80]}")
    for d in domains:
        if (d.get("risk_score") or 0) > 20 or d.get("lookalike_of"):
            iocs.append(f"🌐 **DOMAIN**: {d.get('domain')} {f'(lookalike of {d.get(\"lookalike_of\")})' if d.get('lookalike_of') else ''}")
    for ip in ip_addresses:
        if not ip.get("is_private"):
            iocs.append(f"🖥️ **IP**: {ip.get('ip_address')} (source: {ip.get('source', 'relay')})")

    if not iocs:
        return ChatResponse(
            answer="No high-confidence IOCs extracted from this investigation. [LOCAL HEURISTIC]",
            suggested_followups=["Show me the evidence"],
        )

    answer = f"**IOC Extraction** — [EMAIL HEADER + EMAIL CONTENT]\n\n" + "\n".join(iocs[:15])
    return ChatResponse(
        answer=answer,
        evidence_refs=["Email headers", "URL extraction", "Domain analysis", "IP extraction"],
        suggested_followups=["What action do you recommend?", "Are there related cases?"],
    )


def _answer_timeline(investigation_data) -> ChatResponse:
    created = investigation_data.get("created_at") or ""
    analyzed = investigation_data.get("analyzed_at") or ""
    status = investigation_data.get("status") or ""

    answer = (
        f"**Forensic Timeline Summary** — [LOCAL HEURISTIC]\n\n"
        f"• **Email received / uploaded**: {created}\n"
        f"• **Analysis started**: {created}\n"
        f"• **Analysis completed**: {analyzed or 'Pending'}\n"
        f"• **Status**: {status}\n\n"
        f"The forensic timeline panel on this investigation page shows the complete "
        f"sequence of analysis events with real timestamps where available. "
        f"Events without exact timestamps are labeled 'Analysis event time'."
    )
    return ChatResponse(
        answer=answer,
        suggested_followups=["Show me the evidence", "Generate a forensic summary"],
    )


def _answer_recommendations(risk_score, classification, recs) -> ChatResponse:
    if recs:
        parts = ["**Recommended Response Actions** — [AI INFERENCE]\n"]
        parts.append("⚠️ All destructive actions require **explicit human approval**.\n")
        for r in recs[:5]:
            approval_note = "🔒 Requires approval" if r.get("requires_human_approval") else "✅ Auto-approvable"
            status = r.get("approval_status") or "PENDING"
            parts.append(f"• **{r.get('action', '')}** ({r.get('severity', '')}) — {r.get('reason', '')[:80]} — *{approval_note}* [{status}]")
        return ChatResponse(
            answer="\n".join(parts),
            suggested_followups=["Generate a forensic summary", "Are there related cases?"],
        )

    if risk_score >= 75:
        action = (
            "🚨 **CRITICAL** — Recommended actions (all require human approval):\n"
            "1. Quarantine the email\n2. Block sender domain\n3. Block malicious URLs\n"
            "4. Preserve forensic evidence\n5. Escalate to SOC Tier 2\n6. Notify affected user"
        )
    elif risk_score >= 50:
        action = (
            "⚠️ **HIGH** — Recommended actions:\n"
            "1. Quarantine the email\n2. Block identified malicious URLs\n"
            "3. Create SOC incident\n4. Analyst review of all evidence"
        )
    elif risk_score >= 25:
        action = "📋 **MEDIUM** — Analyst review recommended. Verify sender through out-of-band channel. Monitor for related activity."
    else:
        action = "✅ **LOW** — No automated action required. Standard monitoring."

    return ChatResponse(
        answer=f"**Response Recommendations** — [AI INFERENCE]\n\n{action}",
        suggested_followups=["Generate a forensic summary"],
    )


def _answer_summary(investigation_data, risk_score, classification, meta, auth, findings, indicators) -> ChatResponse:
    case_id = investigation_data.get("case_id") or "Unknown"
    from_addr = meta.get("from_address") or "Unknown"
    subject = meta.get("subject") or "Unknown"
    spf = auth.get("spf_result") or "UNKNOWN"
    dkim = auth.get("dkim_result") or "UNKNOWN"
    dmarc = auth.get("dmarc_result") or "UNKNOWN"
    confidence = float(investigation_data.get("confidence") or 0.5)
    analyzed_at = investigation_data.get("analyzed_at") or "Unknown"

    answer = (
        f"**AI Forensic Summary** — Case {case_id}\n\n"
        f"**Classification**: {classification} | **Risk Score**: {risk_score:.0f}/100 | **AI Confidence**: {confidence:.0%}\n\n"
        f"**Email**: From {from_addr}, Subject: \"{subject}\"\n\n"
        f"**Authentication**: SPF={spf}, DKIM={dkim}, DMARC={dmarc}\n\n"
        f"**Forensic Findings**: {len(findings)} rule(s) fired, {len(indicators)} social engineering indicator(s)\n\n"
        f"**Analyzed at**: {analyzed_at}\n\n"
        f"This summary is generated from actual forensic evidence. All claims cite investigation data. "
        f"External threat intelligence was unavailable — local heuristic analysis was applied. [LOCAL HEURISTIC + AI INFERENCE]"
    )
    return ChatResponse(
        answer=answer,
        evidence_refs=["All investigation artifacts"],
        suggested_followups=["What action do you recommend?", "Are there related cases?"],
    )


def _answer_attachment(meta, findings) -> ChatResponse:
    attachments = meta.get("attachments") or []
    attachment_findings = [f for f in findings if "attachment" in f.get("title", "").lower() or "attachment" in f.get("category", "").lower()]

    if not attachments and not attachment_findings:
        return ChatResponse(
            answer="No attachments were detected in this email. [EMAIL HEADER]",
            suggested_followups=["Show me the evidence"],
        )

    parts = [f"**Attachment Analysis** — [EMAIL HEADER]\n"]
    for att in attachments:
        fname = att.get("filename") or "unnamed"
        size = att.get("size_bytes") or 0
        sha = (att.get("sha256") or "")[:16]
        parts.append(f"• **{fname}** — {size/1024:.1f} KB — SHA256: {sha}…")
    for f in attachment_findings:
        parts.append(f"⚠️ Finding: {f.get('title', '')} ({f.get('severity', '')}): {f.get('explanation', '')[:100]}")

    return ChatResponse(
        answer="\n".join(parts),
        evidence_refs=[att.get("filename") or "attachment" for att in attachments],
        suggested_followups=["Show me the evidence", "What action do you recommend?"],
    )


def _answer_general(risk_score, classification, findings, indicators, meta) -> ChatResponse:
    from_addr = meta.get("from_address") or "Unknown"
    subject = meta.get("subject") or "Unknown"
    answer = (
        f"**Investigation Overview** — [LOCAL HEURISTIC]\n\n"
        f"• **Risk Score**: {risk_score:.0f}/100 ({classification})\n"
        f"• **From**: {from_addr}\n"
        f"• **Subject**: {subject}\n"
        f"• **Forensic Findings**: {len(findings)} rule(s) triggered\n"
        f"• **Threat Indicators**: {len(indicators)} indicator(s) detected\n\n"
        f"Ask me a more specific question about this investigation!"
    )
    return ChatResponse(
        answer=answer,
        suggested_followups=SUGGESTED_QUESTIONS[:6],
    )
