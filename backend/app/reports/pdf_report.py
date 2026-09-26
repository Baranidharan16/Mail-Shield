"""
Professional PDF forensic report generator (Phase 3 Part 18).
Uses fpdf2. Never embeds raw email body content.
Follows the forensic report structure defined in the Phase 3 brief.
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fpdf import FPDF, XPos, YPos


class ForensicReportPDF(FPDF):
    """Custom PDF class with header/footer branding."""

    _case_id: str = ""

    def normalize_text(self, text):
        # Core PDF fonts are latin-1 only; map em-dashes, arrows, bullets etc.
        # instead of crashing (previously any "—"/"↔" made PDF export fail).
        return super().normalize_text(_s(text, 100_000))

    def multi_cell(self, *args, **kwargs):
        # fpdf2 defaults multi_cell to new_x=RIGHT, which leaves the cursor at the
        # right margin and makes the NEXT multi_cell raise "Not enough horizontal
        # space". Default to a normal line break instead.
        kwargs.setdefault("new_x", XPos.LMARGIN)
        kwargs.setdefault("new_y", YPos.NEXT)
        return super().multi_cell(*args, **kwargs)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_fill_color(10, 13, 16)
        self.set_text_color(61, 220, 151)
        self.cell(0, 10, "MAILSHEILD — AI Email Forensic Report   [CONFIDENTIAL]", align="C", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(100, 100, 100)
        self.set_font("Helvetica", "", 7)
        self.cell(0, 5, f"Case: {self._case_id}   Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}   Page {self.page_no()}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(80, 80, 80)
        self.cell(0, 5, "SIH 2026 · Problem Statement 26106 · AICTE Cyber Security Cell · AI-Powered Email Threat Intelligence Platform", align="C")

    def section_title(self, title: str):
        self.set_fill_color(20, 26, 33)
        self.set_text_color(61, 220, 151)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv_row(self, label: str, value: str, label_w: int = 55):
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(80, 80, 80)
        self.cell(label_w, 6, label + ":", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 6, str(value) if value is not None else "—")

    def colored_badge(self, text: str, color: tuple):
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(28, 7, text, fill=True, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_text_color(0, 0, 0)

    def risk_bar(self, score: float, label: str):
        bar_w = 140
        filled = int(bar_w * min(score, 100) / 100)
        color = (226, 72, 61) if score >= 70 else (232, 162, 61) if score >= 40 else (61, 220, 151)
        self.set_font("Helvetica", "", 8)
        self.cell(40, 6, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_fill_color(220, 220, 220)
        self.cell(bar_w, 6, "", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        x, y = self.get_x() - bar_w, self.get_y()
        self.set_fill_color(*color)
        if filled > 0:
            self.rect(x, y, filled, 6, "F")
        self.set_x(self.get_x() + 3)
        self.set_font("Helvetica", "B", 8)
        self.cell(15, 6, f"{score:.0f}/100", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _classification_color(cls: str) -> tuple:
    return {
        "CRITICAL": (226, 72, 61),
        "HIGH": (226, 72, 61),
        "MEDIUM": (232, 162, 61),
        "LOW": (61, 220, 151),
    }.get(cls or "", (120, 120, 120))


def generate_pdf_report(report_json: Dict[str, Any], advanced: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Generates a PDF forensic report from the stored report_json.
    Returns raw PDF bytes. Never includes raw email body content.
    """
    pdf = ForensicReportPDF(orientation="P", unit="mm", format="A4")
    pdf._case_id = report_json.get("case_id", "UNKNOWN")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── COVER / EXECUTIVE SUMMARY ──
    pdf.section_title("Executive Summary")
    pdf.set_font("Helvetica", "", 9)
    ai = report_json.get("ai_ml_analysis", {})
    ts = report_json.get("threat_score", {})
    classification = ai.get("fused_classification") or ts.get("classification", "UNKNOWN")
    score = ai.get("fused_overall_score") or ts.get("overall_score", 0)
    confidence = ai.get("fused_confidence") or ts.get("confidence", 0)

    pdf.kv_row("Case ID", report_json.get("case_id", "—"))
    pdf.kv_row("Generated At", report_json.get("generated_at", "—"))
    pdf.kv_row("Evidence SHA-256", report_json.get("evidence", {}).get("sha256", "—"))
    pdf.kv_row("Original Filename", report_json.get("evidence", {}).get("original_filename", "—"))
    pdf.kv_row("File Size", f"{report_json.get('evidence', {}).get('size_bytes', 0):,} bytes")
    pdf.ln(3)

    # Score badge
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 7, "Threat Classification:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.colored_badge(classification, _classification_color(classification))
    pdf.set_x(pdf.get_x() + 5)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 7, f"  Score: {score:.1f}/100   Confidence: {confidence:.0%}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # AI reasons
    reasons = ai.get("reasons", [])
    if reasons:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(0, 6, "Key Risk Signals:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 8)
        for r in reasons[:8]:
            pdf.cell(5, 5, "•", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.multi_cell(0, 5, str(r))

    # ── EMAIL METADATA ──
    pdf.section_title("Email Metadata")
    em = report_json.get("email_summary", {})
    pdf.kv_row("From", str(em.get("from", "—")))
    pdf.kv_row("From Display Name", str(em.get("from_display_name") or "—"))
    pdf.kv_row("To", ", ".join(em.get("to") or []) or "—")
    pdf.kv_row("Subject", str(em.get("subject", "—")))
    pdf.kv_row("Date", str(em.get("date", "—")))
    pdf.kv_row("Sender Domain", str(em.get("sender_domain", "—")))

    # ── AUTHENTICATION ──
    pdf.section_title("Authentication Results (SPF / DKIM / DMARC)")
    auth = report_json.get("authentication", {})
    pdf.kv_row("SPF", f"{auth.get('spf', {}).get('result', '—')} (domain: {auth.get('spf', {}).get('domain', '—')})")
    pdf.kv_row("DKIM", f"{auth.get('dkim', {}).get('result', '—')} (domain: {auth.get('dkim', {}).get('domain', '—')})")
    pdf.kv_row("DMARC", f"{auth.get('dmarc', {}).get('result', '—')} (policy: {auth.get('dmarc', {}).get('policy', '—')})")
    alignment = auth.get("alignment", {})
    pdf.kv_row("From↔Return-Path Aligned", str(alignment.get("from_return_path_aligned", "unknown")))
    pdf.kv_row("From↔Reply-To Aligned", str(alignment.get("from_reply_to_aligned", "unknown")))
    pdf.kv_row("DKIM Domain Aligned", str(alignment.get("dkim_domain_aligned", "unknown")))

    # ── RECEIVED CHAIN ──
    pdf.section_title("Received Relay Chain (Observed Infrastructure)")
    rc = report_json.get("received_chain", {})
    pdf.kv_row("Hop Count", str(rc.get("hop_count", 0)))
    for hop in (rc.get("hops") or []):
        label = f"  Hop {hop.get('hop_index', '?')}"
        val = f"{hop.get('from_host', '?')} → {hop.get('by_host', '?')}"
        if hop.get("ip_address"):
            val += f" [{hop['ip_address']}]"
        if hop.get("timestamp"):
            val += f" at {hop['timestamp']}"
        pdf.kv_row(label, val)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(0, 5, "NOTE: The earliest hop reflects observed mail relay infrastructure, NOT a confirmed attacker location. Received headers can be forged or incomplete.")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    # ── RISK DIMENSION BREAKDOWN ──
    pdf.section_title("Explainable Risk Score Breakdown")
    breakdown = ts.get("breakdown") or {}
    for dim_name, dim_data in breakdown.items():
        if isinstance(dim_data, dict):
            pdf.risk_bar(dim_data.get("score", 0), dim_name.replace("_", " ").title())
    pdf.ln(3)

    # ── FORENSIC FINDINGS ──
    findings = report_json.get("findings", [])
    if findings:
        pdf.section_title(f"Forensic Findings ({len(findings)} detected)")
        for f in findings[:15]:
            sev = f.get("severity", "INFO")
            clr = _classification_color({"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(sev, "LOW"))
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*clr)
            pdf.cell(20, 6, f"[{sev}]", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 6, f.get("title", ""), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.multi_cell(0, 5, f.get("explanation", ""))
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)

    # ── URL FINDINGS ──
    urls = report_json.get("urls", [])
    if urls:
        pdf.section_title(f"URL Intelligence ({len(urls)} URLs analyzed)")
        for u in urls[:10]:
            url_str = str(u.get("url", ""))[:100]
            score_u = u.get("risk_score") or 0
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(20, 5, f"Score: {score_u:.0f}", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_font("Helvetica", "", 7)
            pdf.multi_cell(0, 5, url_str)
            reasons = u.get("risk_reasons") or []
            for r in reasons[:3]:
                pdf.set_text_color(150, 100, 0)
                pdf.cell(5, 4, "›", new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.set_text_color(80, 80, 80)
                pdf.multi_cell(0, 4, r)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)

    # ── DOMAIN FINDINGS ──
    domains = report_json.get("domains", [])
    if domains:
        pdf.section_title(f"Domain Intelligence ({len(domains)} domains analyzed)")
        for d in domains[:10]:
            pdf.kv_row(f"  {d.get('domain', '?')} [{d.get('role', '?')}]", f"Risk: {d.get('risk_score') or 0:.0f}")
            for ev in (d.get("evidence") or [])[:3]:
                pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(5, 4, "›", new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.multi_cell(0, 4, str(ev))
            pdf.set_text_color(0, 0, 0)

    # ── THREAT INTELLIGENCE ──
    intel = report_json.get("threat_intelligence", {})
    if intel:
        pdf.section_title("Threat Intelligence Summary")
        pdf.kv_row("Providers Used", ", ".join(intel.get("providers_used") or []))
        agg = intel.get("aggregate_score")
        pdf.kv_row("Aggregate Intel Score", f"{agg:.1f}/100" if agg is not None else "—")
        for ip_r in (intel.get("ip_results") or [])[:5]:
            pdf.kv_row(f"  IP: {ip_r.get('indicator', '?')}", f"Risk: {ip_r.get('risk_score') or '—'}")

    # ── CAMPAIGN CORRELATION ──
    campaign = report_json.get("campaign_correlation", [])
    if campaign:
        pdf.section_title(f"Campaign Correlation ({len(campaign)} related investigation(s))")
        for c in campaign[:5]:
            pdf.kv_row(f"  {c.get('case_id', '?')}", f"Similarity: {c.get('similarity_score', 0):.0%}  [{c.get('relationship', '?')}]")

    # ── ATTRIBUTION ──
    attr = report_json.get("attribution", {})
    if attr:
        pdf.section_title("Attribution Confidence Assessment")
        pdf.kv_row("Attribution Level", f"{attr.get('level', 0)} — {attr.get('level_label', '—')}")
        pdf.kv_row("Detection Confidence", f"{(attr.get('detection_confidence') or 0):.0%}")
        pdf.kv_row("Infrastructure Confidence", f"{(attr.get('infrastructure_confidence') or 0):.0%}")
        pdf.kv_row("Campaign Confidence", f"{(attr.get('campaign_confidence') or 0):.0%}")
        pdf.kv_row("Attribution Confidence", f"{(attr.get('attribution_confidence') or 0):.0%}")
        for exp_item in (attr.get("explanation") or [])[:5]:
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(5, 4, "›", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.multi_cell(0, 4, str(exp_item))
        pdf.set_text_color(0, 0, 0)

    # ── AI INVESTIGATION SUMMARY ──
    ai_inv = report_json.get("ai_investigation_summary", {})
    if ai_inv:
        pdf.section_title("AI Investigation Agent Summary")
        pdf.kv_row("Agent Classification", str(ai_inv.get("classification", "—")))
        pdf.kv_row("Agent Risk", str(ai_inv.get("risk", "—")))
        pdf.kv_row("Infrastructure Assessment", str(ai_inv.get("infrastructure_assessment", "—")))
        for finding in (ai_inv.get("key_findings") or [])[:6]:
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(5, 4, "›", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.multi_cell(0, 4, str(finding))
        pdf.set_text_color(0, 0, 0)

    # ── RESPONSE RECOMMENDATIONS ──
    recs = ai_inv.get("recommended_actions") or []
    if recs:
        pdf.section_title("Response Recommendations")
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 4, "All destructive actions require human approval before execution.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        for rec in recs:
            sev_r = rec.get("severity", "LOW")
            clr_r = _classification_color(sev_r)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*clr_r)
            pdf.cell(20, 6, f"[{sev_r}]", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(0, 6, rec.get("action", ""), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(80, 80, 80)
            pdf.multi_cell(0, 4, rec.get("reason", ""))
            pdf.set_text_color(0, 0, 0)

    # ── EVIDENCE INTEGRITY ──
    pdf.section_title("Evidence Integrity & Chain of Custody")
    ev = report_json.get("evidence", {})
    pdf.kv_row("SHA-256 Evidence Hash", ev.get("sha256", "—"))
    pdf.kv_row("Original Filename", ev.get("original_filename", "—"))
    pdf.kv_row("File Size", f"{ev.get('size_bytes', 0):,} bytes")
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(0, 5, "Blockchain Ledger Anchor (Local Tamper-Evident Hash Chain):", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(0, 4, "This platform implements a local cryptographic hash chain (same primitive as a blockchain). Each block hash references the previous block's hash, making tampering detectable. See verification API endpoint for integrity check.")
    pdf.set_text_color(0, 0, 0)

    # ── SANDBOX / AI-SECURITY / GRC / VAPT / THREAT REPORT ──
    if advanced and advanced.get("threat_report"):
        _advanced_sections(pdf, advanced)

    # ── DISCLAIMERS ──
    pdf.section_title("Disclaimers & Limitations")
    for disc in report_json.get("disclaimers", []):
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(5, 4, "•", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.multi_cell(0, 4, disc)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(0, 4, "This report is generated by an AI-powered forensic system and is an investigation-support tool. It does not constitute a legal finding or definitive attribution. All conclusions require human analyst review.")
    pdf.set_text_color(0, 0, 0)

    return bytes(pdf.output())


_PDF_MAP = str.maketrans({"\u2192": "->", "\u2190": "<-", "\u2248": "~", "\u2026": "...", "\u2265": ">=", "\u2264": "<=",
                          "\u2260": "!=", "\u00b7": "-", "\u2713": "OK", "\u2717": "X", "\u2018": "'", "\u2019": "'",
                          "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-", "\u00d7": "x", "\u2022": "*", "\u2194": "<->", "\u2191": "^", "\u2193": "v", "\u2705": "OK", "\u26a0": "!"})


def _s(v: Any, n: int = 600) -> str:
    """Core PDF fonts are latin-1 only: map common symbols and drop anything else."""
    return str(v if v is not None else "-").translate(_PDF_MAP)[:n].encode("latin-1", "replace").decode("latin-1")


def _para(pdf: "ForensicReportPDF", text: str, size: int = 8, bold: bool = False, color=(20, 20, 20), indent: int = 0):
    pdf.set_font("Helvetica", "B" if bold else "", size)
    pdf.set_text_color(*color)
    if indent:
        pdf.set_x(pdf.l_margin + indent)
    pdf.multi_cell(0, 4.5, _s(text, 2000), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)


_STATUS_COLOR = {"FAIL": (170, 40, 30), "WARN": (190, 120, 20), "PASS": (60, 120, 60), "NOT_ASSESSED": (110, 110, 110)}
_VERDICT_COLOR = {"MALICIOUS": (180, 30, 30), "SUSPICIOUS": (200, 120, 20), "SAFE": (40, 130, 70)}


def _advanced_sections(pdf: "ForensicReportPDF", adv: Dict[str, Any]) -> None:
    tr = adv.get("threat_report") or {}
    # 1. consolidated verdict + pipeline
    pdf.add_page()
    pdf.section_title("Consolidated Threat Verdict (Detection + Sandbox + AI Security + GRC)")
    v = tr.get("final_verdict", "UNKNOWN")
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(40, 7, "Final Verdict:", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.colored_badge(v, _VERDICT_COLOR.get(v, (90, 90, 90)))
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 7, _s(f"   Combined score: {tr.get('final_score', 0)}/100"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    for r in tr.get("verdict_reasons", [])[:8]:
        _para(pdf, f"* {r}", 7)
    pdf.ln(2)
    _para(pdf, "Processing pipeline", 8, True)
    for st in tr.get("pipeline", []):
        _para(pdf, f"{st.get('step')}: {st.get('status')}" + (f"  ({st.get('detail')})" if st.get("detail") else ""), 7, indent=3)
    led = adv.get("ledger") or {}
    if led.get("block_index") is not None:
        _para(pdf, f"Blockchain audit: block #{led['block_index']}  ref {led.get('case_ref')}  report SHA-256 {led.get('report_hash')}", 7,
              color=(60, 60, 60))

    # 2. where it went wrong
    pdf.section_title("Where the E-mail Went Wrong (Checkpoint Analysis)")
    for c in tr.get("where_it_went_wrong", []):
        st = c.get("status", "")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*_STATUS_COLOR.get(st, (80, 80, 80)))
        pdf.cell(24, 5, _s(st), new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(0, 5, _s(f"{c.get('checkpoint')} - {c.get('summary')}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for e in c.get("evidence", [])[:3]:
            _para(pdf, f"- {e}", 6, color=(90, 90, 90), indent=24)

    # 3. sandbox
    sb = (adv.get("sandbox") or {})
    res = sb.get("result") or {}
    pdf.section_title("Isolated Sandbox Analysis (static / controlled - nothing executed)")
    pdf.kv_row("Status", _s(sb.get("status")))
    pdf.kv_row("Verdict / Score", _s(f"{sb.get('verdict') or '-'} / {sb.get('score') if sb.get('score') is not None else '-'}"))
    pdf.kv_row("Engine", _s(res.get("engine_version") or "-"))
    if sb.get("error"):
        pdf.kv_row("Note", _s(sb.get("error")))
    for f in res.get("files", [])[:10]:
        _para(pdf, f"{f['filename']}  [{f['verdict']} {f['score']}]  type={f['detected_type']}  size={f['size_bytes']}", 8, True)
        _para(pdf, f"SHA-256 {f['sha256']}   entropy {f.get('entropy')}", 6, color=(90, 90, 90), indent=3)
        for x in f.get("findings", [])[:6]:
            _para(pdf, f"[{x['rule_id']}] {x['severity']}: {x['title']} - {x['explanation']}", 6, indent=3)
    bad_urls = [u for u in res.get("urls", []) if u.get("verdict") != "SAFE"]
    if bad_urls:
        _para(pdf, "Links flagged by the sandbox:", 8, True)
        for u in bad_urls[:10]:
            _para(pdf, f"{u['verdict']} {u['score']}: {u['url'][:120]}  - {(u.get('reasons') or [''])[0][:160]}", 6, indent=3)
    if res.get("predicted_behavior"):
        _para(pdf, "Predicted behaviour (static inference):", 8, True)
        for b in res["predicted_behavior"][:10]:
            _para(pdf, f"- {b}", 7, indent=3)

    # 4. AI security
    ai = adv.get("ai_security") or {}
    pdf.section_title("AI Security (attacks on AI + platform AI guardrails)")
    pdf.kv_row("Verdict", _s(f"{ai.get('verdict')} (score {ai.get('score')})"))
    pdf.kv_row("AI-written lure likelihood", _s(f"{ai.get('ai_generated_likelihood')} (heuristic)"))
    for x in ai.get("findings", [])[:8]:
        _para(pdf, f"[{x['rule_id']}] {x['severity']}: {x['title']} - {x['explanation']}", 7)
        if x.get("evidence"):
            _para(pdf, f"Evidence: {x['evidence']}", 6, color=(90, 90, 90), indent=3)
    _para(pdf, "Guardrails protecting MailShield's own AI:", 8, True)
    for g in ai.get("guardrails", []):
        _para(pdf, f"{g['status']}: {g['control']} - {g['detail']}", 6, indent=3)

    # 5. GRC
    grc = adv.get("grc") or {}
    pdf.section_title("Governance, Risk & Compliance (Indian legal / regulatory mapping)")
    pdf.kv_row("Compliance status", _s(grc.get("status")))
    for i in grc.get("items", []):
        _para(pdf, f"[{i['type']}] {i['framework']} - {i['provision']}: {i['title']} ({i['severity']})", 7, True)
        _para(pdf, i["description"], 6, indent=3)
        for e in i.get("evidence", [])[:3]:
            _para(pdf, f"Evidence: {e}", 6, color=(90, 90, 90), indent=3)
        for a in i.get("actions", [])[:2]:
            _para(pdf, f"Action: {a}", 6, color=(40, 80, 40), indent=3)
    for ch in grc.get("reporting_channels", []):
        _para(pdf, f"Report to: {ch['name']} - {ch['contact']} ({ch['when']})", 7)
    _para(pdf, grc.get("disclaimer", ""), 6, color=(100, 100, 100))

    # 6. VAPT
    va = adv.get("vapt") or {}
    pdf.section_title("VAPT Assessment - Attacker Intent & Exploited Weaknesses")
    pi = va.get("primary_intent") or {}
    pdf.kv_row("Primary intent", _s(f"{pi.get('label')} (confidence {pi.get('confidence')})"))
    pdf.kv_row("Attacker objective", _s(pi.get("attacker_objective")))
    pdf.kv_row("Exploitability", _s(f"{va.get('exploitability_score')}/100"))
    pdf.kv_row("MITRE ATT&CK", _s(", ".join(va.get("mitre_attack", []))))
    _para(pdf, f"Attack path: {va.get('attack_path')}", 7)
    _para(pdf, "Weaknesses exploited (where):", 8, True)
    for w in va.get("weaknesses", []):
        _para(pdf, f"{w['rating']} ({w['score']}/16) - {w['title']} @ {w['location']}  [owner: {w['owner']}]", 7, True, indent=3)
        _para(pdf, f"{w['description']}  Fix: {w['remediation']}", 6, indent=6)
