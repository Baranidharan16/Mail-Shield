"""Post-detection pipeline

    Email → AI Threat Detection → Suspicious? → Quarantine → Isolated Sandbox
          → AI-Security + GRC + VAPT → Threat Report → Blockchain audit → SOC alarm

Runs after the existing forensic/ML pipeline has COMPLETED (it never changes
the stored forensic report, so the existing ledger anchor stays valid). Its
own consolidated threat report is anchored as a separate block
(case id suffix "-SBX") in the same tamper-evident hash chain.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.advanced.ai_security import analyze_ai_security
from app.advanced.grc import BANKS, GOV_ENTITIES, PII, evaluate_grc
from app.advanced.soc import get_config, raise_alarm
from app.advanced.vapt import assess_vapt
from app.models.advanced import AdvancedAnalysis
from app.models.investigation import AuditLog, Investigation
from app.sandbox import client as sandbox_client

logger = logging.getLogger("mailshield.advanced")
PIPELINE_VERSION = "advanced-pipeline/1.0.0"
_RUNNING: set = set()
_LOCK = threading.Lock()
SUSPICIOUS_CLASSES = ("MEDIUM", "HIGH", "CRITICAL")


def _now():
    return datetime.now(timezone.utc)


def _enabled() -> bool:
    return os.getenv("ADVANCED_PIPELINE_ENABLED", "true").lower() in ("1", "true", "yes")


def schedule_advanced_pipeline(investigation_id: str, raw_bytes: Optional[bytes] = None, trigger: str = "AUTO",
                               force_sandbox: bool = False) -> None:
    """Fire-and-forget: the sandbox may be cold-starting, so this never blocks
    the upload response or the Gmail monitor loop."""
    if not _enabled():
        return
    if os.getenv("ADVANCED_PIPELINE_SYNC", "false").lower() == "true":
        run_advanced_pipeline(investigation_id, raw_bytes, trigger, force_sandbox)
        return
    threading.Thread(target=run_advanced_pipeline, args=(investigation_id, raw_bytes, trigger, force_sandbox),
                     daemon=True, name=f"advanced-{investigation_id[:8]}").start()


def run_advanced_pipeline(investigation_id: str, raw_bytes: Optional[bytes] = None, trigger: str = "AUTO",
                          force_sandbox: bool = False) -> None:
    with _LOCK:
        if investigation_id in _RUNNING:
            return
        _RUNNING.add(investigation_id)
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        _run(db, investigation_id, raw_bytes, trigger, force_sandbox)
    except Exception as exc:  # noqa: BLE001
        logger.exception("advanced pipeline failed for %s", investigation_id)
        db.rollback()
        adv = db.query(AdvancedAnalysis).filter(AdvancedAnalysis.investigation_id == investigation_id).first()
        if adv:
            adv.pipeline_status = "FAILED"
            adv.error = f"{type(exc).__name__}: {exc}"[:2000]
            db.commit()
    finally:
        with _LOCK:
            _RUNNING.discard(investigation_id)
        db.close()


def is_running(investigation_id: str) -> bool:
    return investigation_id in _RUNNING


def _load_evidence(inv: Investigation) -> Optional[bytes]:
    from app.core.config import get_settings
    base = os.path.abspath(get_settings().UPLOAD_STORAGE_DIR)
    p = os.path.abspath(os.path.join(base, inv.filename or ""))
    if p.startswith(base + os.sep) and os.path.isfile(p):
        with open(p, "rb") as fh:
            return fh.read()
    return None


def _audit(db: Session, inv_id: str, action: str, detail: str) -> None:
    db.add(AuditLog(investigation_id=inv_id, actor="system", action=action, detail=detail[:2000]))
    db.commit()


# ── signal extraction from the stored investigation ─────────────────────────
def _body_text(raw: Optional[bytes]) -> str:
    if not raw:
        return ""
    from app.advanced.ai_security import _texts, _visible
    t = _texts(raw)
    return (t["plain"] + " " + _visible(t["html"]))[:200_000]


def _signals(inv: Investigation, raw: Optional[bytes], sandbox: Optional[dict]) -> Dict:
    auth = inv.authentication_result
    meta = inv.email_metadata
    spf = (auth.spf_result or "NONE").upper() if auth else "NONE"
    dkim = (auth.dkim_result or "NONE").upper() if auth else "NONE"
    dmarc = (auth.dmarc_result or "NONE").upper() if auth else "NONE"
    fails = [n for n, r in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)) if r in ("FAIL", "SOFTFAIL", "PERMERROR")]
    body = _body_text(raw)
    subject = (meta.subject if meta else "") or ""
    display = (meta.from_display_name if meta else "") or ""
    ind_ev: Dict[str, str] = {}
    for i in inv.indicators or []:
        ind_ev.setdefault(i.indicator_type, f"{i.indicator_type}: {(i.matched_evidence or i.explanation or '')[:120]}")
    lookalikes = sorted({f"{d.domain}≈{d.lookalike_of}" for d in (inv.domains or []) if d.lookalike_of})
    header_forgery = [f"{f.rule_id} {f.title}" for f in (inv.findings or []) if f.category in ("header", "authentication")
                      and (f.severity or "").upper() in ("HIGH", "CRITICAL", "MEDIUM")]
    sb_files = (sandbox or {}).get("files") or []
    cred_form = next((f"{f['filename']}: credential form" for f in sb_files
                      for x in f.get("findings", []) if x.get("rule_id") == "SBX-HTM-001"), "")
    if not cred_form and any(x.get("rule_id") == "SBX-HTM-001" for x in ((sandbox or {}).get("html_body") or {}).get("findings", [])):
        cred_form = "e-mail body: credential form"
    text_all = " ".join([subject, display, body])
    claim = (re.search(GOV_ENTITIES, text_all, re.I) or re.search(BANKS, text_all, re.I))
    pii = re.search(PII, text_all, re.I)
    return {
        "subject": subject, "display_name": display, "body": body,
        "sender_domain": (meta.sender_domain if meta else "") or "",
        "indicator_types": sorted({i.indicator_type for i in inv.indicators or []}),
        "indicator_evidence": ind_ev,
        "auth_fail": bool(fails), "auth_summary": f"SPF={spf} DKIM={dkim} DMARC={dmarc}"
                                                  + (f" (policy={auth.dmarc_policy})" if auth and auth.dmarc_policy else ""),
        "sender_no_dmarc": dmarc in ("NONE", "UNKNOWN", ""),
        "dmarc_policy_weak": bool(auth and (auth.dmarc_policy or "").lower() == "none"),
        "delivered_despite_fail": bool(fails) and (inv.original_filename or "").startswith("gmail_"),
        "reply_to_mismatch": bool(auth and auth.from_reply_to_aligned is False),
        "lookalikes": lookalikes,
        "header_forgery": header_forgery,
        "risky": (inv.classification or "LOW") in SUSPICIOUS_CLASSES,
        "url_count": len(inv.urls or []),
        "url_risky": any((u.risk_score or 0) >= 40 for u in inv.urls or []),
        "sandbox_verdict": (sandbox or {}).get("verdict"),
        "sandbox_malicious_files": [f"{f['filename']} ({f['detected_type']}, sha256 {f['sha256'][:16]}…)" for f in sb_files
                                    if f.get("verdict") == "MALICIOUS"],
        "sandbox_cred_form": cred_form,
        "gov_or_brand_claim": claim.group(0) if claim else "",
        "pii_requested": pii.group(0) if pii else "",
    }


# ── consolidated report ─────────────────────────────────────────────────────
def _cp(name, status, summary, evidence=None):
    return {"checkpoint": name, "status": status, "summary": summary, "evidence": [e for e in (evidence or []) if e][:6]}


def _checkpoints(inv: Investigation, sig: Dict, adv: AdvancedAnalysis, ai_sec: Dict, grc: Dict) -> List[dict]:
    out = []
    auth = inv.authentication_result
    res = {n: ((getattr(auth, f"{n.lower()}_result", None) or "NONE").upper() if auth else "NONE") for n in ("SPF", "DKIM", "DMARC")}
    if sig["auth_fail"]:
        out.append(_cp("Sender authentication (SPF / DKIM / DMARC)", "FAIL", "Authentication failed — the sender is not proven.", [sig["auth_summary"]]))
    elif any(v in ("NONE", "NEUTRAL", "UNKNOWN", "TEMPERROR") for v in res.values()):
        out.append(_cp("Sender authentication (SPF / DKIM / DMARC)", "WARN", "Authentication incomplete or not published.", [sig["auth_summary"]]))
    else:
        out.append(_cp("Sender authentication (SPF / DKIM / DMARC)", "PASS", "SPF, DKIM and DMARC passed.", [sig["auth_summary"]]))

    ident = sig["lookalikes"] + [f for f in sig["header_forgery"] if "impersonat" in f.lower() or "display name" in f.lower()]
    if ident:
        out.append(_cp("Sender identity & domain", "FAIL", "Sender identity is impersonated / look-alike.", ident))
    elif sig["reply_to_mismatch"] or (auth and auth.from_return_path_aligned is False):
        out.append(_cp("Sender identity & domain", "WARN", "Sender address fields are not aligned.",
                       ["From ≠ Reply-To" if sig["reply_to_mismatch"] else "", "From ≠ Return-Path" if auth and auth.from_return_path_aligned is False else ""]))
    else:
        out.append(_cp("Sender identity & domain", "PASS", "From, Reply-To and Return-Path are consistent.", []))

    hdr = [f for f in inv.findings or [] if f.category == "header"]
    hi = [f for f in hdr if (f.severity or "").upper() in ("HIGH", "CRITICAL")]
    out.append(_cp("Transport path & header integrity", "FAIL" if hi else ("WARN" if hdr else "PASS"),
                   f"{len(hdr)} header anomaly finding(s)." if hdr else "No routing / header anomalies.",
                   [f"{f.rule_id}: {f.title}" for f in hdr]))

    inds = inv.indicators or []
    hi_i = [i for i in inds if (i.severity or "").upper() in ("HIGH", "CRITICAL")]
    out.append(_cp("Content & social engineering", "FAIL" if hi_i else ("WARN" if inds else "PASS"),
                   f"{len(inds)} manipulation indicator(s): " + ", ".join(sorted({i.indicator_type for i in inds}))[:160] if inds else "No social-engineering language detected.",
                   [f"{i.indicator_type}: {(i.matched_evidence or '')[:80]}" for i in inds]))

    sb = adv.sandbox_result or {}
    sb_urls = sb.get("urls") or []
    bad = [u for u in sb_urls if u.get("verdict") == "MALICIOUS"] + [u for u in inv.urls or [] if (u.risk_score or 0) >= 60]
    warn = [u for u in sb_urls if u.get("verdict") == "SUSPICIOUS"] + [u for u in inv.urls or [] if 30 <= (u.risk_score or 0) < 60]
    ev = [(u.get("url") if isinstance(u, dict) else u.url)[:100] for u in (bad or warn)]
    out.append(_cp("Links / URLs", "FAIL" if bad else ("WARN" if warn else "PASS"),
                   f"{len(bad)} malicious, {len(warn)} suspicious link(s)." if (bad or warn) else
                   ("No links in the message." if not (inv.urls or sb_urls) else "Links look benign."), ev))

    atts = (inv.email_metadata.attachments if inv.email_metadata else None) or []
    files = sb.get("files") or []
    if files:
        mal = [f for f in files if f["verdict"] == "MALICIOUS"]
        sus = [f for f in files if f["verdict"] == "SUSPICIOUS"]
        out.append(_cp("Attachments (isolated sandbox)", "FAIL" if mal else ("WARN" if sus else "PASS"),
                       f"{len(files)} file(s) analysed in the sandbox: {len(mal)} malicious, {len(sus)} suspicious.",
                       [f"{f['filename']} → {f['verdict']}: {f['reasons'][0] if f['reasons'] else ''}"[:160] for f in (mal + sus or files)]))
    elif atts:
        out.append(_cp("Attachments (isolated sandbox)", "NOT_ASSESSED",
                       f"{len(atts)} attachment(s); sandbox status: {adv.sandbox_status}.", [a.get("filename") for a in atts]))
    else:
        out.append(_cp("Attachments (isolated sandbox)", "PASS", "No attachments.", []))

    bh = (sb.get("html_body") or {})
    if bh.get("verdict") in ("SUSPICIOUS", "MALICIOUS"):
        out.append(_cp("HTML body behaviour (sandbox)", "FAIL" if bh["verdict"] == "MALICIOUS" else "WARN",
                       "Active content in the e-mail body.", [f"{x['rule_id']} {x['title']}" for x in bh.get("findings", [])]))

    av = ai_sec.get("verdict")
    out.append(_cp("AI manipulation / adversarial AI", "FAIL" if av == "MANIPULATION_DETECTED" else ("WARN" if av == "SUSPICIOUS" or ai_sec.get("ai_generated_likelihood", 0) >= 0.45 else "PASS"),
                   ai_sec.get("summary", ""), [f"{f['rule_id']} {f['title']}" for f in ai_sec.get("findings", [])]))

    ti = inv.threat_intel_summary
    ti_score = (ti.aggregate_score or 0) if ti else 0
    out.append(_cp("Threat intelligence & reputation", "FAIL" if ti_score >= 50 else ("WARN" if ti_score > 0 else "PASS"),
                   f"Aggregate threat-intel score {ti_score:.0f}." if ti else "No threat-intel matches.",
                   list((ti.reasons or []) if ti else [])[:4]))

    mlp = inv.ml_prediction
    if mlp:
        cls = mlp.fused_classification or inv.classification
        out.append(_cp("AI / ML threat detection", "FAIL" if cls in ("HIGH", "CRITICAL") else ("WARN" if cls == "MEDIUM" else "PASS"),
                       f"Fused AI/ML verdict {cls} (score {mlp.fused_overall_score or 0:.0f}).", list(mlp.fused_reasons or [])[:4]))

    out.append(_cp("Legal & regulatory (GRC)", "FAIL" if grc["violations"] else ("WARN" if grc["obligations"] or grc["control_gaps"] else "PASS"),
                   f"{grc['violations']} potential violation(s), {grc['obligations']} reporting obligation(s), {grc['control_gaps']} control gap(s).",
                   [f"{i['provision']} — {i['title']}" for i in grc["items"]]))
    return out


def _final(inv: Investigation, adv: AdvancedAnalysis, ai_sec: Dict, grc: Dict):
    parts = [(inv.risk_score or 0) / 100.0]
    if adv.sandbox_status == "COMPLETED" and adv.sandbox_score is not None:
        parts.append(adv.sandbox_score / 100.0)
    parts.append(0.6 * ai_sec.get("score", 0) / 100.0)
    parts.append(min(0.5, 0.15 * grc.get("violations", 0)))
    p = 1.0
    for x in parts:
        p *= 1 - max(0.0, min(1.0, x))
    score = round((1 - p) * 100, 1)
    reasons = []
    if adv.sandbox_verdict == "MALICIOUS" or inv.classification == "CRITICAL" or score >= 80:
        v = "MALICIOUS"
    elif adv.sandbox_verdict == "SUSPICIOUS" or inv.classification in SUSPICIOUS_CLASSES or score >= 40:
        v = "SUSPICIOUS"
    else:
        v = "SAFE"
    reasons.append(f"AI/forensic detection: {inv.classification} (risk {inv.risk_score or 0:.0f}/100).")
    if adv.sandbox_status == "COMPLETED":
        reasons.append(f"Isolated sandbox: {adv.sandbox_verdict} (score {adv.sandbox_score:.0f}).")
        reasons += (adv.sandbox_result or {}).get("reasons", [])[:3]
    else:
        reasons.append(f"Isolated sandbox: {adv.sandbox_status.replace('_', ' ').lower()}.")
    if ai_sec.get("findings"):
        reasons.append(f"AI security: {ai_sec['summary']}")
    if grc.get("violations"):
        reasons.append(f"GRC: {grc['violations']} potential legal violation(s) — " + ", ".join(i["provision"] for i in grc["items"] if i["type"] == "VIOLATION")[:200])
    return v, score, reasons


def _pipeline_steps(inv, adv, suspicious, sb_needed) -> List[dict]:
    t = lambda d: d.isoformat() if d else None  # noqa: E731
    return [
        {"step": "Email received", "status": "DONE", "at": t(inv.created_at), "detail": inv.original_filename},
        {"step": "AI threat detection", "status": "DONE", "at": t(inv.analyzed_at),
         "detail": f"{inv.classification} · risk {inv.risk_score or 0:.0f}/100"},
        {"step": "Suspicious e-mail", "status": "YES" if suspicious else "NO", "at": t(inv.analyzed_at),
         "detail": "Classification ≥ MEDIUM" if suspicious else "Below suspicious threshold"},
        {"step": "Quarantine", "status": adv.quarantine_status, "at": t(adv.quarantined_at), "detail": adv.quarantine_reason},
        {"step": "Isolated sandbox analysis", "status": adv.sandbox_status if sb_needed or adv.sandbox_status != "NOT_REQUIRED" else "NOT_REQUIRED",
         "at": t(adv.sandbox_completed_at), "detail": adv.sandbox_verdict or adv.sandbox_error},
        {"step": "Threat report", "status": "DONE", "at": t(_now()), "detail": None},
        {"step": "Blockchain audit log", "status": "PENDING", "at": None, "detail": None},
    ]


def _run(db: Session, investigation_id: str, raw_bytes: Optional[bytes], trigger: str, force_sandbox: bool) -> None:
    inv = db.get(Investigation, investigation_id)
    if inv is None or inv.status != "COMPLETED":
        return
    adv = db.query(AdvancedAnalysis).filter(AdvancedAnalysis.investigation_id == inv.id).first()
    if adv is None:
        adv = AdvancedAnalysis(investigation_id=inv.id, user_id=inv.user_id, case_id=inv.case_id)
        db.add(adv)
    adv.pipeline_status, adv.trigger, adv.error = "RUNNING", trigger, None
    db.commit()

    raw = raw_bytes or _load_evidence(inv)
    cfg = get_config(db, inv.user_id) if inv.user_id else None
    scope = cfg.sandbox_scope if cfg else "SUSPICIOUS"
    suspicious = (inv.classification or "LOW") in SUSPICIOUS_CLASSES
    sb_needed = force_sandbox or trigger == "MANUAL_QUARANTINE" or scope == "ALL" or (scope == "SUSPICIOUS" and suspicious)

    ml_ok = bool(inv.ml_prediction and (inv.ml_prediction.structured_available or inv.ml_prediction.text_available))
    ai_sec = analyze_ai_security(raw or b"", ml_available=ml_ok, llm_configured=bool(os.getenv("GEMINI_API_KEY")))
    adv.ai_security = ai_sec

    # 1) QUARANTINE (application-level evidence quarantine; Gmail label move stays analyst-approved)
    if sb_needed and adv.quarantine_status != "QUARANTINED":
        adv.quarantine_status = "QUARANTINED"
        adv.quarantined_at = _now()
        adv.quarantine_reason = ("Analyst quarantined the e-mail" if trigger == "MANUAL_QUARANTINE" else
                                 f"Auto-quarantined: AI detection classified the e-mail {inv.classification}"
                                 f" (risk {inv.risk_score or 0:.0f}/100)" if suspicious else "Sandbox scope = ALL")
        _audit(db, inv.id, "EVIDENCE_QUARANTINED", adv.quarantine_reason)

    # 2) ISOLATED SANDBOX
    sandbox = adv.sandbox_result if adv.sandbox_status == "COMPLETED" and not force_sandbox else None
    if sb_needed and sandbox is None:
        if not sandbox_client.sandbox_enabled():
            adv.sandbox_status = "UNAVAILABLE"
            adv.sandbox_error = "Sandbox service not configured (set SANDBOX_URL and SANDBOX_SHARED_SECRET)."
        else:
            payload, manifest = sandbox_client.extract_artifacts(raw or b"", [u.url for u in inv.urls or []])
            if raw is None:
                manifest["note"] = "Original .eml not on this server's disk; only stored URLs were submitted."
            adv.sandbox_submission = manifest
            if not (payload["attachments"] or payload["urls"] or payload["html_bodies"]):
                adv.sandbox_status = "NO_ARTIFACTS"
            else:
                adv.sandbox_status, adv.sandbox_started_at = "RUNNING", _now()
                adv.sandbox_attempts = (adv.sandbox_attempts or 0) + 1
                db.commit()
                _audit(db, inv.id, "SANDBOX_SUBMITTED", f"{len(payload['attachments'])} file(s), {len(payload['urls'])} url(s); "
                                                        f"bundle sha256={manifest['artifact_bundle_sha256'][:16]}…")
                try:
                    sandbox = sandbox_client.submit(payload)
                    adv.sandbox_status = "COMPLETED"
                    adv.sandbox_result = sandbox
                    adv.sandbox_verdict = sandbox.get("verdict")
                    adv.sandbox_score = float(sandbox.get("score") or 0)
                    adv.sandbox_error = sandbox.get("error")
                    adv.sandbox_completed_at = _now()
                    _audit(db, inv.id, "SANDBOX_COMPLETED", f"verdict={adv.sandbox_verdict} score={adv.sandbox_score}")
                except sandbox_client.SandboxUnavailable as exc:
                    adv.sandbox_status, adv.sandbox_error = "UNAVAILABLE", str(exc)[:1000]
                    _audit(db, inv.id, "SANDBOX_UNAVAILABLE", str(exc)[:300])
        db.commit()
    elif not sb_needed and adv.sandbox_status in (None, "NOT_REQUIRED"):
        adv.sandbox_status = "NOT_REQUIRED"

    # 3) GRC + VAPT on the full evidence set
    sig = _signals(inv, raw, sandbox)
    grc = evaluate_grc(sig)
    vapt = assess_vapt(sig, sandbox, ai_sec)
    adv.grc, adv.vapt = grc, vapt

    # 4) consolidated threat report
    verdict, score, reasons = _final(inv, adv, ai_sec, grc)
    adv.final_verdict, adv.final_score = verdict, score
    steps = _pipeline_steps(inv, adv, suspicious, sb_needed)
    report = {
        "report_type": "MailShield Consolidated Threat Report",
        "pipeline_version": PIPELINE_VERSION,
        "case_id": inv.case_id,
        "generated_at": _now().isoformat(),
        "final_verdict": verdict,
        "final_score": score,
        "verdict_reasons": reasons,
        "pipeline": steps,
        "where_it_went_wrong": _checkpoints(inv, sig, adv, ai_sec, grc),
        "detection": {"classification": inv.classification, "risk_score": inv.risk_score, "confidence": inv.confidence,
                      "top_reasons": list((inv.ml_prediction.fused_reasons if inv.ml_prediction else None) or [])[:6]},
        "quarantine": {"status": adv.quarantine_status, "reason": adv.quarantine_reason,
                       "at": adv.quarantined_at.isoformat() if adv.quarantined_at else None},
        "sandbox": {"status": adv.sandbox_status, "verdict": adv.sandbox_verdict, "score": adv.sandbox_score,
                    "error": adv.sandbox_error, "submission": adv.sandbox_submission,
                    "reasons": (sandbox or {}).get("reasons", []), "predicted_behavior": (sandbox or {}).get("predicted_behavior", []),
                    "mitre_techniques": (sandbox or {}).get("mitre_techniques", []), "engine": (sandbox or {}).get("engine_version")},
        "ai_security": ai_sec,
        "grc": grc,
        "vapt": vapt,
        "privacy": "Report contains findings, hashes and indicators only — no e-mail body is stored in it.",
    }
    adv.threat_report = report
    db.commit()

    # 5) BLOCKCHAIN AUDIT — separate block so the original forensic anchor stays valid
    from app.blockchain.ledger import anchor_evidence, canonical_report_hash
    report_hash = canonical_report_hash(report)
    evidence_hash = (adv.sandbox_submission or {}).get("artifact_bundle_sha256") or inv.evidence_hash_sha256
    block = anchor_evidence(db, f"{inv.case_id}-SBX", evidence_hash, report_hash)
    adv.ledger_block_index, adv.ledger_block_hash, adv.report_hash = block.block_index, block.block_hash, report_hash
    adv.pipeline_status = "COMPLETED"
    db.commit()
    _audit(db, inv.id, "THREAT_REPORT_ANCHORED", f"block={block.block_index} verdict={verdict} report_hash={report_hash[:16]}…")

    # 6) SOC ALARMS
    if inv.user_id:
        if inv.classification in SUSPICIOUS_CLASSES:
            raise_alarm(db, inv.user_id, inv.classification, "DETECTION",
                        f"{inv.classification} threat e-mail detected — {inv.case_id}",
                        "; ".join(reasons[:2]), inv.id, inv.case_id)
        if adv.sandbox_verdict == "MALICIOUS":
            raise_alarm(db, inv.user_id, "CRITICAL", "SANDBOX", f"Sandbox confirmed MALICIOUS artefact — {inv.case_id}",
                        "; ".join((sandbox or {}).get("reasons", [])[:2]), inv.id, inv.case_id)
        crit_grc = [i for i in grc["items"] if i["type"] == "VIOLATION" and i["severity"] in ("HIGH", "CRITICAL")]
        if crit_grc and suspicious:
            raise_alarm(db, inv.user_id, "CRITICAL" if any(i["severity"] == "CRITICAL" for i in crit_grc) else "HIGH", "GRC",
                        f"Regulatory violation indicators — {inv.case_id}",
                        ", ".join(i["provision"] for i in crit_grc)[:400], inv.id, inv.case_id)


def mark_manual_quarantine(investigation_id: str) -> None:
    """Called by the existing quarantine endpoints: ensures the quarantined
    e-mail's artefacts go to the sandbox even if auto-scope skipped it."""
    schedule_advanced_pipeline(investigation_id, None, "MANUAL_QUARANTINE", force_sandbox=False)


def advanced_view(adv: Optional[AdvancedAnalysis], running: bool = False) -> dict:
    if adv is None:
        return {"exists": False, "pipeline_status": "RUNNING" if running else "NOT_STARTED"}
    return {
        "exists": True,
        "pipeline_status": "RUNNING" if running else adv.pipeline_status,
        "trigger": adv.trigger,
        "quarantine": {"status": adv.quarantine_status, "reason": adv.quarantine_reason,
                       "at": adv.quarantined_at.isoformat() if adv.quarantined_at else None},
        "sandbox": {"status": adv.sandbox_status, "verdict": adv.sandbox_verdict, "score": adv.sandbox_score,
                    "attempts": adv.sandbox_attempts, "error": adv.sandbox_error, "submission": adv.sandbox_submission,
                    "result": adv.sandbox_result,
                    "started_at": adv.sandbox_started_at.isoformat() if adv.sandbox_started_at else None,
                    "completed_at": adv.sandbox_completed_at.isoformat() if adv.sandbox_completed_at else None},
        "ai_security": adv.ai_security, "grc": adv.grc, "vapt": adv.vapt,
        "threat_report": adv.threat_report,
        "final_verdict": adv.final_verdict, "final_score": adv.final_score,
        "ledger": {"block_index": adv.ledger_block_index, "block_hash": adv.ledger_block_hash,
                   "report_hash": adv.report_hash, "case_ref": f"{adv.case_id}-SBX" if adv.case_id else None},
        "error": adv.error,
        "updated_at": adv.updated_at.isoformat() if adv.updated_at else None,
    }
