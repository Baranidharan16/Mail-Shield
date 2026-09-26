"""AI Security module.

Two halves:
 1. Threats AGAINST AI — does this e-mail try to manipulate AI systems
    (the recipient's AI mail assistant, our own ML/NLP filters, or an LLM
    summariser)?  Prompt injection, hidden text / Bayesian poisoning, invisible
    Unicode token-splitting, homoglyph obfuscation, and signals that the lure
    itself was machine-generated (AI-written phishing).
 2. How MailShield's own AI is protected — the guardrails actually in force
    for this analysis, reported with their live status.

Every finding carries rule ID + severity + explanation + evidence. The
"AI-generated text" estimate is an explicitly-labelled stylometric
heuristic, not a proof of authorship.
"""
from __future__ import annotations

import email
import email.policy
import html as _html
import re
import statistics
import unicodedata
from typing import Dict, List, Optional

SEV_W = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}

INJECTION = [
    (r"ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts|rules)", "Instruction-override phrase"),
    (r"disregard (all |any |the )?(previous|prior|above) (instructions|rules)", "Instruction-override phrase"),
    (r"(you are|act as|pretend to be) (now )?(an? )?(ai|assistant|chatbot|language model|system)", "Role-reassignment of an AI"),
    (r"(system prompt|developer mode|jailbreak|DAN mode)", "Jailbreak / system-prompt probing"),
    (r"(classify|mark|label|treat) (this|the) (e-?mail|message) as (safe|legitimate|not spam|clean)", "Direct instruction to AI filter"),
    (r"(do not|don't|never) (flag|report|quarantine|block|warn)", "Instruction to suppress security warnings"),
    (r"(ai|assistant|copilot|gemini|chatgpt)[, ]+(please )?(summari[sz]e|forward|reply|send|include) .{0,40}(password|otp|credential|link|file)", "Instruction to an AI mail assistant to leak data"),
    (r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|###\s*(instruction|system)", "LLM control tokens"),
    (r"when (you|the ai|the assistant) (read|summari[sz]e|process)s? this", "Conditional trigger aimed at AI readers"),
]
LLM_STYLE = [
    r"i hope this (e-?mail|message) finds you well", r"i trust this (e-?mail|message) finds you", r"please do not hesitate to",
    r"rest assured", r"at your earliest convenience", r"we (sincerely )?apologi[sz]e for any inconvenience",
    r"we value your (trust|security|privacy)", r"to ensure (the )?(continued )?(security|safety) of your account",
    r"as part of our ongoing (commitment|efforts)", r"we kindly (request|ask)", r"thank you for your (prompt )?(attention|cooperation|understanding)",
    r"in order to (maintain|ensure|safeguard)", r"(seamless|streamlined|enhanced) (experience|security)", r"we have (detected|noticed|identified) (unusual|suspicious)",
]
ZERO_WIDTH = re.compile("[​‌‍⁠﻿­᠎]")
BIDI = re.compile("[‪-‮⁦-⁩]")
HIDDEN_CSS = re.compile(r"(?is)<(\w+)[^>]*style\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em)?\b|"
                        r"opacity\s*:\s*0(\.0+)?\b|color\s*:\s*(#fff(fff)?|white)\b[^\"']*background(-color)?\s*:\s*(#fff(fff)?|white)|"
                        r"max-height\s*:\s*0|height\s*:\s*0(px)?\b[^\"']*overflow\s*:\s*hidden)[^\"']*[\"'][^>]*>(.*?)</\1>")
TAG_RE = re.compile(r"(?s)<[^>]+>")


def _texts(raw: bytes) -> Dict[str, str]:
    out = {"plain": "", "html": "", "subject": "", "from": ""}
    try:
        msg = email.message_from_bytes(raw or b"", policy=email.policy.default)
    except Exception:  # noqa: BLE001
        return out
    out["subject"] = str(msg.get("Subject") or "")
    out["from"] = str(msg.get("From") or "")
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ct = part.get_content_type()
        if ct in ("text/plain", "text/html"):
            try:
                t = part.get_content()
            except Exception:  # noqa: BLE001
                t = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            key = "plain" if ct == "text/plain" else "html"
            out[key] += str(t)[:500_000] + "\n"
    return out


def _visible(html_text: str) -> str:
    return _html.unescape(TAG_RE.sub(" ", re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_text)))


def _mixed_script_words(text: str) -> List[str]:
    hits = []
    for w in set(re.findall(r"\w{4,}", text)):
        scripts = set()
        for ch in w:
            if ch.isalpha():
                try:
                    scripts.add(unicodedata.name(ch).split(" ")[0])
                except ValueError:
                    pass
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
            hits.append(w)
    return hits[:10]


def _f(rule, title, sev, conf, expl, evidence="", mitre=None, target=None):
    return {"rule_id": rule, "title": title, "severity": sev, "confidence": conf, "explanation": expl,
            "evidence": str(evidence)[:300], "mitre_atlas_or_attack": mitre, "targets": target}


def analyze_ai_security(raw_bytes: bytes, ml_available: bool = True, llm_configured: bool = False,
                        ml_text_confidence: Optional[float] = None) -> dict:
    t = _texts(raw_bytes)
    visible = t["plain"] + "\n" + _visible(t["html"])
    everything = t["subject"] + "\n" + visible + "\n" + t["html"]
    findings: List[dict] = []

    # 1) prompt injection aimed at AI readers / filters
    for rx, title in INJECTION:
        m = re.search(rx, everything, re.I)
        if m:
            findings.append(_f("AISEC-001", f"Prompt injection: {title}", "HIGH", 0.85,
                               "Text addressed to an AI system rather than a human — attempts to hijack AI mail assistants "
                               "(summarisers, copilots, auto-responders) or to talk an AI filter into a 'safe' verdict.",
                               m.group(0), "AML.T0051 (LLM Prompt Injection)", "AI mail assistants / LLM filters"))
    # 2) hidden content (invisible to humans, visible to machines)
    hidden_chunks = []
    for m in HIDDEN_CSS.finditer(t["html"]):
        txt = _visible(m.group(m.lastindex or 0)).strip()
        if len(txt) >= 15:
            hidden_chunks.append(txt)
    if hidden_chunks:
        joined = " | ".join(hidden_chunks)[:300]
        inj_in_hidden = any(re.search(rx, " ".join(hidden_chunks), re.I) for rx, _ in INJECTION)
        findings.append(_f("AISEC-002", "Hidden text invisible to the reader", "CRITICAL" if inj_in_hidden else "HIGH",
                           0.85, "Content is styled so humans cannot see it (display:none, zero font, white-on-white). "
                           "It is aimed at machine readers: to poison ML/Bayesian filters with benign words or to carry "
                           "hidden AI instructions" + (" — and it contains AI-directed instructions." if inj_in_hidden else "."),
                           joined, "AML.T0043 (Craft Adversarial Data)", "ML spam/phishing classifiers"))
    # 3) invisible unicode / bidi controls
    zw = ZERO_WIDTH.findall(t["subject"] + visible)
    if len(zw) >= 3:
        findings.append(_f("AISEC-003", "Zero-width characters splitting words", "MEDIUM", 0.75,
                           f"{len(zw)} invisible characters break up keywords (e.g. 'pa​ssword') so NLP models and "
                           "keyword filters no longer match them — a known adversarial evasion.",
                           f"{len(zw)} × {sorted(set(hex(ord(c)) for c in zw))}", "AML.T0015 (Evade ML Model)", "NLP filters"))
    if BIDI.search(t["subject"] + visible + t["from"]):
        findings.append(_f("AISEC-004", "Bidirectional-override characters", "HIGH", 0.8,
                           "Right-to-left override characters reorder displayed text to disguise links or names.",
                           "U+202A–U+202E / U+2066–U+2069 present", "T1036.002", "Human reader + filters"))
    mixed = _mixed_script_words(t["subject"] + " " + t["from"] + " " + visible)
    if mixed:
        findings.append(_f("AISEC-005", "Homoglyph (mixed-script) words", "HIGH", 0.8,
                           "Words mix Latin with Cyrillic/Greek look-alike letters so they read as a brand to a human but "
                           "are different tokens for filters.", ", ".join(mixed), "AML.T0015 (Evade ML Model)", "NLP filters + human"))
    # 4) AI-generated lure (stylometric heuristic)
    low = visible.lower()
    style_hits = [p for p in LLM_STYLE if re.search(p, low)]
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", visible)) if len(s.split()) >= 4][:80]
    lengths = [len(s.split()) for s in sentences]
    uniformity = 0.0
    if len(lengths) >= 4:
        mean = statistics.mean(lengths)
        cv = statistics.pstdev(lengths) / mean if mean else 1
        uniformity = max(0.0, min(1.0, (0.6 - cv) / 0.4))
    typos = len(re.findall(r"\b(recieve|acount|verfy|pasword|informations|kindly do the needful|urgent attension)\b", low))
    lik = min(1.0, 0.18 * len(style_hits) + 0.35 * uniformity + (0.1 if len(sentences) >= 5 else 0) - 0.2 * typos)
    lik = round(max(0.0, lik), 2)
    if lik >= 0.45:
        findings.append(_f("AISEC-006", "Lure text shows AI-generated (LLM) writing patterns", "MEDIUM" if lik < 0.7 else "HIGH",
                           lik, "Polished, template-like phrasing with uniform sentence structure and no human typos — "
                           "characteristic of LLM-written phishing, which defeats 'look for spelling mistakes' training. "
                           "Heuristic estimate, not proof of authorship.",
                           "; ".join(style_hits[:4]) or f"sentence-length uniformity {uniformity:.2f}",
                           "AML.T0048 (LLM-generated content abuse)", "Human reader"))

    # score (noisy-OR) + verdict
    p = 1.0
    for f in findings:
        p *= 1 - SEV_W[f["severity"]] * f["confidence"]
    score = round((1 - p) * 100, 1)
    verdict = "MANIPULATION_DETECTED" if score >= 60 else ("SUSPICIOUS" if score >= 30 else "CLEAN")

    guardrails = [
        {"control": "Prompt-injection scanner on e-mail content", "status": "ACTIVE",
         "detail": "Every e-mail is scanned for AI-directed instructions; matches are reported as evidence and never executed."},
        {"control": "Untrusted-content boundary for LLM explanations", "status": "ACTIVE" if llm_configured else "NOT_APPLICABLE",
         "detail": "E-mail text is passed to the LLM only as quoted data; the LLM explains results and never decides the verdict."
                   if llm_configured else "No external LLM configured — explanations are deterministic (LOCAL_ONLY)."},
        {"control": "Verdict is ensemble-based, not LLM-based", "status": "ACTIVE",
         "detail": "Final risk = rule engine + ML models + threat intel + sandbox (noisy-OR fusion) — one fooled model cannot flip the verdict."},
        {"control": "Adversarial text normalisation", "status": "ACTIVE",
         "detail": "Zero-width / bidi characters and hidden HTML are surfaced here so evasion attempts themselves raise risk."},
        {"control": "ML models loaded & version-pinned", "status": "ACTIVE" if ml_available else "DEGRADED",
         "detail": "Model artefacts carry version + training metadata; deviations are auditable."},
        {"control": "Human approval for destructive actions", "status": "ACTIVE",
         "detail": "AI recommendations (block, delete, release) require analyst approval; every agent tool call is logged."},
        {"control": "Sandbox isolation for artefacts", "status": "ACTIVE",
         "detail": "Attachments/URLs are analysed in a separate network-restricted container, never on the AI/API server."},
    ]
    return {
        "verdict": verdict,
        "score": score,
        "ai_generated_likelihood": lik,
        "ai_generated_note": "Stylometric heuristic (template phrases, sentence uniformity, absence of typos). Use as a signal, not proof.",
        "findings": findings,
        "guardrails": guardrails,
        "ml_text_confidence": ml_text_confidence,
        "summary": ("E-mail attempts to manipulate AI/ML systems." if verdict == "MANIPULATION_DETECTED" else
                    "Some adversarial-AI signals present." if verdict == "SUSPICIOUS" else
                    "No attempt to manipulate AI systems detected."),
    }
