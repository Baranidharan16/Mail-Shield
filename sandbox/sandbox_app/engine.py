"""Sandbox analysis engine: runs every static analyzer that applies to a file
(dispatched on the REAL detected type), recursively for archive members,
then produces a per-file and overall Safe / Suspicious / Malicious verdict
with reasons, IOCs, MITRE ATT&CK mapping and a predicted-behaviour profile.

Nothing here executes, renders, mounts or fetches the analysed content.
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .analyzers import archive, executable, filetype, html, office, pdf, strings_ioc, url as url_an
from .rules import Finding, decide

ENGINE_VERSION = "mailshield-sandbox/1.0.0 (static)"
MAX_DEPTH = 2
MAX_FILES = 12
MAX_FILE_BYTES = int(os.getenv("SANDBOX_MAX_FILE_BYTES", str(20 * 1024 * 1024)))
MAX_URLS = 60

_BLOCKLIST_PATH = Path(os.getenv("SANDBOX_BLOCKLIST", str(Path(__file__).parent / "data" / "known_bad_sha256.txt")))


def _load_blocklist() -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in _BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                h, _, label = line.partition(" ")
                out[h.lower()] = label.strip() or "known malicious sample"
    except OSError:
        pass
    return out


BLOCKLIST = _load_blocklist()


def analyze_file(filename: str, declared_ctype: str, data: bytes, depth: int = 0) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    detected = filetype.detect_type(data, filename)
    findings: List[Finding] = []
    children: List[dict] = []
    extra: dict = {}

    if sha256 in BLOCKLIST:
        findings.append(Finding("SBX-REP-001", "Known-malicious file hash", "CRITICAL", 1.0, "reputation",
                                f"SHA-256 matches the local threat-intel blocklist ({BLOCKLIST[sha256]}).", sha256))

    fn_findings, ext = filetype.filename_checks(filename, detected, declared_ctype)
    findings += fn_findings

    s_findings, iocs, sample = strings_ioc.scan_bytes(data, filename or "attachment")
    findings += s_findings

    if detected in ("Word OOXML", "Excel OOXML", "PowerPoint OOXML", "OOXML container"):
        findings += office.analyze_ooxml(data, filename)
    elif detected.startswith("OLE2"):
        findings += office.analyze_ole(data, filename)
    elif detected == "RTF document":
        findings += office.analyze_rtf(data, filename)
    elif detected == "PDF document":
        pf, counts, inflated = pdf.analyze_pdf(data, filename)
        findings += pf
        extra["pdf_keywords"] = {k: v for k, v in counts.items() if v}
        if inflated:
            more, more_iocs, _ = strings_ioc.scan_bytes(inflated[:5_000_000], f"{filename} (decompressed streams)")
            findings += more
            for k in iocs:
                iocs[k] = sorted(set(iocs[k]) | set(more_iocs.get(k, [])))[:100]
    elif detected in ("HTML document", "SVG image"):
        findings += html.analyze_html(data.decode("utf-8", "ignore"), filename)
    elif detected == "PE executable":
        pf, meta = executable.analyze_pe(data, filename)
        findings += pf
        extra["pe"] = meta
    elif detected == "Windows shortcut (LNK)":
        findings += executable.analyze_lnk(data, filename)

    # macro source extracted by olevba is scanned like any script
    for f in list(findings):
        if f.rule_id == "SBX-MAC-000":
            findings.remove(f)
            findings += strings_ioc.scan_text(f.evidence, f"VBA macro of {filename}")
            iocs["urls"] = sorted(set(iocs["urls"]) | set(strings_ioc.harvest_iocs(f.evidence)["urls"]))[:100]

    if detected in ("ZIP archive", "Java archive", "Android package") and depth < MAX_DEPTH:
        af, members, info = archive.unpack_zip(data, filename)
        findings += af
        extra["archive"] = info
        for name, b in members[:MAX_FILES]:
            children.append(analyze_file(name, "", b, depth + 1))
    elif detected == "ZIP archive (corrupt)":
        findings.append(Finding("SBX-ARC-009", "Corrupt / malformed archive", "MEDIUM", 0.6, "archive",
                                "Archive structure is invalid — malformed containers are used to crash or evade scanners "
                                "while still opening in some extraction tools.", filename, "T1027"))
    elif detected in ("RAR archive", "7-Zip archive", "CAB archive", "GZIP archive"):
        findings.append(Finding("SBX-ARC-005", f"{detected} (contents not unpacked)", "MEDIUM", 0.55, "archive",
                                "This container format is not unpacked by the prototype sandbox; archives are a common "
                                "way to smuggle payloads past gateways — treat contents as untrusted.", filename, "T1027"))

    # child verdicts roll up into the parent
    for c in children:
        if c["verdict"] != "SAFE":
            findings.append(Finding("SBX-ARC-010", f"Archive member '{c['filename']}' is {c['verdict'].lower()}",
                                    "CRITICAL" if c["verdict"] == "MALICIOUS" else "MEDIUM",
                                    0.9 if c["verdict"] == "MALICIOUS" else 0.6, "archive",
                                    "; ".join(c["reasons"][:2]), c["sha256"]))

    # URLs found inside the file are analysed statically as well
    url_findings = []
    for u in iocs.get("urls", [])[:20]:
        for uf in url_an.analyze_url(u):
            if uf.severity in ("HIGH", "CRITICAL"):
                uf.explanation = f"URL embedded in {filename}: " + uf.explanation
                url_findings.append(uf)
    findings += url_findings[:10]

    # deduplicate by rule id (keep strongest)
    best: Dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in best or f.weight() > best[f.rule_id].weight():
            best[f.rule_id] = f
    findings = list(best.values())
    v = decide(findings)
    behaviors = sorted({f"{f.behavior} ({f.mitre})" if f.mitre else f.behavior for f in findings if f.behavior})
    return {
        "filename": filename or "unnamed",
        "declared_content_type": declared_ctype or None,
        "extension": ext or None,
        "detected_type": detected,
        "size_bytes": len(data),
        "sha256": sha256,
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - identification only
        "entropy": filetype.entropy(data),
        "verdict": v.verdict,
        "score": v.score,
        "reasons": v.reasons,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: f.weight(), reverse=True)],
        "iocs": iocs,
        "mitre_techniques": sorted({f.mitre for f in findings if f.mitre}),
        "predicted_behavior": behaviors,
        "strings_sample": sample[:25],
        "children": children,
        **extra,
    }


def analyze_request(payload: dict) -> dict:
    started = datetime.now(timezone.utc)
    files_out: List[dict] = []
    skipped: List[dict] = []
    for a in (payload.get("attachments") or [])[:MAX_FILES]:
        name = str(a.get("filename") or "unnamed")[:255]
        try:
            data = base64.b64decode(a.get("data_b64") or "", validate=False)
        except Exception:  # noqa: BLE001
            skipped.append({"filename": name, "reason": "invalid base64"})
            continue
        if len(data) > MAX_FILE_BYTES:
            skipped.append({"filename": name, "reason": f"exceeds {MAX_FILE_BYTES} byte limit",
                            "sha256": hashlib.sha256(data).hexdigest()})
            continue
        files_out.append(analyze_file(name, str(a.get("content_type") or "")[:128], data))

    url_out = []
    seen = set()
    for u in (payload.get("urls") or [])[:MAX_URLS]:
        u = str(u)[:2048]
        if u in seen:
            continue
        seen.add(u)
        fs = url_an.analyze_url(u)
        v = decide(fs)
        url_out.append({"url": u, "verdict": v.verdict, "score": v.score, "reasons": v.reasons,
                        "findings": [f.to_dict() for f in fs],
                        "mitre_techniques": sorted({f.mitre for f in fs if f.mitre})})

    html_findings: List[Finding] = []
    for i, h in enumerate((payload.get("html_bodies") or [])[:3]):
        html_findings += html.analyze_html(str(h)[:3_000_000], f"e-mail HTML body #{i + 1}")
    body_v = decide(html_findings)

    # overall = noisy-OR over every component's own findings (no double counting)
    all_findings: List[Finding] = list(html_findings)
    for f in files_out:
        all_findings += [Finding(**x) for x in f["findings"]]
    for u in url_out:
        all_findings += [Finding(**x) for x in u["findings"]]
    overall = decide(all_findings)
    if any(f["verdict"] == "MALICIOUS" for f in files_out) or any(u["verdict"] == "MALICIOUS" for u in url_out) \
            or body_v.verdict == "MALICIOUS":
        overall.verdict = "MALICIOUS"
    elif overall.verdict == "SAFE" and (any(f["verdict"] == "SUSPICIOUS" for f in files_out)
                                        or any(u["verdict"] == "SUSPICIOUS" for u in url_out) or body_v.verdict == "SUSPICIOUS"):
        overall.verdict = "SUSPICIOUS"

    behaviors = sorted({b for f in files_out for b in f["predicted_behavior"]} |
                       {f"{x.behavior} ({x.mitre})" if x.mitre else x.behavior for x in html_findings + [
                           Finding(**y) for u in url_out for y in u["findings"]] if x.behavior})
    mitre = sorted({t for f in files_out for t in f["mitre_techniques"]} | {t for u in url_out for t in u["mitre_techniques"]}
                   | {x.mitre for x in html_findings if x.mitre})
    finished = datetime.now(timezone.utc)
    return {
        "request_id": payload.get("request_id"),
        "engine_version": ENGINE_VERSION,
        "analysis_mode": "STATIC_CONTROLLED",
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "verdict": overall.verdict,
        "score": overall.score,
        "reasons": overall.reasons,
        "files": files_out,
        "skipped_files": skipped,
        "urls": url_out,
        "html_body": {"verdict": body_v.verdict, "score": body_v.score, "findings": [f.to_dict() for f in html_findings]},
        "predicted_behavior": behaviors,
        "mitre_techniques": mitre,
        "summary": {
            "files_analyzed": len(files_out), "urls_analyzed": len(url_out),
            "malicious_files": sum(1 for f in files_out if f["verdict"] == "MALICIOUS"),
            "suspicious_files": sum(1 for f in files_out if f["verdict"] == "SUSPICIOUS"),
            "malicious_urls": sum(1 for u in url_out if u["verdict"] == "MALICIOUS"),
            "suspicious_urls": sum(1 for u in url_out if u["verdict"] == "SUSPICIOUS"),
        },
    }
