"""PDF structural analysis (pdfid-style keyword counting + bounded stream
inflation to see JavaScript / URIs hidden in compressed streams)."""
from __future__ import annotations

import re
import zlib
from typing import Dict, List, Tuple

from ..rules import Finding

KEYS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/URI", "/SubmitForm",
        "/AcroForm", "/XFA", "/RichMedia", "/ObjStm", "/Encrypt", "/GoToR", "/GoToE"]
STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
NAME_HEX_RE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _normalize(data: bytes) -> Tuple[bytes, bool]:
    """Decode '#xx' escapes inside PDF names (/J#61vaScript → /JavaScript)."""
    obf = bool(re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data))
    return NAME_HEX_RE.sub(lambda m: bytes([int(m.group(1), 16)]), data), obf


def _inflate_streams(data: bytes, budget: int = 20_000_000) -> bytes:
    out = []
    for m in list(STREAM_RE.finditer(data))[:400]:
        raw = m.group(1)
        try:
            d = zlib.decompressobj()
            chunk = d.decompress(raw, max(0, min(budget, 5_000_000)))
        except zlib.error:
            continue
        budget -= len(chunk)
        out.append(chunk)
        if budget <= 0:
            break
    return b"\n".join(out)


def analyze_pdf(data: bytes, filename: str) -> Tuple[List[Finding], Dict[str, int], bytes]:
    out: List[Finding] = []
    norm, obfuscated = _normalize(data)
    inflated = _inflate_streams(norm)
    blob = norm + b"\n" + inflated
    counts = {k: len(re.findall(re.escape(k.encode()) + rb"(?![A-Za-z])", blob)) for k in KEYS}

    if obfuscated:
        out.append(Finding("SBX-PDF-001", "Obfuscated PDF names", "HIGH", 0.8, "pdf",
                           "PDF keywords are hex-escaped (e.g. /J#61vaScript) — only done to evade scanners.", filename, "T1027"))
    if counts["/JavaScript"] or counts["/JS"]:
        out.append(Finding("SBX-PDF-002", "Embedded JavaScript", "HIGH", 0.8, "pdf",
                           "PDF contains JavaScript, used for exploits and for redirecting to phishing pages.",
                           f"/JavaScript×{counts['/JavaScript']} /JS×{counts['/JS']}", "T1059.007",
                           "Runs JavaScript inside the PDF reader."))
    auto = counts["/OpenAction"] + counts["/AA"]
    if auto and (counts["/JavaScript"] or counts["/JS"] or counts["/Launch"] or counts["/URI"]):
        out.append(Finding("SBX-PDF-003", "Automatic action on open", "HIGH", 0.85, "pdf",
                           "/OpenAction or /AA triggers script / launch / URL the moment the PDF is opened.",
                           f"/OpenAction×{counts['/OpenAction']} /AA×{counts['/AA']}", "T1204.002",
                           "Acts automatically on open without a click."))
    if counts["/Launch"]:
        out.append(Finding("SBX-PDF-004", "Launch action", "CRITICAL", 0.9, "pdf",
                           "/Launch can start an external program or command.", f"/Launch×{counts['/Launch']}", "T1204.002",
                           "Attempts to start an external executable."))
    if counts["/EmbeddedFile"]:
        out.append(Finding("SBX-PDF-005", "Embedded file", "MEDIUM", 0.7, "pdf",
                           "PDF carries an embedded file (possible dropper).", f"/EmbeddedFile×{counts['/EmbeddedFile']}", "T1027.006"))
    if counts["/SubmitForm"] or (counts["/AcroForm"] and counts["/URI"]):
        out.append(Finding("SBX-PDF-006", "Form that submits data externally", "MEDIUM", 0.65, "pdf",
                           "Interactive form posts data to a remote server — typical of credential-harvest PDFs.",
                           f"/SubmitForm×{counts['/SubmitForm']} /AcroForm×{counts['/AcroForm']}", "T1056.003"))
    if counts["/XFA"] or counts["/RichMedia"]:
        out.append(Finding("SBX-PDF-007", "XFA / RichMedia content", "MEDIUM", 0.6, "pdf",
                           "Rich or XFA forms enlarge the reader attack surface and are rare in normal documents.",
                           f"/XFA×{counts['/XFA']} /RichMedia×{counts['/RichMedia']}", "T1203"))
    if counts["/GoToR"] or counts["/GoToE"]:
        out.append(Finding("SBX-PDF-008", "Remote go-to action", "MEDIUM", 0.6, "pdf",
                           "Jumps to a remote document (can leak NTLM hashes over SMB).", "/GoToR", "T1187"))
    return out, counts, inflated
