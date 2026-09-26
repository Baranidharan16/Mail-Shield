"""Office document analysis: VBA macros (oletools/olevba, parse-only — VBA is
never executed), OOXML remote-template injection, DDE, embedded OLE objects,
and RTF exploit markers."""
from __future__ import annotations

import io
import re
import zipfile
from typing import List

from ..rules import Finding

try:  # oletools is optional at import time so unit tests still run without it
    from oletools.olevba import VBA_Parser  # type: ignore
    HAVE_OLEVBA = True
except Exception:  # noqa: BLE001
    HAVE_OLEVBA = False


def _vba(data: bytes, filename: str) -> List[Finding]:
    out: List[Finding] = []
    if not HAVE_OLEVBA:
        if re.search(rb"(?i)(vbaproject|attribute vb_name|autoopen|document_open|workbook_open)", data):
            out.append(Finding("SBX-MAC-001", "VBA macro present", "HIGH", 0.7, "macro",
                               "Macro project markers found (olevba unavailable, byte-level detection).", filename, "T1059.005"))
        return out
    vp = None
    try:
        vp = VBA_Parser(filename or "doc", data=data)
        if not vp.detect_vba_macros():
            return out
        code_parts = []
        for (_f, _s, vname, code) in vp.extract_macros():
            if code:
                code_parts.append(f"' --- {vname}\n{code[:20000]}")
        out.append(Finding("SBX-MAC-001", "VBA macro present", "MEDIUM", 0.8, "macro",
                           f"Document contains {len(code_parts)} VBA module(s). Macros are the #1 Office malware vector.",
                           ", ".join(p.split("\n", 1)[0][6:] for p in code_parts[:5]), "T1059.005"))
        autoexec, suspicious, iocs = [], [], []
        for kw_type, keyword, desc in vp.analyze_macros():
            if kw_type == "AutoExec":
                autoexec.append(keyword)
            elif kw_type == "Suspicious":
                suspicious.append(f"{keyword} ({desc})")
            elif kw_type == "IOC":
                iocs.append(keyword)
        if autoexec:
            out.append(Finding("SBX-MAC-002", "Auto-executing macro", "HIGH", 0.9, "macro",
                               "Macro runs automatically when the document is opened / closed / content enabled.",
                               ", ".join(autoexec[:6]), "T1204.002", "Runs as soon as the victim clicks 'Enable Content'."))
        if suspicious:
            shellish = [s for s in suspicious if re.search(r"(?i)shell|run|exec|createobject|powershell|wscript|call", s)]
            out.append(Finding("SBX-MAC-003", "Suspicious macro behaviour", "HIGH" if shellish else "MEDIUM", 0.85, "macro",
                               "olevba flagged suspicious VBA keywords.", "; ".join(suspicious[:8]), "T1059.005",
                               "Macro " + ("launches external processes." if shellish else "performs file / network operations.")))
        if autoexec and any(re.search(r"(?i)shell|powershell|wscript|createobject|exec", s) for s in suspicious):
            out.append(Finding("SBX-MAC-004", "Auto-exec macro that launches a shell", "CRITICAL", 0.92, "macro",
                               "Classic malicious-document (maldoc) pattern: auto-open + process execution.",
                               ", ".join(autoexec[:3]) + " → " + ", ".join(suspicious[:3]), "T1204.002",
                               "Opening the document with macros enabled spawns a command / PowerShell process."))
        if iocs:
            out.append(Finding("SBX-MAC-005", "Network IOCs embedded in macro", "HIGH", 0.8, "ioc",
                               "URLs / IPs / executable names hard-coded inside VBA.", ", ".join(iocs[:8]), "T1105",
                               "Macro contacts the listed infrastructure."))
        # macro code is also passed to the string scanner by the caller
        out.append(Finding("SBX-MAC-000", "__macro_source__", "INFO", 0.0, "macro", "", "\n".join(code_parts)[:60000]))
    except Exception as exc:  # noqa: BLE001
        out.append(Finding("SBX-MAC-009", "Macro parser error", "LOW", 0.5, "macro",
                           "The document could not be fully parsed — malformed structures are sometimes deliberate.",
                           type(exc).__name__))
    finally:
        try:
            if vp:
                vp.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def analyze_ooxml(data: bytes, filename: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return [Finding("SBX-OFF-009", "Corrupt OOXML container", "LOW", 0.5, "file_type", "Could not open the Office zip.", filename)]
    names = zf.namelist()[:3000]
    lower = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lower):
        out += _vba(data, filename)
    if any("activex" in n for n in lower):
        out.append(Finding("SBX-OFF-001", "ActiveX control embedded", "MEDIUM", 0.7, "macro",
                           "ActiveX controls can auto-run code on document open.", "activeX parts present", "T1559"))
    if any("embeddings/" in n and (n.endswith(".bin") or "oleobject" in n) for n in lower):
        out.append(Finding("SBX-OFF-002", "Embedded OLE object", "MEDIUM", 0.65, "macro",
                           "Embedded OLE objects can package executables or scripts shown as innocent icons.",
                           ", ".join(n for n in names if "embeddings/" in n.lower())[:200], "T1027.006",
                           "Victim double-clicks the icon and runs the embedded payload."))
    budget = 5_000_000
    for n in names:
        nl = n.lower()
        if not (nl.endswith(".rels") or nl.endswith("document.xml") or nl.endswith(".xml")) or budget <= 0:
            continue
        try:
            info = zf.getinfo(n)
            if info.file_size > 2_000_000:
                continue
            xml = zf.read(n).decode("utf-8", "ignore")
            budget -= len(xml)
        except Exception:  # noqa: BLE001
            continue
        if nl.endswith(".rels"):
            for m in re.finditer(r'Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"[^>]*Target="(https?://[^"]+)"[^>]*TargetMode="External"', xml):
                out.append(Finding("SBX-OFF-003", "Remote template / external object injection", "CRITICAL", 0.9, "macro",
                                   f"Document silently fetches a remote '{m.group(1)}' when opened — used to load macro "
                                   "payloads or exploit Follina-style bugs without any macro in the file.",
                                   m.group(2), "T1221", "Downloads a remote template/object on open."))
            for m in re.finditer(r'Target="(mhtml:|ms-msdt:|search-ms:|ms-excel:)[^"]*"', xml):
                out.append(Finding("SBX-OFF-004", "Protocol-handler exploit link", "CRITICAL", 0.9, "macro",
                                   "Relationship targets a protocol handler abused by known Office RCEs (e.g. CVE-2022-30190 'Follina').",
                                   m.group(0)[:200], "T1203", "Triggers code execution through a Windows protocol handler."))
        if re.search(r"(?i)\b(DDEAUTO|DDE)\b\s", xml) and ("instrText" in xml or "fldSimple" in xml or "ddeService" in xml):
            out.append(Finding("SBX-OFF-005", "DDE field code", "HIGH", 0.85, "macro",
                               "Dynamic Data Exchange fields run commands without macros.",
                               re.search(r"(?i).{0,40}DDE.{0,80}", xml).group(0), "T1559.002", "Runs a command when fields update."))
    return out


def analyze_ole(data: bytes, filename: str) -> List[Finding]:
    out = _vba(data, filename)
    if re.search(rb"(?i)equation\.3|0002ce02-0000-0000-c000-000000000046", data):
        out.append(Finding("SBX-OFF-006", "Equation Editor object (CVE-2017-11882 family)", "CRITICAL", 0.85, "macro",
                           "Legacy Equation Editor objects are exploited for code execution without macros.", "Equation.3", "T1203",
                           "Exploits EQNEDT32.EXE to run shellcode on open."))
    return out


def analyze_rtf(data: bytes, filename: str) -> List[Finding]:
    out: List[Finding] = []
    if re.search(rb"\\objdata|\\objemb|\\objlink", data):
        out.append(Finding("SBX-RTF-001", "RTF embedded object", "MEDIUM", 0.7, "macro",
                           "RTF carries an embedded OLE object.", "\\objdata", "T1027.006"))
    if re.search(rb"\\objupdate", data):
        out.append(Finding("SBX-RTF-002", "RTF auto-updating object", "HIGH", 0.8, "macro",
                           "\\objupdate forces the embedded object to load on open — typical of RTF exploit kits.", "\\objupdate", "T1203",
                           "Loads the embedded object automatically."))
    if re.search(rb"(?i)0002ce02|equation\.3|4571756174696f6e2e33", data):
        out.append(Finding("SBX-OFF-006", "Equation Editor object (CVE-2017-11882 family)", "CRITICAL", 0.85, "macro",
                           "RTF references the Equation Editor CLSID used by well-known exploits.", "Equation.3 CLSID", "T1203",
                           "Exploits EQNEDT32.EXE to run shellcode on open."))
    return out
