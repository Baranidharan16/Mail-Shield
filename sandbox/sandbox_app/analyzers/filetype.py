"""True file-type identification from magic bytes (never trusts the extension
or the Content-Type the sender chose) + filename deception checks."""
from __future__ import annotations

import io
import math
import os
import zipfile
from collections import Counter
from typing import List, Tuple

from ..rules import Finding

EXECUTABLE_EXT = {".exe", ".scr", ".com", ".pif", ".dll", ".cpl", ".msi", ".msix", ".sys", ".elf", ".bin", ".apk", ".jar"}
SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".bat", ".cmd", ".hta", ".sct", ".reg", ".vb", ".py", ".sh"}
SHORTCUT_EXT = {".lnk", ".url", ".scf", ".library-ms", ".settingcontent-ms", ".appref-ms"}
DISK_IMAGE_EXT = {".iso", ".img", ".vhd", ".vhdx"}
MACRO_OFFICE_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".xlsb"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".csv", ".odt",
           ".jpg", ".jpeg", ".png", ".gif"} | MACRO_OFFICE_EXT
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".cab", ".arj", ".ace", ".xz", ".bz2"}

# detected family -> expected extensions
FAMILY_EXT = {
    "PE executable": EXECUTABLE_EXT, "ELF executable": {".elf", ".bin", ".so", ""},
    "PDF document": {".pdf"}, "OLE2 (legacy Office / MSI)": {".doc", ".xls", ".ppt", ".msi", ".dot", ".xlt", ".msg"},
    "Word OOXML": {".docx", ".docm", ".dotx", ".dotm"}, "Excel OOXML": {".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".xlam"},
    "PowerPoint OOXML": {".pptx", ".pptm", ".potx", ".ppsx", ".ppam"}, "ZIP archive": {".zip"},
    "Java archive": {".jar"}, "Android package": {".apk"}, "RAR archive": {".rar"}, "7-Zip archive": {".7z"},
    "GZIP archive": {".gz", ".tgz"}, "ISO disk image": {".iso", ".img"}, "Windows shortcut (LNK)": {".lnk"},
    "RTF document": {".rtf", ".doc"}, "HTML document": {".html", ".htm", ".shtml", ".xhtml", ".mht"},
    "SVG image": {".svg"}, "PNG image": {".png"}, "JPEG image": {".jpg", ".jpeg"}, "GIF image": {".gif"},
    "CAB archive": {".cab"},
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data[: 2_000_000])
    n = sum(counts.values())
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def _zip_family(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()[:2000]
    except Exception:  # noqa: BLE001
        return "ZIP archive (corrupt)"
    s = set(n.lower() for n in names)
    if "[content_types].xml" in s:
        if any(n.startswith("word/") for n in s):
            return "Word OOXML"
        if any(n.startswith("xl/") for n in s):
            return "Excel OOXML"
        if any(n.startswith("ppt/") for n in s):
            return "PowerPoint OOXML"
        return "OOXML container"
    if "androidmanifest.xml" in s:
        return "Android package"
    if "meta-inf/manifest.mf" in s:
        return "Java archive"
    return "ZIP archive"


def detect_type(data: bytes, filename: str = "") -> str:
    head = data[:64]
    low = data[:2048].lower().lstrip()
    if head.startswith(b"MZ"):
        return "PE executable"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head.startswith(b"%PDF") or b"%PDF-" in data[:1024]:
        return "PDF document"
    if head.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        return "OLE2 (legacy Office / MSI)"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _zip_family(data)
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR archive"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip archive"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP archive"
    if head.startswith(b"MSCF"):
        return "CAB archive"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO disk image"
    if head.startswith(bytes.fromhex("4C0000000114020000000000C000000000000046")):
        return "Windows shortcut (LNK)"
    if head.startswith(b"{\\rt"):
        return "RTF document"
    if head.startswith(b"\x89PNG"):
        return "PNG image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith(b"GIF8"):
        return "GIF image"
    if low.startswith(b"<svg") or (low.startswith(b"<?xml") and b"<svg" in low):
        return "SVG image"
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta", b"<form", b"<iframe")) or b"<html" in low[:512]:
        return "HTML document"
    printable = sum(1 for b in data[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    if data and printable / min(len(data), 4096) > 0.95:
        ext = os.path.splitext(filename.lower())[1]
        if ext in SCRIPT_EXT:
            return f"Script ({ext[1:].upper()})"
        return "Plain text"
    return "Unknown binary"


def filename_checks(filename: str, detected: str, declared_ctype: str) -> Tuple[List[Finding], str]:
    out: List[Finding] = []
    name = filename or "unnamed"
    lower = name.lower()
    ext = os.path.splitext(lower)[1]

    if "‮" in name:
        out.append(Finding("SBX-FN-001", "Right-to-left override in filename", "CRITICAL", 0.95, "file_type",
                           "The filename contains the Unicode RLO character, used to visually reverse an extension "
                           "(e.g. 'invoice‮gpj.exe' displays as 'invoiceexe.jpg').", repr(name), "T1036.002",
                           "Victim is tricked into launching an executable that looks like a document."))
    parts = lower.split(".")
    if len(parts) >= 3 and ("." + parts[-2]) in DOC_EXT and ("." + parts[-1]) in (EXECUTABLE_EXT | SCRIPT_EXT | SHORTCUT_EXT):
        out.append(Finding("SBX-FN-002", "Double extension disguise", "CRITICAL", 0.9, "file_type",
                           f"'{name}' pretends to be a .{parts[-2]} document but its real extension is .{parts[-1]}.",
                           name, "T1036.007", "Executes code when the victim opens what they believe is a document."))
    inner = [("." + x) for x in parts[1:-1] if ("." + x) in (EXECUTABLE_EXT | SCRIPT_EXT)]
    if inner and ext in ARCHIVE_EXT | DISK_IMAGE_EXT:
        out.append(Finding("SBX-FN-003", "Executable extension hidden inside archive name", "HIGH", 0.8, "file_type",
                           f"'{name}' advertises an inner {inner[0]} payload wrapped in a {ext} container — "
                           "a typical way to smuggle an executable past attachment filters.", name, "T1036.007",
                           "Victim extracts and runs the executable."))
    if ext in EXECUTABLE_EXT or detected in ("PE executable", "ELF executable"):
        out.append(Finding("SBX-FT-001", "Executable attachment", "CRITICAL", 0.9, "executable",
                           f"Native executable delivered by e-mail (detected: {detected}). Legitimate senders almost never "
                           "e-mail executables.", f"{name} → {detected}", "T1204.002",
                           "Runs attacker code with the victim's privileges when double-clicked."))
    if ext in SCRIPT_EXT or detected.startswith("Script"):
        out.append(Finding("SBX-FT-002", "Script attachment", "HIGH", 0.85, "script",
                           f"Script file ({ext or detected}) is directly executable by Windows Script Host / PowerShell / cmd.",
                           name, "T1059", "Script interpreter would execute the payload on double-click."))
    if ext in SHORTCUT_EXT or detected == "Windows shortcut (LNK)":
        out.append(Finding("SBX-FT-003", "Shortcut / LNK attachment", "HIGH", 0.85, "script",
                           "Shortcut files are a common initial-access vector: they silently launch cmd/powershell with arguments.",
                           name, "T1204.002", "Launches a hidden command line when opened."))
    if ext in DISK_IMAGE_EXT or detected == "ISO disk image":
        out.append(Finding("SBX-FT-004", "Disk-image container", "HIGH", 0.75, "archive",
                           "ISO/IMG/VHD containers are used to bypass Mark-of-the-Web and gateway scanning of the files inside.",
                           name, "T1553.005", "Mounts as a drive; files inside escape Office Protected View / SmartScreen."))
    if ext in MACRO_OFFICE_EXT:
        out.append(Finding("SBX-FT-005", "Macro-enabled Office format", "MEDIUM", 0.7, "macro",
                           f"The {ext} format exists specifically to carry VBA macros.", name, "T1566.001"))

    # extension vs real type mismatch
    expected = FAMILY_EXT.get(detected)
    if expected is not None and ext and ext not in expected and not (detected == "Plain text"):
        sev = "CRITICAL" if detected in ("PE executable", "ELF executable") else "HIGH"
        out.append(Finding("SBX-FT-006", "File extension does not match real content", sev, 0.85, "file_type",
                           f"Named '{ext}' but the magic bytes identify it as {detected}. Type spoofing is used to slip "
                           "past extension-based filters.", f"{name}: declared {declared_ctype or 'n/a'}, detected {detected}",
                           "T1036.008"))
    return out, ext
