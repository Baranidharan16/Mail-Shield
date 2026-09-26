"""ZIP-family archive inspection with zip-bomb guards. Members are read into
memory (never written to disk) and handed back to the engine for recursive
static analysis up to a fixed depth / byte budget."""
from __future__ import annotations

import io
import os
import zipfile
from typing import List, Tuple

from ..rules import Finding
from .filetype import EXECUTABLE_EXT, SCRIPT_EXT, SHORTCUT_EXT, DISK_IMAGE_EXT

MAX_MEMBERS = 50
MAX_MEMBER_BYTES = 15_000_000
MAX_TOTAL_BYTES = 40_000_000


def unpack_zip(data: bytes, filename: str) -> Tuple[List[Finding], List[Tuple[str, bytes]], dict]:
    out: List[Finding] = []
    members: List[Tuple[str, bytes]] = []
    info = {"entries": 0, "encrypted": False, "listing": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return [Finding("SBX-ARC-009", "Corrupt archive", "LOW", 0.5, "archive",
                        "Archive could not be opened (possibly truncated or deliberately malformed).", filename)], [], info
    infos = zf.infolist()
    info["entries"] = len(infos)
    info["listing"] = [{"name": i.filename, "size": i.file_size, "compressed": i.compress_size} for i in infos[:100]]
    total_unc = sum(i.file_size for i in infos)
    total_c = sum(i.compress_size for i in infos) or 1
    if total_unc > 500_000_000 or (total_unc / total_c > 200 and total_unc > 50_000_000):
        out.append(Finding("SBX-ARC-001", "Decompression bomb", "HIGH", 0.85, "archive",
                           f"Expands to {total_unc:,} bytes (ratio {total_unc / total_c:.0f}:1) — designed to exhaust scanners.",
                           filename, "T1499"))
        return out, [], info
    if any(i.flag_bits & 0x1 for i in infos):
        info["encrypted"] = True
        out.append(Finding("SBX-ARC-002", "Password-protected archive", "HIGH", 0.8, "archive",
                           "Encrypted archives cannot be scanned by mail gateways; the password is usually in the e-mail body.",
                           ", ".join(i.filename for i in infos[:5]), "T1027.013",
                           "Victim extracts content that no gateway could inspect."))
    risky = [i.filename for i in infos if os.path.splitext(i.filename.lower())[1] in (EXECUTABLE_EXT | SCRIPT_EXT | SHORTCUT_EXT | DISK_IMAGE_EXT)]
    if risky:
        out.append(Finding("SBX-ARC-003", "Executable / script inside archive", "HIGH", 0.85, "archive",
                           "The archive wraps directly executable content to evade attachment-type filters.",
                           ", ".join(risky[:6]), "T1027", "Victim extracts and runs the payload."))
    if len(infos) == 1 and risky:
        out.append(Finding("SBX-ARC-004", "Single-payload archive", "MEDIUM", 0.6, "archive",
                           "An archive containing exactly one executable/script is a classic loader delivery pattern.",
                           risky[0], "T1204.002"))
    budget = MAX_TOTAL_BYTES
    for i in infos[:MAX_MEMBERS]:
        if i.is_dir() or i.flag_bits & 0x1 or i.file_size > MAX_MEMBER_BYTES or i.file_size > budget:
            continue
        try:
            with zf.open(i) as fh:
                b = fh.read(MAX_MEMBER_BYTES + 1)
        except Exception:  # noqa: BLE001
            continue
        budget -= len(b)
        members.append((i.filename, b))
    return out, members, info
