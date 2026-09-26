"""Header-level parsing of Windows PE files and LNK shortcuts (no loading,
no execution)."""
from __future__ import annotations

import datetime as _dt
import re
import struct
from typing import Dict, List, Tuple

from ..rules import Finding
from .filetype import entropy


def analyze_pe(data: bytes, filename: str) -> Tuple[List[Finding], Dict]:
    out: List[Finding] = []
    meta: Dict = {}
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return out, {"valid_pe": False}
        machine, nsec, ts = struct.unpack_from("<HHI", data, e_lfanew + 4)
        opt_size, chars = struct.unpack_from("<HH", data, e_lfanew + 20)
        meta = {"valid_pe": True, "machine": hex(machine), "sections": nsec, "is_dll": bool(chars & 0x2000),
                "compile_time_utc": _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat() if ts else None}
        sec_off = e_lfanew + 24 + opt_size
        secs = []
        for i in range(min(nsec, 40)):
            o = sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1", "ignore")
            raw_size, raw_ptr = struct.unpack_from("<II", data, o + 16)
            ent = entropy(data[raw_ptr:raw_ptr + raw_size]) if raw_size else 0.0
            secs.append({"name": name, "raw_size": raw_size, "entropy": ent})
        meta["section_table"] = secs
        if any(s["name"].upper().startswith(("UPX", ".ASPACK", ".MPRESS", ".THEMIDA", ".VMP")) for s in secs):
            out.append(Finding("SBX-PE-001", "Packed executable", "HIGH", 0.8, "executable",
                               "Known packer section names — packing hides the real code from static scanners.",
                               ", ".join(s["name"] for s in secs), "T1027.002"))
        elif any(s["entropy"] > 7.2 and s["raw_size"] > 4096 for s in secs):
            out.append(Finding("SBX-PE-002", "High-entropy (encrypted/compressed) section", "MEDIUM", 0.65, "executable",
                               "Section entropy above 7.2 suggests an encrypted or packed payload.",
                               ", ".join(f"{s['name']}={s['entropy']}" for s in secs if s["entropy"] > 7.2), "T1027.002"))
        if ts and ts > _dt.datetime.now(_dt.timezone.utc).timestamp() + 86400:
            out.append(Finding("SBX-PE-003", "Future compile timestamp", "LOW", 0.5, "executable",
                               "Compile time is in the future — timestamps are often forged.", meta["compile_time_utc"], "T1070.006"))
    except Exception:  # noqa: BLE001
        meta = {"valid_pe": False}
    return out, meta


def analyze_lnk(data: bytes, filename: str) -> List[Finding]:
    text = data.decode("utf-16le", "ignore") + "\n" + data.decode("latin-1", "ignore")
    m = re.search(r"(?i)(powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl)[^\x00]{0,160}", text)
    if m:
        return [Finding("SBX-LNK-001", "Shortcut launches a command interpreter", "CRITICAL", 0.9, "script",
                        "The LNK target runs a shell / LOLBin with arguments — a common initial-access dropper.",
                        m.group(0)[:200], "T1204.002", "Launches a hidden command that downloads or runs malware.")]
    return []
