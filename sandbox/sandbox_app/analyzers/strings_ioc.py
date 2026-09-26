"""String extraction + IOC (indicator of compromise) harvesting + suspicious
API / command keyword detection. Pure byte scanning — nothing is decoded into
executable form and nothing is run."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Dict, List, Tuple

from ..rules import Finding

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp|hxxps?)://[^\s\"'<>()\\\x00]{3,512}")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# (rule_id, regex, title, severity, confidence, category, mitre, behaviour)
KEYWORDS: List[Tuple[str, str, str, str, float, str, str, str]] = [
    ("SBX-STR-001", r"(?i)powershell(\.exe)?\b.{0,40}(-e(nc|ncodedcommand)?\b|-w(indowstyle)?\s+hidden|-nop|iex|invoke-expression)",
     "Hidden / encoded PowerShell command", "CRITICAL", 0.9, "script", "T1059.001",
     "Starts a hidden PowerShell process running an encoded command."),
    ("SBX-STR-002", r"(?i)\b(cmd(\.exe)?\s+/c|wscript\.shell|shell\.application|shellexecute|winexec)\b",
     "Command-shell execution primitive", "HIGH", 0.8, "script", "T1059.003", "Spawns a command shell."),
    ("SBX-STR-003", r"(?i)\b(urldownloadtofile|msxml2\.xmlhttp|winhttp\.winhttprequest|net\.webclient|downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|bitsadmin\s+/transfer)\b",
     "Remote payload download routine", "HIGH", 0.85, "script", "T1105",
     "Downloads a second-stage payload from the internet."),
    ("SBX-STR-004", r"(?i)\b(mshta|rundll32|regsvr32|certutil\s+-(decode|urlcache)|installutil|msbuild|wmic\s+process\s+call\s+create)\b",
     "Living-off-the-land binary (LOLBin) abuse", "HIGH", 0.8, "script", "T1218",
     "Proxies execution through a signed Windows binary to evade controls."),
    ("SBX-STR-005", r"(?i)\b(virtualalloc(ex)?|writeprocessmemory|createremotethread|ntunmapviewofsection|rtlmovememory|setwindowshookex)\b",
     "Process-injection API", "HIGH", 0.8, "executable", "T1055", "Injects code into another process."),
    ("SBX-STR-006", r"(?i)(currentversion\\run|schtasks\s+/create|\\start menu\\programs\\startup|new-scheduledtask)",
     "Persistence mechanism", "HIGH", 0.75, "script", "T1547.001", "Installs itself to run at every logon."),
    ("SBX-STR-007", r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|bcdedit\s+/set.*recoveryenabled\s+no|wbadmin\s+delete|your files (have been|are) encrypted)",
     "Ransomware behaviour", "CRITICAL", 0.9, "executable", "T1490", "Deletes backups / encrypts files for ransom."),
    ("SBX-STR-008", r"(?i)\b(frombase64string|\[convert\]::|strreverse|chrw?\(\d+\)\s*&|string\.fromcharcode|unescape\(|atob\(|eval\()",
     "Code obfuscation / runtime decoding", "MEDIUM", 0.65, "script", "T1027", "Decodes hidden code at run time."),
    ("SBX-STR-009", r"(?i)\b(isdebuggerpresent|checkremotedebuggerpresent|vmware|virtualbox|vboxservice|sbiedll|wine_get_unix_file_name)\b",
     "Anti-analysis / sandbox evasion", "MEDIUM", 0.6, "executable", "T1497", "Checks for analysis tools before detonating."),
    ("SBX-STR-010", r"(?i)(mimikatz|sekurlsa|lsass\.exe|procdump.*lsass|sam\\sam|ntds\.dit)",
     "Credential-dumping tooling", "CRITICAL", 0.85, "executable", "T1003", "Dumps stored Windows credentials."),
    ("SBX-STR-011", r"(?i)\b(keylogger|getasynckeystate|setwindowshookexa|clipboard.{0,20}(bitcoin|wallet))",
     "Keylogging / clipboard hijack", "HIGH", 0.75, "executable", "T1056.001", "Captures keystrokes or crypto addresses."),
    ("SBX-STR-012", r"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|ngrok\.io|trycloudflare\.com)",
     "Exfiltration / C2 channel endpoint", "HIGH", 0.8, "ioc", "T1567", "Sends stolen data to an attacker-controlled channel."),
]
_COMPILED = [(r[0], re.compile(r[1]), *r[2:]) for r in KEYWORDS]


def extract_strings(data: bytes, limit: int = 20000) -> List[str]:
    out: List[str] = []
    for m in ASCII_RE.finditer(data[:8_000_000]):
        out.append(m.group().decode("ascii", "ignore"))
        if len(out) >= limit:
            return out
    for m in UTF16_RE.finditer(data[:8_000_000]):
        out.append(m.group().decode("utf-16le", "ignore"))
        if len(out) >= limit:
            break
    return out


def harvest_iocs(text: str) -> Dict[str, List[str]]:
    urls = sorted(set(u.rstrip(".,;)]}'\"") for u in URL_RE.findall(text)))[:100]
    ips = sorted(set(i for i in IP_RE.findall(text) if not i.startswith(("0.", "127.", "255."))))[:100]
    emails = sorted(set(EMAIL_RE.findall(text)))[:50]
    domains = sorted(set(re.sub(r"(?i)^(hxxps?|https?|ftp)://", "", u).split("/")[0].split(":")[0].lower() for u in urls))[:100]
    return {"urls": urls, "ips": ips, "emails": emails, "domains": domains}


def scan_text(text: str, where: str) -> List[Finding]:
    out: List[Finding] = []
    for rid, rx, title, sev, conf, cat, mitre, beh in _COMPILED:
        m = rx.search(text)
        if m:
            s = max(0, m.start() - 40)
            out.append(Finding(rid, title, sev, conf, cat, f"Found in {where}.", text[s:m.end() + 40].replace("\x00", ""), mitre, beh))
    return out


def scan_bytes(data: bytes, where: str) -> Tuple[List[Finding], Dict[str, List[str]], List[str]]:
    findings: List[Finding] = []
    if EICAR in data[:4096] or EICAR in data:
        findings.append(Finding("SBX-REP-002", "EICAR anti-malware test signature", "CRITICAL", 1.0, "reputation",
                                "The file contains the industry-standard EICAR test string. It is harmless, but every "
                                "AV engine treats it as malware — proving the detection pipeline end-to-end.",
                                "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", None, "None (test file)."))
    strings = extract_strings(data)
    text = "\n".join(strings)
    findings += scan_text(text, where)
    iocs = harvest_iocs(text)

    # long base64 blobs that decode to an executable or a script
    for m in list(B64_RE.finditer(data[:4_000_000]))[:20]:
        blob = m.group()
        try:
            dec = base64.b64decode(blob[: (len(blob) // 4) * 4], validate=False)
        except (binascii.Error, ValueError):
            continue
        if dec[:2] == b"MZ":
            findings.append(Finding("SBX-STR-020", "Base64-embedded Windows executable", "CRITICAL", 0.9, "executable",
                                    f"A base64 blob inside {where} decodes to a PE executable (MZ header).",
                                    blob[:80].decode("ascii", "ignore") + "…", "T1027.009",
                                    "Drops and runs an embedded executable."))
            break
        dtext = dec[:20000].decode("utf-16le" if dec[1:2] == b"\x00" else "latin-1", "ignore")
        sub = scan_text(dtext, f"base64-decoded content in {where}")
        if sub:
            findings.append(Finding("SBX-STR-021", "Base64-encoded malicious script", "HIGH", 0.85, "script",
                                    f"A base64 blob inside {where} decodes to code containing: " + ", ".join(s.title for s in sub[:3]),
                                    dtext[:160], "T1027", "Decodes and executes a hidden script."))
            findings += sub
            break
    sample = [s for s in strings if len(s) >= 8][:40]
    return findings, iocs, sample
