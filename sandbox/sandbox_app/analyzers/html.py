"""HTML / SVG attachment & body analysis: credential-harvest forms, HTML
smuggling, redirects, script obfuscation, hidden iframes. Nothing is rendered."""
from __future__ import annotations

import re
from typing import List

from ..rules import Finding

BRANDS = r"(microsoft|office\s?365|outlook|onedrive|sharepoint|google|gmail|apple|icloud|paypal|amazon|dhl|fedex|docusign|adobe|netflix|linkedin|facebook|instagram|whatsapp|sbi|state bank|hdfc|icici|axis bank|kotak|paytm|phonepe|bhim|upi|income ?tax|gst|aadhaar|uidai|epfo|digilocker|india post|irctc|nic|gov\.in)"


def analyze_html(text: str, where: str) -> List[Finding]:
    out: List[Finding] = []
    t = text[:3_000_000]
    low = t.lower()
    has_pw = bool(re.search(r"<input[^>]+type\s*=\s*[\"']?password", low))
    forms = re.findall(r"<form[^>]*action\s*=\s*[\"']?([^\"'\s>]+)", low)
    ext_forms = [f for f in forms if f.startswith(("http", "//"))]
    if has_pw:
        brand = re.search(BRANDS, low)
        out.append(Finding("SBX-HTM-001", "Credential-harvesting login form", "CRITICAL" if (ext_forms or brand) else "HIGH",
                           0.9, "html",
                           "A local HTML file asking for a password is almost always a phishing kit"
                           + (f" (impersonating '{brand.group(0)}')" if brand else "") + ".",
                           (ext_forms[0] if ext_forms else "password field present")[:200], "T1056.003",
                           "Captures the victim's password and posts it to the attacker."))
    elif ext_forms:
        out.append(Finding("SBX-HTM-002", "Form posting to external server", "MEDIUM", 0.7, "html",
                           "HTML form submits user input to a remote endpoint.", ext_forms[0][:200], "T1056.003"))
    if re.search(r"new\s+blob\s*\(", low) and re.search(r"(mssaveoropenblob|createobjecturl|\.download\s*=|download\s*=)", low):
        out.append(Finding("SBX-HTM-003", "HTML smuggling", "CRITICAL", 0.9, "html",
                           "JavaScript assembles a file in the browser and triggers a download, bypassing gateway scanning "
                           "(technique used by QakBot / NOBELIUM).", "Blob + createObjectURL/msSaveOrOpenBlob", "T1027.006",
                           "Browser silently writes an attacker payload (often ZIP/ISO) to disk."))
    if re.search(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[^>]+url\s*=", low) or \
            re.search(r"(window|document|top)\.location(\.href)?\s*=|location\.replace\(", low):
        m = re.search(r"url\s*=\s*([^\"'>\s]+)|location(?:\.href)?\s*=\s*[\"']([^\"']+)", low)
        out.append(Finding("SBX-HTM-004", "Automatic redirect", "MEDIUM", 0.65, "html",
                           "Page redirects the browser automatically — used to bounce victims to phishing sites.",
                           (m.group(1) or m.group(2)) if m else "redirect", "T1204.001", "Redirects the browser on open."))
    obf = sum(len(re.findall(p, low)) for p in (r"\batob\(", r"\bunescape\(", r"\beval\(", r"string\.fromcharcode",
                                                r"document\.write\(", r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}"))
    if obf >= 3:
        out.append(Finding("SBX-HTM-005", "Obfuscated JavaScript", "HIGH", 0.75, "html",
                           f"{obf} obfuscation primitives (atob/unescape/eval/fromCharCode/hex escapes).", where, "T1027",
                           "Decodes and runs hidden script in the browser."))
    elif obf:
        out.append(Finding("SBX-HTM-006", "Script decoding primitive", "LOW", 0.5, "html",
                           "Uses a runtime-decoding JavaScript function.", where, "T1027"))
    if re.search(r"<iframe[^>]+(width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|display\s*:\s*none|visibility\s*:\s*hidden)", low):
        out.append(Finding("SBX-HTM-007", "Hidden iframe", "HIGH", 0.75, "html",
                           "Zero-size or hidden iframe loads remote content invisibly.", where, "T1189",
                           "Loads a hidden remote page (drive-by)."))
    datas = re.findall(r"data:(?:application|text/html)[^,]{0,60};base64,[a-z0-9+/=]{200,}", low)
    if datas:
        out.append(Finding("SBX-HTM-008", "Large base64 data: URI payload", "MEDIUM", 0.65, "html",
                           "Embeds an application/HTML payload inline to avoid a separate download.", datas[0][:120], "T1027.006"))
    if re.search(r"<script[^>]+src\s*=\s*[\"']?https?://", low) and has_pw:
        out.append(Finding("SBX-HTM-009", "Remote script on credential page", "MEDIUM", 0.6, "html",
                           "Phishing kit loads its logic from an external host.", where, "T1059.007"))
    if "telegram.org/bot" in low or "discord.com/api/webhooks" in low:
        out.append(Finding("SBX-HTM-010", "Credential exfiltration channel", "CRITICAL", 0.9, "html",
                           "Captured data is posted to a Telegram bot / Discord webhook.", where, "T1567",
                           "Exfiltrates typed credentials to a chat channel."))
    return out
