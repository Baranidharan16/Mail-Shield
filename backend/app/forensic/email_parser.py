"""
Core .eml parser.

Uses Python's standard `email` package (policy.default) to robustly parse
RFC 5322 messages, including malformed/real-world mail. No third-party
parsing libraries are required for this step - this keeps the trusted
parsing surface small, which matters because uploaded email content is
untrusted input.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, List, Optional


@dataclass
class AttachmentInfo:
    filename: Optional[str]
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    raw_headers: List[Dict[str, str]] = field(default_factory=list)  # ordered [{name, value}]
    headers_index: Dict[str, List[str]] = field(default_factory=dict)  # lower-case name -> list of raw values

    from_address: Optional[str] = None
    from_display_name: Optional[str] = None
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)
    bcc_addresses: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    date_raw: Optional[str] = None
    date_parsed: Optional[datetime] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    mime_version: Optional[str] = None
    content_type: Optional[str] = None
    x_mailer: Optional[str] = None
    user_agent: Optional[str] = None

    authentication_results_raw: List[str] = field(default_factory=list)
    dkim_signature_raw: List[str] = field(default_factory=list)
    received_headers_raw: List[str] = field(default_factory=list)

    text_body: str = ""
    html_body: str = ""

    attachments: List[AttachmentInfo] = field(default_factory=list)

    parse_warnings: List[str] = field(default_factory=list)

    @property
    def sender_domain(self) -> Optional[str]:
        return _domain_of(self.from_address)

    @property
    def reply_to_domain(self) -> Optional[str]:
        return _domain_of(self.reply_to)

    @property
    def return_path_domain(self) -> Optional[str]:
        return _domain_of(self.return_path)


def _domain_of(address: Optional[str]) -> Optional[str]:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip().strip(">").lower() or None


def _first_header(msg: EmailMessage, name: str) -> Optional[str]:
    val = msg.get(name)
    return str(val) if val is not None else None


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail structure.

    Never executes, opens, or shells out on any part of the message.
    Purely read-only structural parsing.
    """
    warnings: List[str] = []
    try:
        msg: EmailMessage = message_from_bytes(raw_bytes, policy=policy.default)  # type: ignore
    except Exception as exc:  # pragma: no cover - defensive
        warnings.append(f"Primary parser failed ({exc}); retrying with compat32 policy")
        msg = message_from_bytes(raw_bytes)  # type: ignore

    parsed = ParsedEmail()
    parsed.parse_warnings = warnings

    # --- raw header preservation (ordered) --------------------------------
    for idx, (name, value) in enumerate(msg.items()):
        parsed.raw_headers.append({"name": name, "value": str(value)})
        parsed.headers_index.setdefault(name.lower(), []).append(str(value))

    # --- From / display name ------------------------------------------------
    from_header = msg.get("From")
    if from_header:
        addrs = getaddresses([str(from_header)])
        if addrs:
            parsed.from_display_name, parsed.from_address = addrs[0]
            parsed.from_address = (parsed.from_address or "").lower() or None
            parsed.from_display_name = parsed.from_display_name or None

    parsed.to_addresses = [a for _, a in getaddresses([str(v) for v in msg.get_all("To", [])])]
    parsed.cc_addresses = [a for _, a in getaddresses([str(v) for v in msg.get_all("Cc", [])])]
    parsed.bcc_addresses = [a for _, a in getaddresses([str(v) for v in msg.get_all("Bcc", [])])]

    parsed.subject = _first_header(msg, "Subject")
    parsed.date_raw = _first_header(msg, "Date")
    if parsed.date_raw:
        try:
            parsed.date_parsed = parsedate_to_datetime(parsed.date_raw)
        except Exception:
            parsed.parse_warnings.append("Could not parse Date header")

    reply_to_header = msg.get("Reply-To")
    if reply_to_header:
        addrs = getaddresses([str(reply_to_header)])
        if addrs:
            parsed.reply_to = (addrs[0][1] or "").lower() or None

    return_path_header = msg.get("Return-Path")
    if return_path_header:
        addrs = getaddresses([str(return_path_header)])
        if addrs and addrs[0][1]:
            parsed.return_path = addrs[0][1].lower()
        else:
            parsed.return_path = str(return_path_header).strip("<>").lower() or None

    parsed.message_id = _first_header(msg, "Message-ID")
    parsed.mime_version = _first_header(msg, "MIME-Version")
    parsed.content_type = msg.get_content_type()
    parsed.x_mailer = _first_header(msg, "X-Mailer")
    parsed.user_agent = _first_header(msg, "User-Agent")

    parsed.authentication_results_raw = [str(v) for v in msg.get_all("Authentication-Results", [])]
    parsed.dkim_signature_raw = [str(v) for v in msg.get_all("DKIM-Signature", [])]
    parsed.received_headers_raw = [str(v) for v in msg.get_all("Received", [])]

    # --- body extraction (text + html), attachments ------------------------
    if msg.is_multipart():
        for part in msg.walk():
            _consume_part(part, parsed)
    else:
        _consume_part(msg, parsed)

    return parsed


def _consume_part(part: EmailMessage, parsed: ParsedEmail) -> None:
    content_disposition = (part.get_content_disposition() or "").lower()
    content_type = part.get_content_type()

    if content_disposition == "attachment" or (part.get_filename() and content_type not in ("text/plain", "text/html")):
        filename = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
        parsed.attachments.append(
            AttachmentInfo(
                filename=filename,
                content_type=content_type,
                size_bytes=len(payload),
                sha256=sha256,
            )
        )
        return

    if content_type == "text/plain" and not part.is_multipart():
        try:
            parsed.text_body += part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                parsed.text_body += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                parsed.parse_warnings.append("Failed to decode a text/plain part")
    elif content_type == "text/html" and not part.is_multipart():
        try:
            parsed.html_body += part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                parsed.html_body += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                parsed.parse_warnings.append("Failed to decode a text/html part")
