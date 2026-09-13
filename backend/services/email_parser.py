"""
MailShield - Email Forensic Parser Service
Safely parses raw .eml bytes without executing attachments or modifying evidence.
"""
from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from utils.text_processing import extract_urls, extract_domain, clean_text_for_model


@dataclass
class ParsedEmailData:
    # Normalized extracted fields
    from_header: str
    to_header: str
    cc_header: str
    reply_to: str
    subject: str
    date: str
    message_id: str
    
    sender_domain: str
    reply_to_domain: str
    
    plain_text_body: str
    html_body: str
    combined_body: str
    model_text: str  # Subject + Clean Body for ML/NLP
    
    urls: List[str]
    attachments: List[Dict[str, Any]]
    attachment_filenames: List[str]
    
    # Raw un-altered headers for chain-of-custody forensic audit
    received_headers_raw: List[str]
    authentication_results_raw: List[str]
    dkim_signatures_raw: List[str]
    raw_headers: Dict[str, str] = field(default_factory=dict)
    
    raw_bytes: bytes = field(default_factory=bytes, repr=False)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmailData:
    """Parses raw .eml bytes using Python's modern email.policy.default."""
    msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)

    from_header = str(msg.get("From") or "").strip()
    to_header = str(msg.get("To") or "").strip()
    cc_header = str(msg.get("Cc") or "").strip()
    reply_to = str(msg.get("Reply-To") or "").strip()
    subject = str(msg.get("Subject") or "").strip()
    date_header = str(msg.get("Date") or "").strip()
    message_id = str(msg.get("Message-ID") or "").strip()

    sender_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to) if reply_to else sender_domain

    received_headers_raw = [str(h).strip() for h in msg.get_all("Received", [])]
    auth_results_raw = [str(h).strip() for h in msg.get_all("Authentication-Results", [])]
    dkim_sigs_raw = [str(h).strip() for h in msg.get_all("DKIM-Signature", [])]

    # Store all raw headers
    raw_headers = {k: str(v) for k, v in msg.items()}

    # Extract bodies and attachments safely
    plain_text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []
    attachment_filenames: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()

            if filename or "attachment" in content_disposition.lower():
                safe_name = filename or f"unnamed_attachment_{len(attachments)}"
                payload_bytes = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": safe_name,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload_bytes),
                })
                attachment_filenames.append(safe_name)
                continue

            content_type = part.get_content_type()
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    if content_type == "text/plain":
                        plain_text_parts.append(payload)
                    elif content_type == "text/html":
                        html_parts.append(payload)
            except Exception:
                pass
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                if content_type == "text/plain":
                    plain_text_parts.append(payload)
                elif content_type == "text/html":
                    html_parts.append(payload)
        except Exception:
            pass

    plain_text = "\n".join(plain_text_parts).strip()
    html_text = "\n".join(html_parts).strip()
    combined_body = plain_text if plain_text else html_text

    # Extract URLs
    urls = extract_urls(plain_text, html_text)

    # Format text for model: Subject + Body cleaned
    clean_body = clean_text_for_model(combined_body)
    model_text = f"{subject}\n{clean_body}".strip() if subject else clean_body

    return ParsedEmailData(
        from_header=from_header,
        to_header=to_header,
        cc_header=cc_header,
        reply_to=reply_to,
        subject=subject,
        date=date_header,
        message_id=message_id,
        sender_domain=sender_domain,
        reply_to_domain=reply_to_domain,
        plain_text_body=plain_text,
        html_body=html_text,
        combined_body=combined_body,
        model_text=model_text,
        urls=urls,
        attachments=attachments,
        attachment_filenames=attachment_filenames,
        received_headers_raw=received_headers_raw,
        authentication_results_raw=auth_results_raw,
        dkim_signatures_raw=dkim_sigs_raw,
        raw_headers=raw_headers,
        raw_bytes=raw_bytes,
    )
