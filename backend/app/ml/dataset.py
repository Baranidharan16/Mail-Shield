"""
Synthetic labeled training-data generator for the Phase 2 ML baseline
models.

IMPORTANT: every example produced here is SYNTHETIC DEMONSTRATION DATA,
generated from parameterized templates with a fixed random seed for
reproducibility. No real emails or real people are used anywhere. This
mirrors the same approach used for the 7 Phase 1 test fixtures, scaled up
so the ML baselines have enough labeled examples to fit on.

Labels: LEGITIMATE, SUSPICIOUS, PHISHING, BUSINESS_EMAIL_COMPROMISE,
IMPERSONATION, CREDENTIAL_HARVESTING, FRAUD, MALWARE_SUSPECTED

Each generated example is a full synthetic .eml byte string, run through
the REAL Phase 1 forensic engine to produce its feature vector - the
model never trains on hand-typed numbers, only on features the same
pipeline would compute for a genuine upload.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Tuple

DATASET_VERSION = "synthetic-v1.0.0"

LABELS = [
    "LEGITIMATE",
    "SUSPICIOUS",
    "PHISHING",
    "BUSINESS_EMAIL_COMPROMISE",
    "IMPERSONATION",
    "CREDENTIAL_HARVESTING",
    "FRAUD",
    "MALWARE_SUSPECTED",
]

_LEGIT_DOMAINS = ["acmecorp.example", "globex.example", "initech.example", "umbrella.example"]
_SUSPICIOUS_TLDS = ["top", "xyz", "click", "work", "loan"]
_SHORTENERS = ["bit.ly", "tinyurl.com", "rb.gy"]
_FREEMAIL = ["gmail.com", "yahoo.com", "outlook.com"]

_URGENCY = ["This is urgent, please act immediately.", "Respond within 24 hours to avoid suspension."]
_CREDENTIAL = ["Please verify your password to continue.", "Confirm your account credentials using the link below."]
_PAYMENT = ["Please process the wire transfer today.", "Kindly update our new bank account for payment."]
_EXEC = ["Are you at your desk? I need a quick favor, keep this between us.", "I'm in a meeting, can't talk, but need this handled now."]
_MALWARE_CTA = ["Please enable macros to view this invoice.", "Download and open the attached file immediately to view your document."]
_NEUTRAL = ["Please find attached the report for your review.", "Let me know if you have any questions about the schedule."]


def _rand_domain(rng: random.Random, base: str, suspicious: bool = False) -> str:
    if suspicious:
        tld = rng.choice(_SUSPICIOUS_TLDS)
        variant = rng.choice(["secure-", "verify-", "account-", ""])
        return f"{variant}{base.split('.')[0]}-{rng.randint(10,99)}.{tld}"
    return base


def _build_eml(
    rng: random.Random,
    from_domain: str,
    from_display: str,
    reply_to_domain: str,
    return_path_domain: str,
    subject: str,
    body_lines: List[str],
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    include_auth: bool = True,
    url: str | None = None,
    hop_ip: str = "203.0.113.10",
) -> bytes:
    msg_id = f"<{rng.randint(10**9, 10**10)}@{from_domain}>"
    from_addr = f"user{rng.randint(1,999)}@{from_domain}"
    auth_header = ""
    if include_auth:
        auth_header = (
            f"Authentication-Results: mx.example;\n"
            f"       spf={spf} smtp.mailfrom={from_addr};\n"
            f"       dkim={dkim} header.d={from_domain};\n"
            f"       dmarc={dmarc} header.from={from_domain}\n"
        )
    body = "\n".join(body_lines)
    if url:
        body += f'\n<html><body><p>{body}</p><a href="{url}">Click here</a></body></html>'
        content_type = "text/html; charset=\"UTF-8\""
    else:
        content_type = "text/plain; charset=\"UTF-8\""

    eml = (
        f"Received: from mail.relay.test ([{hop_ip}])\n"
        f"        by mx.recipient.test with SMTP id x{rng.randint(1,999)};\n"
        f"        Mon, 01 Jan 2025 10:00:00 +0000\n"
        f"{auth_header}"
        f"From: \"{from_display}\" <{from_addr}>\n"
        f"To: recipient@recipient.test\n"
        f"Reply-To: reply@{reply_to_domain}\n"
        f"Return-Path: <bounce@{return_path_domain}>\n"
        f"Subject: {subject}\n"
        f"Date: Mon, 01 Jan 2025 10:00:00 +0000\n"
        f"Message-ID: {msg_id}\n"
        f"MIME-Version: 1.0\n"
        f"Content-Type: {content_type}\n\n"
        f"SYNTHETIC TRAINING DATA.\n\n{body}\n"
    )
    return eml.encode("utf-8")


@dataclass
class SyntheticExample:
    raw_bytes: bytes
    label: str


def generate_dataset(seed: int = 42, per_class: int = 30) -> List[SyntheticExample]:
    rng = random.Random(seed)
    examples: List[SyntheticExample] = []

    for _ in range(per_class):
        domain = rng.choice(_LEGIT_DOMAINS)
        examples.append(SyntheticExample(_build_eml(
            rng, domain, "Colleague", domain, domain,
            "Project update", [rng.choice(_NEUTRAL)],
            spf="pass", dkim="pass", dmarc="pass",
        ), "LEGITIMATE"))

    for _ in range(per_class):
        domain = rng.choice(_LEGIT_DOMAINS)
        examples.append(SyntheticExample(_build_eml(
            rng, domain, "Newsletter", domain, domain,
            "Weekly digest", [rng.choice(_NEUTRAL), rng.choice(_URGENCY)],
            spf=rng.choice(["softfail", "neutral"]), dkim="pass", dmarc="none",
        ), "SUSPICIOUS"))

    for _ in range(per_class):
        legit = rng.choice(_LEGIT_DOMAINS)
        bad_domain = _rand_domain(rng, legit, suspicious=True)
        url = f"http://{rng.choice(['192.0.2.'+str(rng.randint(2,254)), bad_domain])}/login/verify?confirm=account"
        examples.append(SyntheticExample(_build_eml(
            rng, bad_domain, f"{legit.split('.')[0].title()} Security", bad_domain, bad_domain,
            "Unusual sign-in activity detected - verify now",
            [rng.choice(_URGENCY), rng.choice(_CREDENTIAL)],
            spf="fail", dkim="none", dmarc="fail", url=url,
            hop_ip=f"198.51.100.{rng.randint(2,254)}",
        ), "PHISHING"))

    for _ in range(per_class):
        legit = rng.choice(_LEGIT_DOMAINS)
        freemail = rng.choice(_FREEMAIL)
        examples.append(SyntheticExample(_build_eml(
            rng, freemail, f"CEO {legit.split('.')[0].title()}", "protonmail.com", freemail,
            "Quick request",
            [rng.choice(_EXEC), rng.choice(_PAYMENT)],
            spf="fail", dkim="none", dmarc="fail",
        ), "BUSINESS_EMAIL_COMPROMISE"))

    for _ in range(per_class):
        legit = rng.choice(_LEGIT_DOMAINS)
        lookalike = _rand_domain(rng, legit, suspicious=True)
        examples.append(SyntheticExample(_build_eml(
            rng, lookalike, f"{legit.split('.')[0].title()} Support", lookalike, lookalike,
            "Mandatory policy acknowledgement",
            [rng.choice(_NEUTRAL), rng.choice(_CREDENTIAL)],
            spf="pass", dkim="pass", dmarc="none",
        ), "IMPERSONATION"))

    for _ in range(per_class):
        legit = rng.choice(_LEGIT_DOMAINS)
        bad_domain = _rand_domain(rng, legit, suspicious=True)
        url = f"http://{rng.choice(_SHORTENERS)}/x{rng.randint(1000,9999)}"
        examples.append(SyntheticExample(_build_eml(
            rng, bad_domain, "IT Helpdesk", bad_domain, bad_domain,
            "Password expires today",
            [rng.choice(_CREDENTIAL), rng.choice(_URGENCY)],
            spf="fail", dkim="none", dmarc="fail", url=url,
        ), "CREDENTIAL_HARVESTING"))

    for _ in range(per_class):
        vendor_domain = _rand_domain(rng, rng.choice(_LEGIT_DOMAINS), suspicious=True)
        examples.append(SyntheticExample(_build_eml(
            rng, vendor_domain, "Accounts Payable", vendor_domain, vendor_domain,
            "Updated banking details for upcoming invoice payment",
            [rng.choice(_PAYMENT), "Please confirm once the wire transfer has been completed."],
            spf="neutral", dkim="none", dmarc="none",
        ), "FRAUD"))

    for _ in range(per_class):
        bad_domain = _rand_domain(rng, rng.choice(_LEGIT_DOMAINS), suspicious=True)
        examples.append(SyntheticExample(_build_eml(
            rng, bad_domain, "Document Center", bad_domain, bad_domain,
            "Invoice document attached - action required",
            [rng.choice(_MALWARE_CTA), rng.choice(_URGENCY)],
            spf="fail", dkim="none", dmarc="none",
        ), "MALWARE_SUSPECTED"))

    rng.shuffle(examples)
    return examples
