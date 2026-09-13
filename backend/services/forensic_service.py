"""
MailShield - Forensic Analyzer Service
Performs comprehensive forensic header, authentication, URL, and domain analysis.
"""
from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from services.email_parser import ParsedEmailData
from schemas.analysis import ForensicAnalysisResult
from utils.text_processing import extract_domain, check_suspicious_url

logger = logging.getLogger("mailshield.forensic_service")


def parse_authentication_results(auth_headers: List[str], dkim_headers: List[str]) -> Dict[str, str]:
    """Extracts SPF, DKIM, and DMARC verdicts from Authentication-Results headers."""
    results = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE"}
    combined_auth = " ".join(auth_headers).lower()

    # SPF verdict
    spf_match = re.search(r'\bspf=([a-z]+)', combined_auth)
    if spf_match:
        results["spf"] = spf_match.group(1).upper()

    # DKIM verdict
    dkim_match = re.search(r'\bdkim=([a-z]+)', combined_auth)
    if dkim_match:
        results["dkim"] = dkim_match.group(1).upper()
    elif dkim_headers:
        # DKIM signature present but no explicit server verification header
        results["dkim"] = "SIGNED_UNVERIFIED"

    # DMARC verdict
    dmarc_match = re.search(r'\bdmarc=([a-z]+)', combined_auth)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).upper()

    return results


def analyze_forensics(parsed: ParsedEmailData) -> ForensicAnalysisResult:
    """Executes the full deterministic forensic analysis on the parsed email."""
    # 1. Header & Domain Mismatch
    sender_domain = parsed.sender_domain
    reply_to_domain = parsed.reply_to_domain

    reply_to_mismatch = False
    if sender_domain and reply_to_domain:
        if sender_domain.lower() != reply_to_domain.lower():
            reply_to_mismatch = True

    # Check Return-Path mismatch if present
    return_path_raw = parsed.raw_headers.get("Return-Path", "")
    return_path_domain = extract_domain(return_path_raw)
    if return_path_domain and sender_domain:
        if return_path_domain.lower() != sender_domain.lower():
            # Flag mismatch evidence
            pass

    # 2. Authentication Analysis
    auth_results = parse_authentication_results(
        parsed.authentication_results_raw,
        parsed.dkim_signatures_raw
    )

    # 3. URL Analysis
    suspicious_url_details: List[Dict[str, Any]] = []
    url_domains: Set[str] = set()

    for url in parsed.urls:
        domain = extract_domain(url)
        if domain:
            url_domains.add(domain)

        is_suspicious, reasons = check_suspicious_url(url)
        if is_suspicious:
            suspicious_url_details.append({
                "url": url,
                "domain": domain,
                "reasons": reasons
            })

    # 4. Check for Display Name spoofing (e.g. From: "PayPal Support" <attacker@evil.com>)
    display_name_spoof = False
    from_raw = parsed.from_header.lower()
    well_known_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank", "wells fargo", "chase"]
    for brand in well_known_brands:
        if brand in from_raw and sender_domain and brand not in sender_domain:
            display_name_spoof = True
            break

    # Gather all detected domains
    all_domains = set()
    if sender_domain:
        all_domains.add(sender_domain)
    if reply_to_domain:
        all_domains.add(reply_to_domain)
    if return_path_domain:
        all_domains.add(return_path_domain)
    all_domains.update(url_domains)

    # Received hops count
    received_hop_count = len(parsed.received_headers_raw)

    return ForensicAnalysisResult(
        spf=auth_results["spf"],
        dkim=auth_results["dkim"],
        dmarc=auth_results["dmarc"],
        reply_to_mismatch=reply_to_mismatch,
        suspicious_url_count=len(suspicious_url_details),
        domains=sorted(list(all_domains)),
        urls=parsed.urls,
        received_hop_count=received_hop_count,
        attachment_count=len(parsed.attachments),
        attachments=parsed.attachment_filenames,
        suspicious_url_details=suspicious_url_details,
    )
