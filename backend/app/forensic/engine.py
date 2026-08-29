"""
Forensic engine orchestrator.

This is the single entry point the API/service layer calls. It is pure
Python (no DB, no FastAPI) so it can be unit/integration tested in
isolation, per project architecture requirements.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from app.forensic.email_parser import ParsedEmail, parse_eml_bytes
from app.forensic.received_parser import ReceivedHop, parse_received_headers, describe_originating_infrastructure
from app.forensic.auth_analyzer import AuthenticationAnalysis, analyze_authentication
from app.forensic.header_anomaly import Finding, run_header_anomaly_rules
from app.forensic.url_analyzer import URLFinding, extract_urls
from app.forensic.domain_analyzer import DomainFinding, analyze_domain
from app.forensic.ip_extractor import IPFinding, extract_ip_addresses
from app.forensic.social_engineering import ContentIndicator, analyze_social_engineering
from app.forensic.scoring import ThreatScoreResult, calculate_threat_score
from app.forensic.evidence import EvidenceRecord, hash_evidence


@dataclass
class ForensicAnalysisResult:
    parsed_email: ParsedEmail
    received_hops: List[ReceivedHop]
    originating_infrastructure_note: Optional[str]
    authentication: AuthenticationAnalysis
    header_findings: List[Finding]
    url_findings: List[URLFinding]
    domain_findings: List[DomainFinding]
    ip_findings: List[IPFinding]
    social_engineering_indicators: List[ContentIndicator]
    threat_score: ThreatScoreResult
    evidence: EvidenceRecord


def run_forensic_analysis(raw_bytes: bytes, trusted_domains: Optional[List[str]] = None) -> ForensicAnalysisResult:
    """Runs the complete Phase-1 forensic pipeline on a raw .eml file's bytes.

    Never executes attachments, never fetches URLs, never shells out.
    """
    trusted_domains = trusted_domains or []

    evidence = hash_evidence(raw_bytes)
    parsed = parse_eml_bytes(raw_bytes)

    received_hops = parse_received_headers(parsed.received_headers_raw)
    origin_note = describe_originating_infrastructure(received_hops)

    auth = analyze_authentication(
        authentication_results_raw=parsed.authentication_results_raw,
        dkim_signature_raw=parsed.dkim_signature_raw,
        sender_domain=parsed.sender_domain,
        reply_to_domain=parsed.reply_to_domain,
        return_path_domain=parsed.return_path_domain,
    )

    header_findings = run_header_anomaly_rules(parsed, auth, received_hop_count=len(received_hops))

    url_findings = extract_urls(parsed.text_body, parsed.html_body)

    # Domain findings: sender/reply-to/return-path + every unique URL hostname
    domain_findings: List[DomainFinding] = []
    domain_roles = [
        (parsed.sender_domain, "sender"),
        (parsed.reply_to_domain, "reply_to"),
        (parsed.return_path_domain, "return_path"),
    ]
    seen_domains = set()
    for domain, role in domain_roles:
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            domain_findings.append(analyze_domain(domain, role, trusted_domains))

    url_hostnames = {u.hostname for u in url_findings if u.hostname}
    for hostname in url_hostnames:
        if hostname not in seen_domains:
            seen_domains.add(hostname)
            domain_findings.append(analyze_domain(hostname, "url", trusted_domains))

    ip_findings = extract_ip_addresses(received_hops, url_findings)

    social_indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")

    threat_score = calculate_threat_score(
        auth=auth,
        header_findings=header_findings,
        domain_findings=domain_findings,
        url_findings=url_findings,
        social_engineering_indicators=social_indicators,
        received_hops=received_hops,
        attachments=[{"filename": a.filename, "size_bytes": a.size_bytes} for a in parsed.attachments],
    )

    return ForensicAnalysisResult(
        parsed_email=parsed,
        received_hops=received_hops,
        originating_infrastructure_note=origin_note,
        authentication=auth,
        header_findings=header_findings,
        url_findings=url_findings,
        domain_findings=domain_findings,
        ip_findings=ip_findings,
        social_engineering_indicators=social_indicators,
        threat_score=threat_score,
        evidence=evidence,
    )
