from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class InvestigationSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    filename: str
    status: str
    classification: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    created_at: datetime
    analyzed_at: Optional[datetime] = None


class InvestigationCreateResponse(BaseModel):
    id: str
    case_id: str
    status: str
    message: str


class EmailMetadataOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_address: Optional[str] = None
    from_display_name: Optional[str] = None
    to_addresses: Optional[List[str]] = None
    cc_addresses: Optional[List[str]] = None
    bcc_addresses: Optional[List[str]] = None
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
    sender_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    attachments: Optional[List[Dict[str, Any]]] = None


class ReceivedHopOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    hop_index: int
    raw_header: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_parsed: Optional[datetime] = None


class AuthenticationResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    spf_result: Optional[str] = None
    spf_domain: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_domain: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_policy: Optional[str] = None
    from_return_path_aligned: Optional[bool] = None
    from_reply_to_aligned: Optional[bool] = None
    dkim_domain_aligned: Optional[bool] = None
    dmarc_alignment_pass: Optional[bool] = None
    raw_authentication_results_header: Optional[str] = None
    source: str


class URLOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str
    hostname: Optional[str] = None
    scheme: Optional[str] = None
    source_location: Optional[str] = None
    anchor_text: Optional[str] = None
    is_https: Optional[bool] = None
    is_ip_based: Optional[bool] = None
    is_shortened: Optional[bool] = None
    is_punycode: Optional[bool] = None
    has_suspicious_tld: Optional[bool] = None
    excessive_subdomains: Optional[bool] = None
    has_encoded_chars: Optional[bool] = None
    suspicious_query_params: Optional[bool] = None
    anchor_text_mismatch: Optional[bool] = None
    url_length: Optional[int] = None
    risk_score: Optional[float] = None
    risk_reasons: Optional[List[str]] = None


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    domain: str
    role: Optional[str] = None
    is_punycode: Optional[bool] = None
    suspicious_tld: Optional[bool] = None
    excessive_hyphenation: Optional[bool] = None
    lookalike_of: Optional[str] = None
    similarity_score: Optional[float] = None
    risk_score: Optional[float] = None
    evidence: Optional[List[str]] = None


class IPAddressOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    ip_version: int
    source: Optional[str] = None
    is_private: Optional[bool] = None
    hop_index: Optional[int] = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    title: str
    category: str
    severity: str
    explanation: str
    evidence: Optional[List[str]] = None
    confidence: float


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    indicator_type: str
    severity: str
    matched_evidence: Optional[str] = None
    explanation: str
    confidence: float


class RiskScoreOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    overall_score: float
    classification: str
    confidence: float
    authentication_score: float
    header_score: float
    sender_identity_score: float
    domain_score: float
    url_score: float
    social_engineering_score: float
    infrastructure_score: float
    weights_used: Dict[str, float]
    explanation: Dict[str, Any]


class InvestigationDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    filename: str
    original_filename: str
    evidence_hash_sha256: str
    file_size_bytes: int
    mime_type: Optional[str] = None
    status: str
    classification: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    analyzed_at: Optional[datetime] = None

    email_metadata: Optional[EmailMetadataOut] = None
    received_hops: List[ReceivedHopOut] = []
    authentication_result: Optional[AuthenticationResultOut] = None
    urls: List[URLOut] = []
    domains: List[DomainOut] = []
    ip_addresses: List[IPAddressOut] = []
    findings: List[FindingOut] = []
    indicators: List[IndicatorOut] = []
    risk_score_breakdown: Optional[RiskScoreOut] = None


class HealthOut(BaseModel):
    status: str
    app_name: str
    database: str
