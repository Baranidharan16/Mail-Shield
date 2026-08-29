"""
ORM models.

UUID primary keys are stored as CHAR(36) strings rather than a
database-specific UUID type so the same models work against both
PostgreSQL (production, see docker-compose.yml) and SQLite (used for
local/sandbox development and the automated test-suite).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship

from app.database.session import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(32), unique=True, nullable=False, index=True)
    filename = Column(String(512), nullable=False)
    original_filename = Column(String(512), nullable=False)
    evidence_hash_sha256 = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(Integer, nullable=False)
    mime_type = Column(String(128), nullable=True)

    status = Column(String(32), nullable=False, default="QUEUED")  # QUEUED/PROCESSING/COMPLETED/FAILED
    classification = Column(String(32), nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    risk_score = Column(Float, nullable=True)
    confidence = Column(Float, nullable=True)

    error_message = Column(Text, nullable=True)

    created_by = Column(String(128), nullable=True)  # reserved for Phase-2 auth
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    analyzed_at = Column(DateTime(timezone=True), nullable=True)

    # --- Phase 2: case management fields ---
    case_status = Column(String(32), nullable=False, default="OPEN")  # OPEN/INVESTIGATING/CONTAINED/CLOSED/FALSE_POSITIVE
    analyst = Column(String(128), nullable=True)
    severity = Column(String(16), nullable=True)  # mirrors classification but analyst-editable
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=True)
    notes = Column(JSON, nullable=True)  # list of {author, text, created_at}
    processing_stage = Column(String(32), nullable=True)  # granular Phase 2 pipeline stage

    email_metadata = relationship("EmailMetadata", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    headers = relationship("EmailHeader", back_populates="investigation", cascade="all, delete-orphan")
    received_hops = relationship("ReceivedHop", back_populates="investigation", cascade="all, delete-orphan", order_by="ReceivedHop.hop_index")
    authentication_result = relationship("AuthenticationResult", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    urls = relationship("URLRecord", back_populates="investigation", cascade="all, delete-orphan")
    domains = relationship("DomainRecord", back_populates="investigation", cascade="all, delete-orphan")
    ip_addresses = relationship("IPAddressRecord", back_populates="investigation", cascade="all, delete-orphan")
    indicators = relationship("Indicator", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    risk_score_breakdown = relationship("RiskScoreBreakdown", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    report = relationship("Report", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    ml_prediction = relationship("MLPrediction", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    threat_intel_summary = relationship("ThreatIntelSummary", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    attack_graph = relationship("AttackGraph", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    attribution_assessment = relationship("AttributionAssessment", back_populates="investigation", uselist=False, cascade="all, delete-orphan")


class EmailMetadata(Base):
    __tablename__ = "email_metadata"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    from_address = Column(String(512), nullable=True)
    from_display_name = Column(String(512), nullable=True)
    to_addresses = Column(JSON, nullable=True)
    cc_addresses = Column(JSON, nullable=True)
    bcc_addresses = Column(JSON, nullable=True)
    subject = Column(Text, nullable=True)
    date_raw = Column(String(256), nullable=True)
    date_parsed = Column(DateTime(timezone=True), nullable=True)
    reply_to = Column(String(512), nullable=True)
    return_path = Column(String(512), nullable=True)
    message_id = Column(String(512), nullable=True)
    mime_version = Column(String(64), nullable=True)
    content_type = Column(String(256), nullable=True)
    x_mailer = Column(String(256), nullable=True)
    user_agent = Column(String(256), nullable=True)

    sender_domain = Column(String(256), nullable=True)
    reply_to_domain = Column(String(256), nullable=True)
    return_path_domain = Column(String(256), nullable=True)

    attachments = Column(JSON, nullable=True)  # list of {filename, mime_type, sha256, size}

    investigation = relationship("Investigation", back_populates="email_metadata")


class EmailHeader(Base):
    """Stores every raw header name/value pair observed (for completeness / forensic replay)."""
    __tablename__ = "email_headers"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    name = Column(String(256), nullable=False)
    value = Column(Text, nullable=False)
    order_index = Column(Integer, nullable=False, default=0)

    investigation = relationship("Investigation", back_populates="headers")


class ReceivedHop(Base):
    __tablename__ = "received_hops"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    hop_index = Column(Integer, nullable=False)  # 0 = earliest observed

    raw_header = Column(Text, nullable=False)
    from_host = Column(String(512), nullable=True)
    by_host = Column(String(512), nullable=True)
    with_protocol = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    timestamp_raw = Column(String(256), nullable=True)
    timestamp_parsed = Column(DateTime(timezone=True), nullable=True)

    investigation = relationship("Investigation", back_populates="received_hops")


class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    spf_result = Column(String(32), nullable=True)   # PASS/FAIL/SOFTFAIL/NEUTRAL/NONE/...
    spf_domain = Column(String(256), nullable=True)
    spf_raw = Column(Text, nullable=True)

    dkim_result = Column(String(32), nullable=True)
    dkim_domain = Column(String(256), nullable=True)
    dkim_selector = Column(String(128), nullable=True)
    dkim_raw = Column(Text, nullable=True)

    dmarc_result = Column(String(32), nullable=True)
    dmarc_policy = Column(String(32), nullable=True)
    dmarc_raw = Column(Text, nullable=True)

    from_return_path_aligned = Column(Boolean, nullable=True)
    from_reply_to_aligned = Column(Boolean, nullable=True)
    dkim_domain_aligned = Column(Boolean, nullable=True)
    dmarc_alignment_pass = Column(Boolean, nullable=True)

    raw_authentication_results_header = Column(Text, nullable=True)
    source = Column(String(32), nullable=False, default="OBSERVED")  # OBSERVED vs INSUFFICIENT_DATA

    investigation = relationship("Investigation", back_populates="authentication_result")


class URLRecord(Base):
    __tablename__ = "urls"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    url = Column(Text, nullable=False)
    hostname = Column(String(512), nullable=True)
    scheme = Column(String(16), nullable=True)
    source_location = Column(String(32), nullable=True)  # html_body/text_body/header
    anchor_text = Column(Text, nullable=True)

    is_https = Column(Boolean, nullable=True)
    is_ip_based = Column(Boolean, nullable=True)
    is_shortened = Column(Boolean, nullable=True)
    is_punycode = Column(Boolean, nullable=True)
    has_suspicious_tld = Column(Boolean, nullable=True)
    excessive_subdomains = Column(Boolean, nullable=True)
    has_encoded_chars = Column(Boolean, nullable=True)
    suspicious_query_params = Column(Boolean, nullable=True)
    anchor_text_mismatch = Column(Boolean, nullable=True)
    url_length = Column(Integer, nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_reasons = Column(JSON, nullable=True)

    investigation = relationship("Investigation", back_populates="urls")


class DomainRecord(Base):
    __tablename__ = "domains"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    domain = Column(String(256), nullable=False)
    role = Column(String(32), nullable=True)  # sender/reply_to/return_path/url/received
    is_punycode = Column(Boolean, nullable=True)
    suspicious_tld = Column(Boolean, nullable=True)
    excessive_hyphenation = Column(Boolean, nullable=True)
    lookalike_of = Column(String(256), nullable=True)
    similarity_score = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)
    evidence = Column(JSON, nullable=True)

    investigation = relationship("Investigation", back_populates="domains")


class IPAddressRecord(Base):
    __tablename__ = "ip_addresses"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    ip_address = Column(String(64), nullable=False)
    ip_version = Column(Integer, nullable=False)  # 4 or 6
    source = Column(String(64), nullable=True)  # received_hop / url / header
    is_private = Column(Boolean, nullable=True)
    hop_index = Column(Integer, nullable=True)

    investigation = relationship("Investigation", back_populates="ip_addresses")


class Indicator(Base):
    """Social-engineering / content-based indicators."""
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    indicator_type = Column(String(64), nullable=False)  # urgency/credential_request/...
    severity = Column(String(16), nullable=False)  # LOW/MEDIUM/HIGH
    matched_evidence = Column(Text, nullable=True)
    explanation = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)

    investigation = relationship("Investigation", back_populates="indicators")


class Finding(Base):
    """Deterministic header-anomaly / forensic rule findings."""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)

    rule_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)  # header/authentication/url/domain/social_engineering/infrastructure
    severity = Column(String(16), nullable=False)  # INFO/LOW/MEDIUM/HIGH/CRITICAL
    explanation = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    confidence = Column(Float, nullable=False, default=0.5)

    investigation = relationship("Investigation", back_populates="findings")


class RiskScoreBreakdown(Base):
    __tablename__ = "risk_scores"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    overall_score = Column(Float, nullable=False)
    classification = Column(String(32), nullable=False)
    confidence = Column(Float, nullable=False)

    authentication_score = Column(Float, nullable=False)
    header_score = Column(Float, nullable=False)
    sender_identity_score = Column(Float, nullable=False)
    domain_score = Column(Float, nullable=False)
    url_score = Column(Float, nullable=False)
    social_engineering_score = Column(Float, nullable=False)
    infrastructure_score = Column(Float, nullable=False)

    weights_used = Column(JSON, nullable=False)
    explanation = Column(JSON, nullable=False)

    investigation = relationship("Investigation", back_populates="risk_score_breakdown")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    report_json = Column(JSON, nullable=False)
    generated_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation", back_populates="report")


# ============================================================
# Phase 2 tables
# ============================================================

class ThreatIntelCache(Base):
    """Generic TTL cache for external/heuristic threat-intelligence lookups,
    keyed by (provider, indicator_type, indicator) so the same IP/domain/URL
    is never looked up twice within its TTL window."""
    __tablename__ = "threat_intel_cache"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    provider = Column(String(64), nullable=False)
    indicator_type = Column(String(16), nullable=False)  # ip / domain / url
    indicator = Column(String(512), nullable=False, index=True)
    result_json = Column(JSON, nullable=False)
    fetched_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class MLPrediction(Base):
    """Persisted ML + fusion output for one investigation, with full model
    version provenance (Part: Model Management)."""
    __tablename__ = "ml_predictions"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    structured_available = Column(Boolean, nullable=False, default=False)
    structured_label = Column(String(64), nullable=True)
    structured_confidence = Column(Float, nullable=True)
    structured_probabilities = Column(JSON, nullable=True)
    structured_model_version = Column(String(32), nullable=True)
    structured_top_features = Column(JSON, nullable=True)

    text_available = Column(Boolean, nullable=False, default=False)
    text_label = Column(String(64), nullable=True)
    text_confidence = Column(Float, nullable=True)
    text_probabilities = Column(JSON, nullable=True)
    text_model_version = Column(String(32), nullable=True)
    text_top_features = Column(JSON, nullable=True)

    feature_version = Column(String(16), nullable=True)
    feature_vector = Column(JSON, nullable=True)

    fused_overall_score = Column(Float, nullable=True)
    fused_classification = Column(String(32), nullable=True)
    fused_confidence = Column(Float, nullable=True)
    fused_breakdown = Column(JSON, nullable=True)
    fused_reasons = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation", back_populates="ml_prediction")


class ThreatIntelSummary(Base):
    """Per-investigation rollup of IP/domain/URL intelligence results (the
    individual cached lookups live in ThreatIntelCache; this table stores
    which indicators were checked for THIS investigation and the resulting
    contribution to that investigation's score)."""
    __tablename__ = "threat_intel_summaries"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    ip_results = Column(JSON, nullable=True)
    domain_results = Column(JSON, nullable=True)
    url_results = Column(JSON, nullable=True)
    aggregate_score = Column(Float, nullable=True)
    reasons = Column(JSON, nullable=True)
    providers_used = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation", back_populates="threat_intel_summary")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    campaign_code = Column(String(32), unique=True, nullable=False)
    name = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    indicator_summary = Column(JSON, nullable=True)

    members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")


class CampaignMember(Base):
    __tablename__ = "campaign_members"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=False)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    similarity_score = Column(Float, nullable=False)
    relationship_label = Column(String(32), nullable=False)  # likely related / possibly related
    reasons = Column(JSON, nullable=True)
    added_at = Column(DateTime(timezone=True), default=utcnow)

    campaign = relationship("Campaign", back_populates="members")
    investigation = relationship("Investigation")


class AttackGraph(Base):
    __tablename__ = "attack_graphs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)
    graph_json = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation", back_populates="attack_graph")


class AttributionAssessment(Base):
    __tablename__ = "attribution_assessments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, unique=True)

    level = Column(Integer, nullable=False)  # 0-6
    level_label = Column(String(128), nullable=False)
    detection_confidence = Column(Float, nullable=False)
    infrastructure_confidence = Column(Float, nullable=False)
    campaign_confidence = Column(Float, nullable=False)
    attribution_confidence = Column(Float, nullable=False)
    explanation = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation", back_populates="attribution_assessment")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    severity = Column(String(16), nullable=False)  # matches classification: HIGH/CRITICAL
    threat_score = Column(Float, nullable=False)
    classification = Column(String(32), nullable=False)
    key_reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    acknowledged = Column(Boolean, nullable=False, default=False)

    investigation = relationship("Investigation")


class Feedback(Base):
    """Analyst feedback loop (Part 20) - stored for future model
    improvement; never used to auto-retrain production models."""
    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    predicted_classification = Column(String(32), nullable=True)
    analyst_classification = Column(String(32), nullable=True)
    feedback_type = Column(String(32), nullable=False)  # CORRECT/FALSE_POSITIVE/FALSE_NEGATIVE/NEEDS_REVIEW
    model_version = Column(String(64), nullable=True)
    notes = Column(Text, nullable=True)
    analyst = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation")


class AgentActionLog(Base):
    """Audit log of every AI-investigation-agent tool call (Part 24:
    'every agent action must be auditable')."""
    __tablename__ = "agent_action_log"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    tool_name = Column(String(64), nullable=False)
    tool_input_summary = Column(Text, nullable=True)
    tool_output_summary = Column(Text, nullable=True)
    succeeded = Column(Boolean, nullable=False, default=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation")


# ============================================================
# Phase 3 tables
# ============================================================

class BlockchainBlock(Base):
    """Local tamper-evident hash chain - see app/blockchain/ledger.py for
    the honest scope note on why this is a local ledger, not a public
    blockchain, in this environment."""
    __tablename__ = "blockchain_blocks"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    block_index = Column(Integer, nullable=False, unique=True)
    timestamp = Column(String(64), nullable=False)
    case_id = Column(String(32), nullable=False, index=True)
    evidence_hash = Column(String(64), nullable=False)
    report_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False, unique=True)


class AuditLog(Base):
    """General audit trail (Phase 3 Part 27) distinct from AgentActionLog -
    covers uploads, analysis lifecycle, report generation, evidence
    verification, and blockchain anchoring. Never stores email content."""
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), nullable=True, index=True)
    actor = Column(String(128), nullable=True)  # caller identity or "system"
    action = Column(String(64), nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ResponseRecommendation(Base):
    """Human-approval-gated recommendations (Phase 2 Part 16 / Phase 3 Part 19/25)."""
    __tablename__ = "response_recommendations"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False)
    action = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)
    reason = Column(Text, nullable=False)
    requires_human_approval = Column(Boolean, nullable=False, default=True)
    approval_status = Column(String(16), nullable=False, default="PENDING")  # PENDING/APPROVED/REJECTED
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation")
