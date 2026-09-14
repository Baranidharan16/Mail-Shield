"""
MailShield - Analysis & Assistant API Schemas
Defines the strict contracts for the /api/analyze-email, assistant (chat, voice, speak, transcribe),
health, and model status endpoints.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EmailMetadata(BaseModel):
    subject: Optional[str] = Field(default="", description="Email subject line")
    sender: Optional[str] = Field(default="", description="Full From header value")
    sender_domain: Optional[str] = Field(default="", description="Extracted domain of the sender")
    reply_to: Optional[str] = Field(default="", description="Reply-To header value")
    reply_to_domain: Optional[str] = Field(default="", description="Extracted domain of the Reply-To address")
    date: Optional[str] = Field(default="", description="Email Date header")
    message_id: Optional[str] = Field(default="", description="Message-ID header")


class MLAnalysisResult(BaseModel):
    prediction: str = Field(..., description="'phishing' or 'legitimate'")
    phishing_probability: float = Field(..., ge=0.0, le=1.0, description="Probability that the email is phishing")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")


class NLPAnalysisResult(BaseModel):
    urgency: float = Field(..., ge=0.0, le=1.0, description="Urgency threat pattern probability")
    credential_request: float = Field(..., ge=0.0, le=1.0, description="Credential request pattern probability")
    financial_manipulation: float = Field(..., ge=0.0, le=1.0, description="Financial manipulation pattern probability")
    impersonation: float = Field(..., ge=0.0, le=1.0, description="Impersonation threat pattern probability")
    threat_language: float = Field(..., ge=0.0, le=1.0, description="Threat language pattern probability")
    suspicious_action: float = Field(..., ge=0.0, le=1.0, description="Suspicious call-to-action probability")


class ForensicAnalysisResult(BaseModel):
    spf: Optional[str] = Field(default="NONE", description="SPF validation status (PASS, FAIL, SOFTFAIL, NONE)")
    dkim: Optional[str] = Field(default="NONE", description="DKIM validation status")
    dmarc: Optional[str] = Field(default="NONE", description="DMARC validation status")
    reply_to_mismatch: bool = Field(default=False, description="True if From and Reply-To domains differ")
    suspicious_url_count: int = Field(default=0, description="Number of URLs flagged as suspicious")
    domains: List[str] = Field(default_factory=list, description="All unique domains detected in headers and URLs")
    urls: List[str] = Field(default_factory=list, description="Extracted URLs")
    received_hop_count: int = Field(default=0, description="Count of Received MTA hops")
    attachment_count: int = Field(default=0, description="Number of attachments found")
    attachments: List[str] = Field(default_factory=list, description="Attachment filenames")
    suspicious_url_details: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed reasons for flagged URLs")


class RiskResult(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Deterministic risk score (0-100)")
    level: str = Field(..., description="Risk tier: LOW, MEDIUM, HIGH, or CRITICAL")
    contributing_factors: List[str] = Field(default_factory=list, description="Deterministic itemized evidence factors")


class AIReasoningResult(BaseModel):
    summary: str = Field(..., description="Correlated threat overview")
    why_detected: List[str] = Field(default_factory=list, description="Specific explanations of detection logic")
    key_indicators: List[str] = Field(default_factory=list, description="Primary observable threat signals")
    recommended_actions: List[str] = Field(default_factory=list, description="Actionable SOC/incident response steps")
    confidence_note: str = Field(..., description="Confidence and evidence bounds note")


class EmailAnalysisResponse(BaseModel):
    analysis_id: str = Field(..., description="Unique investigation identifier")
    email: EmailMetadata
    ml: MLAnalysisResult
    nlp: NLPAnalysisResult
    forensics: ForensicAnalysisResult
    risk: RiskResult
    ai_reasoning: AIReasoningResult


class RawEmailRequest(BaseModel):
    subject: Optional[str] = Field(default="", description="Email subject")
    body: str = Field(..., description="Raw email text or content to analyze")
    sender: Optional[str] = Field(default=None, description="Optional sender email")
    reply_to: Optional[str] = Field(default=None, description="Optional reply-to email")


class HealthResponse(BaseModel):
    status: str = "ok"
    app_name: str = "MAILSHIELD"
    version: str = "1.0.0"


class ModelStatusResponse(BaseModel):
    ml_model_loaded: bool
    nlp_model_loaded: bool
    forensic_engine_active: bool = True
    gemini_status: str = "CONNECTED"  # "CONNECTED" | "UNAVAILABLE"
    sarvam_voice_status: str = "CONNECTED"  # "CONNECTED" | "UNAVAILABLE"
    ollama_status: str = "NOT CONFIGURED"  # "CONNECTED" | "NOT CONFIGURED"
    autonomous_agent_status: str = "NOT CONFIGURED"
    autonomous_agent_active: bool = False
    ml_model_path: str
    nlp_model_path: str
    reasoning_provider: str
    gemini_configured: bool


class MLHealthCheckItem(BaseModel):
    """Result of a single check performed by the /health/ml endpoint."""
    name: str = Field(..., description="Short name of the check")
    passed: bool = Field(..., description="True if the check succeeded")
    detail: Optional[str] = Field(default=None, description="Human-readable detail or error")


class MLHealthResponse(BaseModel):
    """Full diagnostic report returned by GET /health/ml."""
    status: str = Field(..., description="'ok' if all checks passed, 'degraded' otherwise")
    python_version: str
    tensorflow_version: Optional[str] = None
    keras_version: Optional[str] = None
    ml_model_path: str
    nlp_model_path: str
    ml_model_loaded: bool
    nlp_model_loaded: bool
    checks: List[MLHealthCheckItem] = Field(default_factory=list)
    # Test prediction results (populated when models are loaded)
    test_predictions: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Results of live test predictions through the full pipeline"
    )
    error: Optional[str] = Field(
        default=None,
        description="Last load error traceback if a model failed to load"
    )


# ── Assistant / Voice Schemas ──────────────────────────────────────────────────

class AssistantChatRequest(BaseModel):
    question: str = Field(..., description="Analyst's query or prompt")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Active email telemetry/evidence")
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Recent conversation turns")
    language: Optional[str] = Field(default="en-IN", description="Language code (e.g. en-IN, ta-IN, hi-IN)")


class AssistantChatResponse(BaseModel):
    answer: str
    engine: str
    language: str
    sources: List[str] = Field(default_factory=list)


class AssistantSpeakRequest(BaseModel):
    text: str = Field(..., description="Text to synthesize into speech")
    voice: Optional[str] = Field(default="priya", description="Sarvam speaker name")
    language: Optional[str] = Field(default="en-IN", description="Target language code")


class AssistantSpeakResponse(BaseModel):
    audio_base64: str
    format: str = "wav"
    engine: str
    language_code: str
    language_name: str
    speaker: str


class AssistantTranscribeResponse(BaseModel):
    transcript: str
    language_code: str
    language_name: str
    confidence: float
    engine: str


class AssistantVoiceResponse(BaseModel):
    transcript: str
    answer: str
    audio_base64: str
    format: str = "wav"
    language_code: str
    language_name: str
    engine: str
