"""
MailShield - Gemini AI Reasoning Service
Integrates the Google Gemini API to generate structured threat explanations and forensic Q&A.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from schemas.analysis import (
    AIReasoningResult,
    EmailMetadata,
    ForensicAnalysisResult,
    MLAnalysisResult,
    NLPAnalysisResult,
    RiskResult,
)
from services.reasoning_provider import (
    ReasoningProvider,
    RuleBasedFallbackProvider,
    OllamaReasoningProvider,
)

logger = logging.getLogger("mailshield.gemini_service")


class GeminiReasoningProvider(ReasoningProvider):
    """Reasoning provider utilizing Google's Gemini Flash model."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        if not self.api_key or self.api_key == "your_key_here":
            logger.warning("Gemini API key is not configured. Reasoning will fall back to local rule-based.")
            return

        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
            logger.info("Gemini client successfully initialized.")
        except Exception as e:
            logger.error("Failed to initialize Google GenAI client: %s", e)
            self.client = None

    def is_configured(self) -> bool:
        return bool(self.client and self.api_key and self.api_key != "your_key_here")

    async def generate_explanation(
        self,
        email: EmailMetadata,
        ml: MLAnalysisResult,
        nlp: NLPAnalysisResult,
        forensics: ForensicAnalysisResult,
        risk: RiskResult,
    ) -> AIReasoningResult:
        if not self.is_configured():
            return await RuleBasedFallbackProvider().generate_explanation(email, ml, nlp, forensics, risk)

        prompt = f"""You are MailShield AI, the reasoning and explanation engine of the MAILSHIELD email security system.

GROUND TRUTH FORENSIC EVIDENCE:
- Email Metadata:
  * Subject: {email.subject}
  * Sender: {email.sender} (Domain: {email.sender_domain})
  * Reply-To: {email.reply_to} (Domain: {email.reply_to_domain})
- Authentication:
  * SPF: {forensics.spf}
  * DKIM: {forensics.dkim}
  * DMARC: {forensics.dmarc}
  * Reply-To Mismatch: {forensics.reply_to_mismatch}
- URL & Domain Intelligence:
  * Suspicious URL Count: {forensics.suspicious_url_count}
  * URLs: {json.dumps(forensics.urls[:5])}
  * Domains Detected: {json.dumps(forensics.domains[:5])}
- MailShield ML Model (Phishing Detection):
  * Prediction: {ml.prediction}
  * Probability: {ml.phishing_probability:.4f}
  * Confidence: {ml.confidence:.4f}
- MailShield NLP Model B (Threat-Pattern Classifier):
  * Urgency: {nlp.urgency:.4f}
  * Credential Request: {nlp.credential_request:.4f}
  * Financial Manipulation: {nlp.financial_manipulation:.4f}
  * Impersonation: {nlp.impersonation:.4f}
  * Threat Language: {nlp.threat_language:.4f}
  * Suspicious Action: {nlp.suspicious_action:.4f}
- Deterministic Risk Score: {risk.score}/100 (Level: {risk.level})
- Key Contributing Factors: {json.dumps(risk.contributing_factors)}

CRITICAL RULES:
1. Do NOT alter the numerical risk score or risk level.
2. Do NOT invent unobserved forensic evidence.
3. Ground every statement in the ML, NLP, and forensic evidence provided above.
4. Return ONLY valid JSON matching this exact structure:
{{
  "summary": "Concise 2-3 sentence threat summary",
  "why_detected": ["Explanation point 1", "Explanation point 2", "Explanation point 3"],
  "key_indicators": ["Indicator 1", "Indicator 2"],
  "recommended_actions": ["Action 1", "Action 2", "Action 3"],
  "confidence_note": "Technical note on evidence completeness and confidence"
}}
"""
        def _call_gemini_sync():
            return self.client.models.generate_content(
                model="gemini-flash-latest",
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )

        try:
            # Run in threadpool so synchronous network I/O does not block event loop
            response = await asyncio.to_thread(_call_gemini_sync)
            raw_text = response.text.strip()
            data = json.loads(raw_text)

            return AIReasoningResult(
                summary=data.get("summary", "Analysis completed."),
                why_detected=data.get("why_detected", []),
                key_indicators=data.get("key_indicators", []),
                recommended_actions=data.get("recommended_actions", []),
                confidence_note=data.get("confidence_note", "Grounded in ML, NLP, and forensic signals."),
            )
        except Exception as err:
            logger.warning("Gemini API call failed (%s). Falling back to local rule-based reasoning.", err)
            fallback = await RuleBasedFallbackProvider().generate_explanation(email, ml, nlp, forensics, risk)
            fallback.confidence_note += f" (Gemini offline fallback: {str(err)[:50]})"
            return fallback

    async def answer_investigation_question(
        self,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        language_code: Optional[str] = "en-IN",
    ) -> Dict[str, Any]:
        if not self.is_configured():
            return await RuleBasedFallbackProvider().answer_investigation_question(
                question, context, history, language_code
            )

        ctx = context or {}
        ctx_formatted = json.dumps(ctx, indent=2)

        history_lines = []
        if history:
            for item in history[-4:]:
                role = item.get("role", "user")
                content = item.get("content", "")
                history_lines.append(f"{role.upper()}: {content}")
        history_str = "\n".join(history_lines) if history_lines else "No previous conversation."

        prompt = f"""You are MailShield AI - FORENSIC SENTINEL • LIVE, the elite cybersecurity assistant embedded in the MailShield Platform.
Answer the user's question accurately based STRICTLY on the investigation evidence provided below.

CURRENT INVESTIGATION EVIDENCE:
{ctx_formatted}

CONVERSATION HISTORY:
{history_str}

USER QUESTION:
{question}

TARGET LANGUAGE: {language_code or 'en-IN'}

OPERATING RULES:
1. Ground answers strictly in the current investigation telemetry (Risk Score, ML Phishing Probability, NLP Threat Dimensions, SPF/DKIM/DMARC headers, and URLs).
2. Do NOT hallucinate information not present in the telemetry.
3. If the user asks in Tamil, Hindi, or another Indian language (or if requested, e.g. "Explain this email in Tamil"), answer fluently in that language using proper script.
4. Keep answers concise, technical, and directly actionable for SOC analysts.
5. Format with clean GitHub markdown (bullet points, bold highlights, code tags for IPs/domains/hashes).
"""
        def _call_gemini_chat():
            return self.client.models.generate_content(
                model="gemini-flash-latest",
                contents=prompt,
            )

        try:
            response = await asyncio.to_thread(_call_gemini_chat)
            answer = response.text.strip()
            return {
                "answer": answer,
                "engine": "gemini-flash-latest",
                "language": language_code or "en-IN",
                "sources": ["mailshield_ml", "mailshield_nlp", "forensic_analyzer", "gemini"],
            }
        except Exception as err:
            logger.warning("Gemini Q&A call failed (%s). Using fallback provider.", err)
            return await RuleBasedFallbackProvider().answer_investigation_question(
                question, context, history, language_code
            )


# Singleton factory function
_provider_instance: Optional[ReasoningProvider] = None


def get_reasoning_provider() -> ReasoningProvider:
    """Returns the configured reasoning provider (Gemini, Ollama, or Fallback)."""
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance

    provider_type = os.getenv("REASONING_PROVIDER", "gemini").lower()

    if provider_type == "gemini":
        gemini_prov = GeminiReasoningProvider()
        if gemini_prov.is_configured():
            _provider_instance = gemini_prov
        else:
            logger.warning("Gemini not configured; falling back to RuleBasedFallbackProvider.")
            _provider_instance = RuleBasedFallbackProvider()
    elif provider_type == "ollama":
        _provider_instance = OllamaReasoningProvider()
    else:
        _provider_instance = RuleBasedFallbackProvider()

    return _provider_instance
