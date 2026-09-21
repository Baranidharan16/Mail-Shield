"""
MailShield - Gemini AI Reasoning Service
Integrates the Google Gemini API to generate structured threat explanations and forensic Q&A.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
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

# Ordered list of models to try — most capable stable first, fallback on 503/404
# NOTE: If you have GOOGLE_API_KEY and GEMINI_API_KEY both set in environment,
#       the SDK may print "Using GOOGLE_API_KEY" — this is just a warning and is
#       safe since we always pass api_key= explicitly to genai.Client().
_GEMINI_MODEL_CANDIDATES = [
    "gemini-3.6-flash",       # Recommended by Google as latest stable
    "gemini-flash-lite-latest", # Fallback: lighter but usually available
    "gemini-flash-latest",      # Alias for current flash (may be overloaded)
    "gemini-2.5-flash-lite",    # Older lite model as last resort
]


class GeminiReasoningProvider(ReasoningProvider):
    """Reasoning provider utilizing Google's Gemini Flash model with automatic model fallback."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        self._active_model: Optional[str] = None
        self._initialize_client()

    def _initialize_client(self):
        if not self.api_key or self.api_key == "your_key_here":
            logger.warning("Gemini API key is not configured. Reasoning will fall back to local rule-based.")
            return

        try:
            from google import genai
            # Pass api_key explicitly so the SDK does NOT fall back to the
            # GOOGLE_API_KEY env variable (which causes "Using GOOGLE_API_KEY"
            # conflict warnings and may use a wrong key).
            self.client = genai.Client(api_key=self.api_key)
            logger.info("Gemini client successfully initialized.")
        except Exception as e:
            logger.error("Failed to initialize Google GenAI client: %s", e)
            self.client = None

    def _call_with_model_fallback(self, make_call):
        """Try each model candidate in order; retry on 503, skip on 404."""
        last_err = None
        for model in _GEMINI_MODEL_CANDIDATES:
            for attempt in range(2):  # 1 retry per model on 503
                try:
                    result = make_call(model)
                    self._active_model = model
                    return result
                except Exception as e:
                    err_str = str(e)
                    if "503" in err_str or "UNAVAILABLE" in err_str:
                        logger.warning("Model %s is overloaded (attempt %d). %s",
                                       model, attempt + 1,
                                       "Retrying..." if attempt == 0 else "Trying next model.")
                        if attempt == 0:
                            time.sleep(1.5)
                        else:
                            last_err = e
                            break  # next model
                    elif "404" in err_str or "NOT_FOUND" in err_str:
                        logger.warning("Model %s not available for this key, skipping.", model)
                        last_err = e
                        break  # next model without retry
                    else:
                        raise  # non-recoverable error
        raise last_err or RuntimeError("All Gemini model candidates failed.")

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
        def _call_gemini_sync(model: str):
            return self.client.models.generate_content(
                model=model,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )

        try:
            # Run in threadpool so synchronous network I/O does not block event loop
            response = await asyncio.to_thread(self._call_with_model_fallback, _call_gemini_sync)
            raw_text = response.text.strip()
            # Strip markdown code fences if model wraps JSON in ```json ... ```
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            data = json.loads(raw_text)

            return AIReasoningResult(
                summary=data.get("summary", "Analysis completed."),
                why_detected=data.get("why_detected", []),
                key_indicators=data.get("key_indicators", []),
                recommended_actions=data.get("recommended_actions", []),
                confidence_note=data.get(
                    "confidence_note",
                    f"Grounded in ML, NLP, and forensic signals. Engine: {self._active_model}",
                ),
            )
        except Exception as err:
            logger.warning("Gemini API call failed (%s). Falling back to local rule-based reasoning.", err)
            fallback = await RuleBasedFallbackProvider().generate_explanation(email, ml, nlp, forensics, risk)
            fallback.confidence_note += f" (Gemini offline fallback: {str(err)[:80]})"
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

        prompt = f"""You are MailShield AI — FORENSIC SENTINEL LIVE, a senior cybersecurity analyst and elite email forensics expert embedded in the MailShield SOC platform.

Your job: answer the user's forensic question with deep technical accuracy, grounded STRICTLY in the evidence below.

═══════════════════════════════════════
ACTIVE INVESTIGATION EVIDENCE
═══════════════════════════════════════
{ctx_formatted}

═══════════════════════════════════════
CONVERSATION HISTORY
═══════════════════════════════════════
{history_str}

═══════════════════════════════════════
USER QUESTION
═══════════════════════════════════════
{question}

TARGET LANGUAGE: {language_code or 'en-IN'}

═══════════════════════════════════════
OPERATING RULES
═══════════════════════════════════════
1. **Ground every statement** in the investigation telemetry above (Risk Score, ML Phishing Probability, NLP Threat Dimensions, SPF/DKIM/DMARC, URLs, headers).
2. **Never hallucinate** — if data is absent from the evidence, say so explicitly.
3. **Language**: If the user writes in Tamil, Hindi, Telugu, Kannada, Malayalam, Bengali, or any other Indian language, respond fluently in that same language with proper script. Translate technical terms naturally.
4. **Forensic depth**: Provide expert-level analysis — explain WHY each indicator matters (e.g., why SPF fail + DKIM pass is suspicious, what domain spoofing implies, how NLP urgency correlates with credential harvesting).
5. **Actionable**: End with concrete next steps for a SOC analyst (block, quarantine, alert user, escalate, etc.).
6. **Format**: Use clean GitHub Markdown — bold key findings, `code` tags for IPs/domains/hashes/headers, bullet points for lists, tables when comparing values.
7. **Concise but complete**: Do not pad answers. Be direct. A good forensic response is typically 150-400 words.
"""
        def _call_gemini_chat(model: str):
            return self.client.models.generate_content(
                model=model,
                contents=prompt,
            )

        try:
            response = await asyncio.to_thread(self._call_with_model_fallback, _call_gemini_chat)
            answer = response.text.strip()
            return {
                "answer": answer,
                "engine": self._active_model or "gemini",
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


def reset_reasoning_provider() -> None:
    """Clears the cached provider so the next call to get_reasoning_provider() re-initializes it."""
    global _provider_instance
    _provider_instance = None


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
            logger.info("Gemini reasoning provider activated.")
        else:
            logger.warning(
                "Gemini not configured (check GEMINI_API_KEY in backend/.env); "
                "falling back to RuleBasedFallbackProvider."
            )
            _provider_instance = RuleBasedFallbackProvider()
    elif provider_type == "ollama":
        _provider_instance = OllamaReasoningProvider()
    else:
        _provider_instance = RuleBasedFallbackProvider()

    return _provider_instance
