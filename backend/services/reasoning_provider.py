"""
MailShield - AI Reasoning Provider Interface & Implementations
Defines the pluggable ReasoningProvider abstraction for Gemini, Ollama, and RuleBasedFallback.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
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

logger = logging.getLogger("mailshield.reasoning_provider")


class ReasoningProvider(ABC):
    """Abstract interface for all forensic explanation and reasoning engines."""

    @abstractmethod
    async def generate_explanation(
        self,
        email: EmailMetadata,
        ml: MLAnalysisResult,
        nlp: NLPAnalysisResult,
        forensics: ForensicAnalysisResult,
        risk: RiskResult,
    ) -> AIReasoningResult:
        """Generates structured SOC incident explanation grounded strictly in evidence."""
        pass

    @abstractmethod
    async def answer_investigation_question(
        self,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        language_code: Optional[str] = "en-IN",
    ) -> Dict[str, Any]:
        """Answers forensic analyst queries about an active investigation or general threat concept."""
        pass


class RuleBasedFallbackProvider(ReasoningProvider):
    """Deterministic, air-gapped fallback provider that never fails and makes zero network calls."""

    async def generate_explanation(
        self,
        email: EmailMetadata,
        ml: MLAnalysisResult,
        nlp: NLPAnalysisResult,
        forensics: ForensicAnalysisResult,
        risk: RiskResult,
    ) -> AIReasoningResult:
        why = []
        indicators = []
        actions = []

        if ml.prediction == "phishing" or ml.phishing_probability > 0.5:
            pct = int(ml.phishing_probability * 100)
            why.append(f"MailShield ML model classified the email as phishing with {pct}% probability.")
            indicators.append(f"ML Classifier Confidence: {pct}%")

        top_nlp = []
        for dim, val in [
            ("Urgency", nlp.urgency),
            ("Credential Request", nlp.credential_request),
            ("Financial Manipulation", nlp.financial_manipulation),
            ("Impersonation", nlp.impersonation),
            ("Threat Language", nlp.threat_language),
            ("Suspicious Action", nlp.suspicious_action),
        ]:
            if val >= 0.5:
                top_nlp.append(f"{dim} ({int(val * 100)}%)")

        if top_nlp:
            why.append(f"NLP Threat-Pattern Model detected active attack vectors: {', '.join(top_nlp)}.")
            indicators.extend(top_nlp)

        if forensics.spf == "FAIL":
            why.append("Sender Policy Framework (SPF) check failed; sending MTA is unauthorized.")
            indicators.append("SPF Authentication Failure")
        if forensics.dkim == "FAIL":
            why.append("DomainKeys Identified Mail (DKIM) cryptographic signature verification failed.")
            indicators.append("DKIM Signature Mismatch")
        if forensics.reply_to_mismatch:
            why.append(f"Header Reply-To domain ({email.reply_to_domain}) diverges from Sender domain ({email.sender_domain}).")
            indicators.append("Reply-To Domain Mismatch")

        if forensics.suspicious_url_count > 0:
            why.append(f"Identified {forensics.suspicious_url_count} suspicious URL(s) exhibiting evasive techniques.")
            indicators.append(f"Suspicious URL Count: {forensics.suspicious_url_count}")

        if risk.level in ("CRITICAL", "HIGH"):
            actions.append("Immediately quarantine the email across the entire mail gateway.")
            actions.append("Block sender domain and all discovered suspicious URLs on perimeter firewalls.")
            actions.append("Revoke active user sessions and mandate immediate password resets if credentials were entered.")
            actions.append("Ingest threat telemetry indicators into corporate SIEM/SOAR.")
        elif risk.level == "MEDIUM":
            actions.append("Move email to quarantine pending secondary tier-2 forensic inspection.")
            actions.append("Warn recipient not to open attachments or click embedded hyperlinks.")
            actions.append("Inspect recipient mail forwarding rules for signs of compromise.")
        else:
            actions.append("Allow message delivery with standard email gateway telemetry.")
            actions.append("Verify DKIM and SPF records for internal domain consistency.")

        summary = f"Risk assessment score: {risk.score}/100 ({risk.level} risk level). "
        if risk.score >= 50:
            summary += "Email contains multiple malicious indicators consistent with phishing and credential harvesting."
        else:
            summary += "Email exhibits standard commercial or internal telemetry with no high-severity anomalies."

        return AIReasoningResult(
            summary=summary,
            why_detected=why or ["Standard forensic evaluation completed."],
            key_indicators=indicators or ["No critical threat signatures identified."],
            recommended_actions=actions,
            confidence_note="Locally derived rule-based reasoning grounded directly in Keras ML/NLP and forensic headers.",
        )

    async def answer_investigation_question(
        self,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        language_code: Optional[str] = "en-IN",
    ) -> Dict[str, Any]:
        q_lower = question.lower()
        ctx = context or {}
        risk = ctx.get("risk") or {}
        ml = ctx.get("ml") or {}
        nlp = ctx.get("nlp") or {}
        forensics = ctx.get("forensics") or {}
        email = ctx.get("email") or {}

        risk_score = risk.get("score", 0)
        risk_level = risk.get("level", "UNKNOWN")

        if "risk" in q_lower:
            answer = f"The evaluated risk score for this email is **{risk_score}/100** ({risk_level} severity). "
            factors = risk.get("contributing_factors", [])
            if factors:
                answer += f"Key contributing factors include:\n" + "\n".join(f"- {f}" for f in factors[:4])
        elif "phishing" in q_lower or "why" in q_lower:
            prob = ml.get("phishing_probability", 0.0)
            pred = ml.get("prediction", "unknown")
            answer = f"The MailShield ML Phishing Detection Model determined this email is **{pred.upper()}** with **{prob * 100:.1f}% confidence**.\n\n"
            if forensics.get("reply_to_mismatch"):
                answer += "- **Reply-To Mismatch**: Sender address and reply address domains do not match.\n"
            if forensics.get("spf") == "FAIL":
                answer += "- **SPF Failure**: The sending server was not authorized by the sender domain.\n"
            if forensics.get("suspicious_url_count", 0) > 0:
                answer += f"- **Suspicious URLs**: {forensics.get('suspicious_url_count')} evasive URLs detected.\n"
        elif "nlp" in q_lower or "threat" in q_lower:
            answer = "The MailShield NLP Threat-Pattern Model detected the following threat vectors:\n"
            for k in ["urgency", "credential_request", "financial_manipulation", "impersonation", "threat_language", "suspicious_action"]:
                val = nlp.get(k, 0.0)
                answer += f"- **{k.replace('_', ' ').title()}**: {val * 100:.1f}%\n"
        elif "spf" in q_lower or "auth" in q_lower or "dkim" in q_lower:
            spf = forensics.get("spf", "NONE")
            dkim = forensics.get("dkim", "NONE")
            dmarc = forensics.get("dmarc", "NONE")
            answer = f"**Authentication Telemetry:**\n- **SPF**: {spf}\n- **DKIM**: {dkim}\n- **DMARC**: {dmarc}\n"
            if spf == "FAIL":
                answer += "\nThe SPF failure indicates the sending IP address was not authorized in the domain's SPF record, pointing to potential spoofing."
        elif "action" in q_lower or "should i do" in q_lower:
            if risk_level in ("CRITICAL", "HIGH"):
                answer = "🚨 **Recommended SOC Actions:**\n1. Quarantine the email immediately across the mail server.\n2. Add sender domain to gateway blocklist.\n3. Instruct recipient not to click any links or enter credentials.\n4. Rotate credentials if previously entered."
            else:
                answer = "✅ **Recommended Actions:**\n1. Standard delivery is acceptable.\n2. Ensure email authentication headers remain intact."
        elif "tamil" in q_lower or language_code == "ta-IN":
            answer = f"இந்த மின்னஞ்சலின் ஆபத்து நிலை: **{risk_score}/100** ({risk_level}). இந்த மின்னஞ்சல் ஏமாற்று வேலை (Phishing) என்று கண்டறியப்பட்டுள்ளது. இதில் உள்ள இணைப்புகளை கிளிக் செய்யாதீர்கள்."
        else:
            answer = f"**MailShield Forensic Analysis:**\n- **Risk**: {risk_score}/100 ({risk_level})\n- **ML Verdict**: {ml.get('prediction', 'analyzed')} ({ml.get('phishing_probability', 0)*100:.1f}%)\n- **Sender**: {email.get('sender', 'Unknown')}\n- **Subject**: {email.get('subject', 'N/A')}\n\nAsk me about the risk score, NLP patterns, SPF/DKIM authentication, or mitigation steps."

        return {
            "answer": answer,
            "engine": "mailshield:rule_based_fallback",
            "language": language_code or "en-IN",
            "sources": ["ml_service", "nlp_service", "forensic_service", "risk_engine"],
        }


class OllamaReasoningProvider(ReasoningProvider):
    """Reasoning provider for local Ollama instances (air-gapped deployment)."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")

    async def generate_explanation(
        self,
        email: EmailMetadata,
        ml: MLAnalysisResult,
        nlp: NLPAnalysisResult,
        forensics: ForensicAnalysisResult,
        risk: RiskResult,
    ) -> AIReasoningResult:
        import httpx
        prompt = f"""You are MailShield AI, an elite cybersecurity forensic reasoning engine.
Analyze this structured email evidence:
- Subject: {email.subject}
- Sender: {email.sender}
- ML Phishing Probability: {ml.phishing_probability:.4f} ({ml.prediction})
- NLP Threat Vectors: Urgency: {nlp.urgency:.2f}, Credential: {nlp.credential_request:.2f}, Impersonation: {nlp.impersonation:.2f}
- Forensics: SPF={forensics.spf}, DKIM={forensics.dkim}, Reply-To Mismatch={forensics.reply_to_mismatch}, URLs={forensics.suspicious_url_count}
- Deterministic Risk: {risk.score}/100 ({risk.level})

Respond ONLY with valid JSON matching this schema:
{{
  "summary": "Brief 2-3 sentence overview",
  "why_detected": ["reason 1", "reason 2"],
  "key_indicators": ["indicator 1", "indicator 2"],
  "recommended_actions": ["action 1", "action 2"],
  "confidence_note": "Technical grounding note"
}}
"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False, "format": "json"},
                )
                res.raise_for_status()
                data = json.loads(res.json().get("response", "{}"))
                return AIReasoningResult(
                    summary=data.get("summary", "Analysis completed."),
                    why_detected=data.get("why_detected", []),
                    key_indicators=data.get("key_indicators", []),
                    recommended_actions=data.get("recommended_actions", []),
                    confidence_note=data.get("confidence_note", f"Ollama local model: {self.model}"),
                )
        except Exception as err:
            logger.warning("Ollama call failed (%s). Falling back to rule-based engine.", err)
            return await RuleBasedFallbackProvider().generate_explanation(email, ml, nlp, forensics, risk)

    async def answer_investigation_question(
        self,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        language_code: Optional[str] = "en-IN",
    ) -> Dict[str, Any]:
        import httpx
        ctx_str = json.dumps(context or {}, indent=2)
        prompt = f"""You are MailShield AI Forensic Sentinel. Answer the SOC analyst's question based strictly on this telemetry:
Telemetry:
{ctx_str}

Question: {question}
Target Language: {language_code}

Provide a concise, direct, technical markdown response."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False},
                )
                res.raise_for_status()
                answer = res.json().get("response", "").strip()
                return {
                    "answer": answer,
                    "engine": f"ollama:{self.model}",
                    "language": language_code or "en-IN",
                    "sources": ["investigation_telemetry", "ollama"],
                }
        except Exception as err:
            logger.warning("Ollama Q&A failed (%s). Using fallback.", err)
            return await RuleBasedFallbackProvider().answer_investigation_question(question, context, history, language_code)
