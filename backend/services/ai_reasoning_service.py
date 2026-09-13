"""
MailShield - AI Reasoning Service (Facade)
Re-exports ReasoningProvider, GeminiReasoningProvider, OllamaReasoningProvider, RuleBasedFallbackProvider.
"""
from services.reasoning_provider import (
    ReasoningProvider,
    RuleBasedFallbackProvider,
    OllamaReasoningProvider,
)
from services.gemini_service import (
    GeminiReasoningProvider,
    get_reasoning_provider,
)

__all__ = [
    "ReasoningProvider",
    "RuleBasedFallbackProvider",
    "OllamaReasoningProvider",
    "GeminiReasoningProvider",
    "get_reasoning_provider",
]
