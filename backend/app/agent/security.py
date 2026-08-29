"""
Prompt-injection defense (Phase 2 Part 25 / Phase 3 security hardening).

The investigation agent in this platform is deterministic (no external LLM
is called - see LOCAL_ONLY_MODE in app/core/config.py), so there is no
literal prompt for email content to "inject" into. Nonetheless we
implement an EXPLICIT, testable defense per the brief, because:
  1. it documents the boundary between SYSTEM/TOOL/TRUSTED/UNTRUSTED data
     that any future LLM-backed agent must respect,
  2. it gives analysts a concrete, evidence-backed finding when an email
     attempts this class of attack, rather than silently ignoring it.

Detected injection attempts are surfaced as a `Finding`-shaped indicator
(category="prompt_injection") - never executed, never treated as an
instruction, always just reported as evidence about the email itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_INJECTION_PATTERNS = [
    r"ignore (all |)(previous|prior|above) instructions",
    r"disregard (all |)(previous|prior|above) instructions",
    r"you are now (in |)(developer|admin|root|system) mode",
    r"act as (if you were|a) (system|admin|root)",
    r"reveal (your |the )?(system prompt|instructions|api key)",
    r"execute (this|the following) (command|code|script)",
    r"run (this|the following) (command|shell|script)",
    r"\bsudo\b.{0,20}\brm\b",
    r"new instructions?:",
    r"forget (everything|all) (you|that) (were|was) told",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@dataclass
class PromptInjectionFinding:
    detected: bool
    matched_patterns: List[str]
    excerpt: str


def scan_for_prompt_injection(text: str) -> PromptInjectionFinding:
    """Scans untrusted email text for prompt-injection style instructions.
    This NEVER executes or acts on anything found - it only reports.
    """
    if not text:
        return PromptInjectionFinding(detected=False, matched_patterns=[], excerpt="")

    matched = []
    first_match_pos = None
    for pattern in _COMPILED:
        m = pattern.search(text)
        if m:
            matched.append(m.group(0))
            if first_match_pos is None:
                first_match_pos = m.start()

    excerpt = ""
    if first_match_pos is not None:
        start = max(0, first_match_pos - 20)
        excerpt = text[start:first_match_pos + 60]

    return PromptInjectionFinding(detected=bool(matched), matched_patterns=matched, excerpt=excerpt)


def sanitize_for_display(text: str, max_len: int = 4000) -> str:
    """Truncates and neutralizes untrusted text before it is ever placed
    into any agent-facing context - defense in depth even though this
    platform's agent is deterministic today."""
    if not text:
        return ""
    text = text[:max_len]
    # Strip anything that looks like a role/instruction delimiter an LLM
    # prompt template might use, so untrusted content can never masquerade
    # as a system/tool message boundary.
    text = re.sub(r"(?im)^\s*(system|assistant|tool|user)\s*:", "[REDACTED_ROLE_MARKER]:", text)
    return text
