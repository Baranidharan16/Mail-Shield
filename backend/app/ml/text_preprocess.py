"""
Text normalisation shared by training AND real-time inference.

It lives inside the saved scikit-learn Pipeline (FunctionTransformer), so the
exact same preprocessing is applied at inference time — it cannot drift.

Normalisation deliberately removes dataset-specific tokens (URLs, e-mail
addresses, numbers, hex ids) so the model learns *language patterns*
(urgency, credential requests, payment pressure) instead of memorising the
specific domains/addresses that happen to appear in the training corpus.
"""
from __future__ import annotations

import html as _html
import re
from typing import Iterable, List

_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"(https?://|www\.)\S+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_HEX = re.compile(r"\b[0-9a-f]{12,}\b", re.I)
_NUM = re.compile(r"\b\d+([.,]\d+)*\b")
_WS = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    t = _html.unescape(_TAG.sub(" ", text or ""))
    t = _URL.sub(" urltoken ", t)
    t = _EMAIL.sub(" emailtoken ", t)
    t = _HEX.sub(" hextoken ", t)
    t = _NUM.sub(" numtoken ", t)
    return _WS.sub(" ", t).strip().lower()[:20000]


def normalize_batch(texts: Iterable[str]) -> List[str]:
    return [normalize_text(t) for t in texts]
