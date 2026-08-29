"""Evidence integrity utilities (Phase 1: SHA-256 hashing only; blockchain
anchoring is explicitly out of scope until Phase 3)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass
class EvidenceRecord:
    sha256: str
    size_bytes: int


def hash_evidence(raw_bytes: bytes) -> EvidenceRecord:
    return EvidenceRecord(sha256=hashlib.sha256(raw_bytes).hexdigest(), size_bytes=len(raw_bytes))
