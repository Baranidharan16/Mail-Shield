"""
Local hash-chain evidence ledger (Phase 3 Part 17).

HONEST SCOPE NOTE: this environment has no network access to a public
blockchain/testnet. Rather than fake a "blockchain anchor", this
implements a genuine, verifiable, tamper-evident hash chain (each block
cryptographically references the previous block's hash - the same core
primitive a blockchain uses) stored in the database. This is real and
independently verifiable; it is documented here as a LOCAL ledger, not
presented as a public blockchain. Swapping this for a real chain
(e.g. writing block_hash to an Ethereum/Polygon testnet transaction) only
requires replacing `anchor()`'s persistence call - the hash-chain
construction and verification logic do not change.

Only hashes/metadata are ever stored - never email content (per Part 12
of the Phase 3 brief).
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.investigation import BlockchainBlock


def _hash_block(index: int, timestamp: str, case_id: str, evidence_hash: str, report_hash: str, previous_hash: str) -> str:
    payload = json.dumps({
        "index": index, "timestamp": timestamp, "case_id": case_id,
        "evidence_hash": evidence_hash, "report_hash": report_hash, "previous_hash": previous_hash,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def anchor_evidence(db: Session, case_id: str, evidence_hash: str, report_hash: str) -> BlockchainBlock:
    last = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).first()
    index = (last.block_index + 1) if last else 0
    previous_hash = last.block_hash if last else "0" * 64
    timestamp = datetime.now(timezone.utc).isoformat()
    block_hash = _hash_block(index, timestamp, case_id, evidence_hash, report_hash, previous_hash)

    block = BlockchainBlock(
        block_index=index, timestamp=timestamp, case_id=case_id,
        evidence_hash=evidence_hash, report_hash=report_hash,
        previous_hash=previous_hash, block_hash=block_hash,
    )
    db.add(block)
    db.commit()
    db.refresh(block)
    return block


def verify_chain(db: Session) -> dict:
    """Recomputes every block's hash and checks linkage - real
    verification, not a stored boolean."""
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.asc()).all()
    if not blocks:
        return {"verified": True, "block_count": 0, "message": "Ledger is empty."}

    expected_previous = "0" * 64
    for b in blocks:
        recomputed = _hash_block(b.block_index, b.timestamp, b.case_id, b.evidence_hash, b.report_hash, b.previous_hash)
        if recomputed != b.block_hash:
            return {"verified": False, "block_count": len(blocks), "message": f"INTEGRITY FAILURE at block {b.block_index}: stored hash does not match recomputed hash."}
        if b.previous_hash != expected_previous:
            return {"verified": False, "block_count": len(blocks), "message": f"INTEGRITY FAILURE at block {b.block_index}: previous_hash does not chain correctly."}
        expected_previous = b.block_hash

    return {"verified": True, "block_count": len(blocks), "message": "VERIFIED - hash chain is intact."}


def verify_evidence_for_case(db: Session, case_id: str, current_evidence_hash: str, current_report_hash: Optional[str] = None) -> dict:
    block = db.query(BlockchainBlock).filter(BlockchainBlock.case_id == case_id).order_by(BlockchainBlock.block_index.desc()).first()
    if not block:
        return {"anchored": False, "message": "No blockchain anchor found for this case."}

    evidence_match = block.evidence_hash == current_evidence_hash
    report_match = (current_report_hash is None) or (block.report_hash == current_report_hash)
    chain_result = verify_chain(db)

    ok = evidence_match and report_match and chain_result["verified"]
    return {
        "anchored": True,
        "verified": ok,
        "status": "VERIFIED" if ok else "INTEGRITY FAILURE",
        "block_index": block.block_index,
        "anchored_at": block.timestamp,
        "evidence_hash_match": evidence_match,
        "report_hash_match": report_match,
        "chain_intact": chain_result["verified"],
    }
