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
import threading
import time
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


_APPEND_LOCK = threading.Lock()


def anchor_evidence(db: Session, case_id: str, evidence_hash: str, report_hash: str) -> BlockchainBlock:
    """Appends one block. Appends are serialized in-process (the Gmail monitor
    thread and API uploads can finish at the same moment) and retried on a
    unique-constraint race with another worker, so the chain never forks."""
    from sqlalchemy.exc import IntegrityError

    last_error = None
    for attempt in range(5):
        with _APPEND_LOCK:
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
            try:
                db.add(block)
                db.commit()
                db.refresh(block)
                return block
            except IntegrityError as exc:  # another process appended the same index
                db.rollback()
                last_error = exc
        time.sleep(0.05 * (attempt + 1))
    raise RuntimeError(f"Could not append ledger block after retries: {last_error}")


def block_is_valid(b: BlockchainBlock) -> bool:
    return _hash_block(b.block_index, b.timestamp, b.case_id, b.evidence_hash,
                       b.report_hash, b.previous_hash) == b.block_hash


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


def canonical_report_hash(report_json) -> str:
    """SHA-256 over a canonical JSON serialisation (sorted keys) of the stored report."""
    normalised = json.loads(json.dumps(report_json, default=str))
    return hashlib.sha256(json.dumps(normalised, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_investigation_integrity(db: Session, investigation) -> dict:
    """
    Real tamper check: RE-CALCULATES the hashes of the current evidence file and
    the current stored forensic report, and compares them with the values
    anchored in the hash-chain ledger when the analysis finished.
    """
    import os
    from app.core.config import get_settings
    block = (db.query(BlockchainBlock).filter(BlockchainBlock.case_id == investigation.case_id)
             .order_by(BlockchainBlock.block_index.desc()).first())
    if not block:
        return {"anchored": False, "status": "NOT_ANCHORED",
                "message": "No ledger anchor exists for this case (analysis not completed yet)."}

    # 1) evidence file
    path = os.path.join(os.path.abspath(get_settings().UPLOAD_STORAGE_DIR), investigation.filename or "")
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            current_evidence = hashlib.sha256(fh.read()).hexdigest()
        evidence_status = "VALID" if current_evidence == block.evidence_hash else "MODIFIED"
    else:
        current_evidence = None
        evidence_status = "FILE_UNAVAILABLE"

    # 2) forensic report
    rep = investigation.report.report_json if getattr(investigation, "report", None) else None
    if rep is None:
        report_status, current_report = "REPORT_MISSING", None
    else:
        current_report = canonical_report_hash(rep)
        legacy = hashlib.sha256(str(rep).encode("utf-8")).hexdigest()
        report_status = "VALID" if block.report_hash in (current_report, legacy) else "MODIFIED"

    chain = verify_chain(db)
    modified = "MODIFIED" in (evidence_status, report_status) or not chain["verified"]
    return {
        "anchored": True,
        "status": "MODIFIED" if modified else "VALID",
        "verified": not modified,
        "evidence_hash_match": evidence_status != "MODIFIED",
        "report_hash_match": report_status == "VALID",
        "chain_intact": chain["verified"],
        "block_index": block.block_index,
        "anchored_at": block.timestamp,
        "message": ("Integrity VALID — recalculated report hash" + (" and evidence-file hash" if current_evidence else "")
                    + " match the ledger anchor." if not modified else
                    "Integrity MODIFIED — the current data no longer matches what was anchored."),
        "evidence_file": {"status": evidence_status, "anchored_hash": block.evidence_hash, "current_hash": current_evidence,
                          "note": None if current_evidence else "Raw evidence file is not on this server's disk "
                                  "(ephemeral storage); the report and chain were still verified."},
        "forensic_report": {"status": report_status, "anchored_hash": block.report_hash, "current_hash": current_report},
        "ledger": {"block_index": block.block_index, "block_hash": block.block_hash, "previous_hash": block.previous_hash,
                   "anchored_at": block.timestamp, "chain_intact": chain["verified"], "chain_message": chain["message"]},
        "what_is_on_the_ledger": "Only case ID, SHA-256 of the evidence file, SHA-256 of the forensic report, timestamp, "
                                 "previous block hash and block hash. No e-mail content, addresses, tokens or personal data.",
        "scope_note": "This is a tamper-evident hash-chain ledger stored in the platform database (blockchain-style "
                      "linking). It proves records were not altered after analysis; it does not encrypt or hide the "
                      "e-mail data itself, and it is not a public blockchain.",
    }
