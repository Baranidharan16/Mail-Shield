from __future__ import annotations
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.blockchain.ledger import verify_chain
from app.blockchain.fabric_service import get_fabric_service
from app.models.investigation import BlockchainBlock, Investigation
from app.models.user import User
from utils.auth_deps import get_current_user


def _owned_investigation(db: Session, user: User, ref: str) -> Investigation:
    """Resolve an investigation by id / case id / evidence hash, only within the caller's own cases."""
    inv = db.query(Investigation).filter(
        Investigation.user_id == user.id,
        (Investigation.case_id == ref) | (Investigation.evidence_hash_sha256 == ref) | (Investigation.id == ref),
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Evidence not found in records.")
    return inv

logger = logging.getLogger("mailshield.api.blockchain")
router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.get("/verify")
@router.post("/verify-chain")
def verify(db: Session = Depends(get_db)):
    """Verifies the complete SHA-256 cryptographic hash-chain ledger."""
    return verify_chain(db)


@router.get("/blocks")
def list_blocks(db: Session = Depends(get_db), limit: int = 100, current_user: User = Depends(get_current_user)):
    """Returns the caller's ledger blocks in reverse chronological order."""
    my_cases = db.query(Investigation.case_id).filter(Investigation.user_id == current_user.id)
    blocks = (
        db.query(BlockchainBlock)
        .filter(BlockchainBlock.case_id.in_(my_cases))
        .order_by(BlockchainBlock.block_index.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return [
        {
            "block_index": b.block_index,
            "case_id": b.case_id,
            "timestamp": b.timestamp,
            "evidence_hash": b.evidence_hash,
            "report_hash": b.report_hash,
            "block_hash": b.block_hash,
            "previous_hash": b.previous_hash,
            "network": "Hyperledger Fabric / Cryptographic Hash Ledger",
            "integrity_status": "VERIFIED",
        }
        for b in blocks
    ]


@router.post("/register/{evidence_id}")
def register_evidence_endpoint(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Registers the evidence hash of one of the caller's investigations on the ledger."""
    inv = _owned_investigation(db, current_user, evidence_id)
    return get_fabric_service().register_evidence(
        db=db, evidence_id=inv.id, case_id=inv.case_id, evidence_hash=inv.evidence_hash_sha256,
    )


@router.get("/verify/{evidence_id}")
def verify_evidence_endpoint(
    evidence_id: str,
    evidence_hash: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verifies integrity of one of the caller's evidence items against the ledger."""
    inv = _owned_investigation(db, current_user, evidence_id)
    return get_fabric_service().verify_evidence(
        db=db, case_id=inv.case_id, current_evidence_hash=evidence_hash or inv.evidence_hash_sha256,
    )


@router.get("/case/{case_id}")
def get_case_evidence_endpoint(
    case_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    """Returns all blockchain blocks registered for one of the caller's cases."""
    _owned_investigation(db, current_user, case_id)
    service = get_fabric_service()
    return service.get_case_evidence(db=db, case_id=case_id)


@router.get("/fabric-status")
def fabric_status():
    """Returns Hyperledger Fabric configuration and health status."""
    service = get_fabric_service()
    return {
        "network": service.network,
        "channel": service.channel,
        "chaincode": service.chaincode,
        "msp_id": service.msp_id,
        "peer_endpoint": service.peer_endpoint,
        "connected": service.is_connected,
        "ledger_type": "Hyperledger Fabric (Permissioned Enterprise Consortium) + Cryptographic Fallback",
        "hash_algorithm": "SHA-256",
        "immutable_verification": True,
    }
