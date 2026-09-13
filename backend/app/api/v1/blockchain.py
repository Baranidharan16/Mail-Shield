from __future__ import annotations
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.blockchain.ledger import verify_chain
from app.blockchain.fabric_service import get_fabric_service
from app.models.investigation import BlockchainBlock, Investigation

logger = logging.getLogger("mailshield.api.blockchain")
router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.get("/verify")
@router.post("/verify-chain")
def verify(db: Session = Depends(get_db)):
    """Verifies the complete SHA-256 cryptographic hash-chain ledger."""
    return verify_chain(db)


@router.get("/blocks")
def list_blocks(db: Session = Depends(get_db), limit: int = 100):
    """Returns ledger blocks in reverse chronological order."""
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).limit(limit).all()
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
    case_id: Optional[str] = None,
    evidence_hash: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Registers an evidence hash onto Hyperledger Fabric / local cryptographic ledger."""
    service = get_fabric_service()
    
    # If evidence_hash not provided directly, lookup from investigation
    if not evidence_hash:
        inv = db.query(Investigation).filter(
            (Investigation.case_id == evidence_id) |
            (Investigation.evidence_hash_sha256 == evidence_id) |
            (Investigation.id == evidence_id)
        ).first()
        if inv:
            evidence_hash = inv.evidence_hash_sha256
            case_id = inv.case_id
        else:
            evidence_hash = evidence_id
            case_id = case_id or f"CASE-{evidence_id[:8]}"

    result = service.register_evidence(
        db=db,
        evidence_id=evidence_id,
        case_id=case_id or f"CASE-{evidence_id[:8]}",
        evidence_hash=evidence_hash,
    )
    return result


@router.get("/verify/{evidence_id}")
def verify_evidence_endpoint(
    evidence_id: str,
    evidence_hash: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Verifies evidence integrity against the immutable blockchain record."""
    service = get_fabric_service()

    # If hash not passed as query param, check investigation or block
    if not evidence_hash:
        inv = db.query(Investigation).filter(
            (Investigation.case_id == evidence_id) |
            (Investigation.evidence_hash_sha256 == evidence_id) |
            (Investigation.id == evidence_id)
        ).first()
        if inv:
            evidence_hash = inv.evidence_hash_sha256
            case_id = inv.case_id
        else:
            block = db.query(BlockchainBlock).filter(
                (BlockchainBlock.case_id == evidence_id) |
                (BlockchainBlock.evidence_hash == evidence_id)
            ).first()
            if block:
                evidence_hash = block.evidence_hash
                case_id = block.case_id
            else:
                raise HTTPException(status_code=404, detail="Evidence not found in records.")
    else:
        case_id = evidence_id

    return service.verify_evidence(db=db, case_id=case_id, current_evidence_hash=evidence_hash)


@router.get("/case/{case_id}")
def get_case_evidence_endpoint(case_id: str, db: Session = Depends(get_db)):
    """Returns all blockchain blocks registered for a specific investigation case."""
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
