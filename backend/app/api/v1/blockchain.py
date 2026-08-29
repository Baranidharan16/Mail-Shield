from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.blockchain.ledger import verify_chain
from app.models.investigation import BlockchainBlock

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.get("/verify")
def verify(db: Session = Depends(get_db)):
    return verify_chain(db)


@router.get("/blocks")
def list_blocks(db: Session = Depends(get_db), limit: int = 50):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).limit(limit).all()
    return [
        {"block_index": b.block_index, "case_id": b.case_id, "timestamp": b.timestamp,
         "evidence_hash": b.evidence_hash, "block_hash": b.block_hash, "previous_hash": b.previous_hash}
        for b in blocks
    ]
