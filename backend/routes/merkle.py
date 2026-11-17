from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from deps import get_db
from models import MerkleRoot
from routes.auth import client_ip
from security import require_admin
from services import ledger
from services.key_manager import KeyStateError

# Every Merkle endpoint requires a logged-in admin.
router = APIRouter(prefix="/merkle", tags=["Merkle Tree"], dependencies=[Depends(require_admin)])


@router.post("/seal")
def seal_now(request: Request, db: Session = Depends(get_db),
             claims: dict = Depends(require_admin)):
    """Seal the open batch now. Batches also seal automatically at BATCH_SIZE logs.
    Sealed roots are append-only; there is no endpoint to overwrite one."""
    # Record the action first, so it is sealed inside the batch it closes.
    ledger.record_server_event(db, "ADMIN_SEAL", claims["sub"], client_ip(request),
                               f"Admin '{claims['sub']}' sealed the open batch manually")
    try:
        row = ledger.seal_open_batch(db)
    except KeyStateError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if row is None:
        return {"status": "Nothing to seal", "message": "The open batch is empty (it may have just been sealed automatically)"}
    return {
        "status": "Sealed",
        "batch_id": row.batch_id,
        "first_log_id": row.first_log_id,
        "last_log_id": row.last_log_id,
        "total_logs": row.total_logs,
        "root_hash": row.root_hash,
        "seal": row.seal,
        "key_version_used": row.key_version,
        "message": f"Key evolved to version {row.batch_id + 1}; key {row.batch_id} destroyed.",
    }


@router.get("/roots")
def get_merkle_roots(db: Session = Depends(get_db)):
    rows = db.query(MerkleRoot).order_by(MerkleRoot.batch_id.asc()).all()
    return [
        {
            "batch_id": r.batch_id, "first_log_id": r.first_log_id,
            "last_log_id": r.last_log_id, "total_logs": r.total_logs,
            "root_hash": r.root_hash, "key_version": r.key_version,
            "previous_seal": r.previous_seal, "seal": r.seal,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/verify/{batch_id}")
def verify_merkle_root(batch_id: int, db: Session = Depends(get_db)):
    return ledger.verify_batch(db, batch_id)


@router.get("/proof/{log_id}")
def merkle_proof(log_id: int, db: Session = Depends(get_db)):
    return ledger.merkle_proof(db, log_id)


@router.get("/tree/{batch_id}")
def merkle_tree(batch_id: int, db: Session = Depends(get_db)):
    return ledger.merkle_tree(db, batch_id)