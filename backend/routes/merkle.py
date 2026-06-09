from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Log, MerkleRoot
from services.merkle_service import build_merkle_root
from services.hash_service import generate_hash
from services.key_manager import get_current_key_state

router = APIRouter(
    prefix="/merkle",
    tags=["Merkle Tree"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/generate/{batch_id}")
def generate_merkle_root(batch_id: int, db: Session = Depends(get_db)):
    """
    Generates a Merkle Root for a specific batch of logs and seals it
    with the current forward-secure key state.
    """
    logs = db.query(Log).filter(Log.batch_id == batch_id).order_by(Log.id.asc()).all()

    if not logs:
        return {
            "status": "Not Found",
            "message": f"No logs found for batch {batch_id}"
        }

    # We use the current_hash already stored in the database
    hashes = [log.current_hash for log in logs]
    root_hash = build_merkle_root(hashes)

    # Get current forward-secure key metadata
    key_state = get_current_key_state()
    key_version = key_state["key_version"]
    forward_secure_key_hash = key_state["current_key_hash"]

    existing_root = db.query(MerkleRoot).filter(MerkleRoot.batch_id == batch_id).first()

    if existing_root:
        existing_root.root_hash = root_hash
        existing_root.total_logs = len(logs)
        existing_root.key_version = key_version
        existing_root.forward_secure_key_hash = forward_secure_key_hash

        db.commit()
        db.refresh(existing_root)

        return {
            "status": "Updated",
            "batch_id": batch_id,
            "root_hash": root_hash,
            "total_logs": len(logs),
            "key_version": key_version,
            "forward_secure_key_hash": forward_secure_key_hash
        }

    new_root = MerkleRoot(
        batch_id=batch_id,
        root_hash=root_hash,
        total_logs=len(logs),
        key_version=key_version,
        forward_secure_key_hash=forward_secure_key_hash
    )

    db.add(new_root)
    db.commit()
    db.refresh(new_root)

    return {
        "status": "Generated",
        "batch_id": batch_id,
        "root_hash": root_hash,
        "total_logs": len(logs),
        "key_version": key_version,
        "forward_secure_key_hash": forward_secure_key_hash
    }


@router.get("/roots")
def get_merkle_roots(db: Session = Depends(get_db)):
    roots = db.query(MerkleRoot).order_by(MerkleRoot.id.asc()).all()
    return roots


@router.get("/verify/{batch_id}")
def verify_merkle_root(batch_id: int, db: Session = Depends(get_db)):
    """
    Verifies a Merkle Root by recalculating all log hashes in the batch
    and rebuilding the Merkle Tree from scratch.
    """
    stored_root = db.query(MerkleRoot).filter(MerkleRoot.batch_id == batch_id).first()

    if not stored_root:
        return {
            "status": "Not Found",
            "message": f"No Merkle Root found for batch {batch_id}"
        }

    logs = db.query(Log).filter(Log.batch_id == batch_id).order_by(Log.id.asc()).all()

    if not logs:
        return {
            "status": "Not Found",
            "message": f"No logs found for batch {batch_id}"
        }

    recalculated_hashes = []

    for log in logs:
        # Reconstruct the data dictionary exactly as it was during ingestion
        log_data = {
            "timestamp": log.timestamp.isoformat() if log.timestamp else "NOW",
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "message": log.message
        }

        # Recalculate the hash for this specific log
        recalculated_hash = generate_hash(log_data, log.previous_hash)
        recalculated_hashes.append(recalculated_hash)

    # Rebuild the Merkle Tree from the recalculated hashes
    recalculated_root = build_merkle_root(recalculated_hashes)

    if recalculated_root != stored_root.root_hash:
        return {
            "status": "Tampered",
            "batch_id": batch_id,
            "reason": "Merkle root mismatch - data has been modified",
            "stored_root": stored_root.root_hash,
            "recalculated_root": recalculated_root
        }

    return {
        "status": "Valid",
        "batch_id": batch_id,
        "message": "Merkle Root verified successfully. All logs in this batch are untampered.",
        "root_hash": stored_root.root_hash,
        "total_logs_verified": len(logs)
    }
