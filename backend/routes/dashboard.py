from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Log, MerkleRoot
from services.hash_service import generate_hash

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_hash_chain_status(db: Session):
    logs = db.query(Log).order_by(Log.id.asc()).limit(1000).all()

    if not logs:
        return "No Logs"

    expected_previous_hash = "GENESIS"

    for log in logs:
        if log.previous_hash != expected_previous_hash:
            return "Tampered"

        # MUST match the exact dict used in logs.py during insertion
        log_data = {
            "timestamp": log.timestamp.isoformat() if log.timestamp else "NOW",
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "message": log.message
        }

        recalculated_hash = generate_hash(log_data, log.previous_hash)

        if recalculated_hash != log.current_hash:
            return "Tampered"

        expected_previous_hash = log.current_hash

    return "Valid"


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_logs = db.query(Log).count()
    total_merkle_roots = db.query(MerkleRoot).count()

    latest_root = db.query(MerkleRoot).order_by(MerkleRoot.id.desc()).first()
    latest_log = db.query(Log).order_by(Log.id.desc()).first()

    integrity_status = check_hash_chain_status(db)

    return {
        "total_logs": total_logs,
        "total_merkle_roots": total_merkle_roots,
        "latest_batch_id": latest_root.batch_id if latest_root else None,
        "latest_merkle_root": latest_root.root_hash if latest_root else None,
        "latest_log_id": latest_log.id if latest_log else None,
        "integrity_status": integrity_status
    }