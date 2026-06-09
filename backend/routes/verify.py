from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Log
from services.hash_service import generate_hash

router = APIRouter(
    prefix="/verify",
    tags=["Verification"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/hash-chain")
def verify_hash_chain(db: Session = Depends(get_db)):
    """
    Verifies the integrity of the entire log chain.
    Checks both the previous_hash link and the content hash.
    """
    logs = db.query(Log).order_by(Log.id.asc()).all()

    if not logs:
        return {
            "status": "Empty",
            "message": "No logs found for verification"
        }

    expected_previous_hash = "GENESIS"

    for log in logs:
        # 1. Check if the link to the previous log is broken
        if log.previous_hash != expected_previous_hash:
            return {
                "status": "Tampered",
                "tampered_log_id": log.id,
                "reason": "Previous hash link mismatch",
                "expected_previous_hash": expected_previous_hash,
                "found_previous_hash": log.previous_hash
            }

        # 2. Reconstruct the data exactly as it was during ingestion
        log_data = {
            "timestamp": log.timestamp.isoformat() if log.timestamp else "NOW",
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "message": log.message
        }

        # 3. Recalculate the hash
        recalculated_hash = generate_hash(log_data, log.previous_hash)

        # 4. Check if the content of this log has been changed
        if recalculated_hash != log.current_hash:
            return {
                "status": "Tampered",
                "tampered_log_id": log.id,
                "reason": "Log content hash mismatch",
                "stored_hash": log.current_hash,
                "recalculated_hash": recalculated_hash
            }

        # Move to the next log in the chain
        expected_previous_hash = log.current_hash

    return {
        "status": "Valid",
        "message": "Hash chain verified successfully. No tampering detected.",
        "total_logs_verified": len(logs)
    }


@router.put("/simulate-tamper/{log_id}")
def simulate_tampering(log_id: int, db: Session = Depends(get_db)):
    """
    Utility endpoint to simulate an attacker modifying a log message
    directly in the database without updating the hash.
    """
    log = db.query(Log).filter(Log.id == log_id).first()

    if not log:
        return {
            "status": "Not Found",
            "message": f"Log with ID {log_id} not found"
        }

    old_message = log.message
    log.message = log.message + " [TAMPERED]"

    db.commit()
    db.refresh(log)

    return {
        "status": "Tampering Simulated",
        "log_id": log.id,
        "old_message": old_message,
        "new_message": log.message,
        "note": "The message was changed, but the hash was NOT updated. Verification will now fail."
    }
