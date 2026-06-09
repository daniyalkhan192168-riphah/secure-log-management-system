from fastapi import APIRouter, Depends
from datetime import datetime
from sqlalchemy.orm import Session
import threading

from database import SessionLocal
from models import Log
from schemas import LogCreate, LogResponse
from services.hash_service import generate_hash

router = APIRouter(
    prefix="/logs",
    tags=["Logs"]
)

# This lock prevents two logs from being inserted at the same time
# which would cause both to grab the same previous_hash (race condition)
_insert_lock = threading.Lock()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/add", response_model=LogResponse)
def add_log(
    log: LogCreate,
    db: Session = Depends(get_db)
):
    with _insert_lock:
        # 1. Get the previous hash to maintain the chain
        latest_log = db.query(Log).order_by(Log.id.desc()).first()
        previous_hash = latest_log.current_hash if latest_log else "GENESIS"

        # 2. Determine the batch (100 logs per batch)
        total_logs = db.query(Log).count()
        batch_id = (total_logs // 100) + 1

        # 3. Capture timestamp NOW so it goes into the hash
        current_time = datetime.utcnow()

        new_log = Log(
            source=log.source,
            event_type=log.event_type,
            username=log.username,
            ip_address=log.ip_address,
            message=log.message,
            previous_hash=previous_hash,
            batch_id=batch_id,
            timestamp=current_time
        )

        # 4. Construct the data dictionary for hashing (MUST include timestamp)
        log_data = {
            "timestamp": current_time.isoformat(),
            "source": new_log.source,
            "event_type": new_log.event_type,
            "username": new_log.username,
            "ip_address": new_log.ip_address,
            "message": new_log.message
        }

        # 5. Generate the hash and assign it to the log
        new_log.current_hash = generate_hash(log_data, previous_hash)

        # 6. Save to database
        db.add(new_log)
        db.commit()
        db.refresh(new_log)

        return new_log


@router.get("/")
def get_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(Log).order_by(Log.id.desc()).limit(limit).all()

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "source": log.source,
            "event_type": log.event_type,
            "username": log.username,
            "ip_address": log.ip_address,
            "message": log.message,
            "previous_hash": log.previous_hash,
            "current_hash": log.current_hash,
            "batch_id": log.batch_id,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]