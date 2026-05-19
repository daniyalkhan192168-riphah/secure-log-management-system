from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Log
from schemas import LogCreate, LogResponse
from services.hash_service import generate_hash

router = APIRouter(
    prefix="/logs",
    tags=["Logs"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/add", response_model=LogResponse)
def add_log(log: LogCreate, db: Session = Depends(get_db)):
    latest_log = db.query(Log).order_by(Log.id.desc()).first()

    if latest_log:
        previous_hash = latest_log.current_hash
    else:
        previous_hash = "GENESIS"

    total_logs = db.query(Log).count()
    batch_id = (total_logs // 100) + 1

    log_data = {
        "source": log.source,
        "event_type": log.event_type,
        "username": log.username,
        "ip_address": log.ip_address,
        "message": log.message
    }

    current_hash = generate_hash(log_data, previous_hash)

    new_log = Log(
        source=log.source,
        event_type=log.event_type,
        username=log.username,
        ip_address=log.ip_address,
        message=log.message,
        previous_hash=previous_hash,
        current_hash=current_hash,
        batch_id=batch_id
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log


@router.get("/", response_model=list[LogResponse])
def get_logs(limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Log).order_by(Log.id.desc()).limit(limit).all()
