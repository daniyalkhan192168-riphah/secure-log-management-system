from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from deps import get_db
from models import Log
from schemas import LogCreate, LogResponse
from security import require_admin, require_agent
from services import ledger
from services.dashboard_service import event_types_with, serialize_log
from services.key_manager import KeyStateError
from services.severity import LEVELS

router = APIRouter(prefix="/logs", tags=["Logs"])


def _append(db: Session, log: LogCreate, agent_id: str):
    try:
        return ledger.append_log(db, log.model_dump(), agent_id=agent_id)
    except KeyStateError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/add", response_model=LogResponse)
def add_log(log: LogCreate, db: Session = Depends(get_db), agent: str = Depends(require_agent)):
    """Used by log agents. Authenticated with the X-API-KEY header."""
    return _append(db, log, agent_id=agent)


@router.post("/manual", response_model=LogResponse)
def add_manual_log(log: LogCreate, db: Session = Depends(get_db),
                   claims: dict = Depends(require_admin)):
    """Used by the dashboard form. Recorded as coming from 'dashboard:<user>'."""
    return _append(db, log, agent_id=f"dashboard:{claims['sub']}")


@router.get("/")
def get_logs(limit: int = 100, offset: int = 0, q: Optional[str] = None,
             severity: Optional[str] = None, db: Session = Depends(get_db),
             claims: dict = Depends(require_admin)):
    """Search and filter across ALL logs (newest first).
    q: text in message/user/IP/source/event/agent, or an exact log id.
    severity: critical | high | medium | low"""
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    query = db.query(Log)

    if q and q.strip():
        text = q.strip()[:100]
        like = f"%{text}%"
        conditions = [Log.message.ilike(like), Log.username.ilike(like),
                      Log.ip_address.ilike(like), Log.source.ilike(like),
                      Log.event_type.ilike(like), Log.agent_id.ilike(like)]
        if text.isdigit():
            conditions.append(Log.id == int(text))
        query = query.filter(or_(*conditions))

    if severity in LEVELS:
        types = event_types_with(db, {severity})
        query = query.filter(Log.event_type.in_(types)) if types else query.filter(Log.id < 0)

    total = query.count()
    rows = query.order_by(Log.id.desc()).offset(offset).limit(limit).all()
    return {"items": [serialize_log(l) for l in rows], "total": total,
            "limit": limit, "offset": offset}