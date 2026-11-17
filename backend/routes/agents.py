from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from deps import get_db
from routes.auth import client_ip
from schemas import HeartbeatRequest
from security import require_admin, require_agent
from services import agents

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("/heartbeat")
def heartbeat(body: HeartbeatRequest, request: Request, db: Session = Depends(get_db),
              agent: str = Depends(require_agent)):
    """Called by each agent every 60 s. The reply carries the server's latest
    seal, which the agent keeps as a witness against rollback."""
    return agents.heartbeat(db, agent, client_ip(request), body.model_dump())


@router.get("/")
def list_agents(db: Session = Depends(get_db), claims: dict = Depends(require_admin)):
    return agents.list_agents(db)