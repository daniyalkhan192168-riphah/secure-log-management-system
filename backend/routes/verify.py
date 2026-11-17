from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from deps import get_db
from routes.auth import client_ip
from security import require_admin, require_demo
from services import ledger
from services.monitor import monitor

router = APIRouter(prefix="/verify", tags=["Verification"])


@router.get("/hash-chain")
def verify_hash_chain(db: Session = Depends(get_db), claims: dict = Depends(require_admin)):
    """Full server-side verification now (also refreshes the dashboard's
    cached integrity status and raises an alert if tampering is new)."""
    return monitor.check_now(reason=f"manual check by {claims['sub']}", db=db)


# ---- Demo attacks: only when SECURELOG_DEMO_MODE=true, and only for admins.
# The admin action is recorded AFTER the attack so the demo shows exactly what
# an attacker's change looks like (a real attacker would not log anything).
@router.put("/simulate-tamper/{log_id}", dependencies=[Depends(require_demo)])
def simulate_tampering(log_id: int, request: Request, db: Session = Depends(get_db),
                       claims: dict = Depends(require_admin)):
    result = ledger.simulate_tamper(db, log_id)
    ledger.record_server_event(db, "DEMO_ATTACK", claims["sub"], client_ip(request),
                               f"Demo: simulate-tamper on log {log_id}")
    monitor.check_now(reason="after demo attack", db=db)
    return result


@router.put("/simulate-rewrite/{log_id}", dependencies=[Depends(require_demo)])
def simulate_rewrite(log_id: int, request: Request, db: Session = Depends(get_db),
                     claims: dict = Depends(require_admin)):
    result = ledger.simulate_rewrite(db, log_id)
    ledger.record_server_event(db, "DEMO_ATTACK", claims["sub"], client_ip(request),
                               f"Demo: simulate-rewrite on log {log_id}")
    monitor.check_now(reason="after demo attack", db=db)
    return result