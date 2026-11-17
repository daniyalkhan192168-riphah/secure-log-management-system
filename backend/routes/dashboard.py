from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from deps import get_db
from security import require_admin
from services import dashboard_service
from services.monitor import monitor

router = APIRouter(prefix="/dashboard", tags=["Dashboard"],
                   dependencies=[Depends(require_admin)])


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Cheap to call every few seconds: the integrity part comes from the
    background monitor's latest check instead of re-verifying every log."""
    return dashboard_service.build_stats(db, monitor.latest())


@router.get("/alerts")
def get_alerts(limit: int = 10, db: Session = Depends(get_db)):
    return dashboard_service.recent_alerts(db, max(1, min(limit, 100)))