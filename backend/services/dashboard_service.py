"""
Dashboard statistics, computed over ALL logs with SQL (not just the rows the
browser has loaded), using the single severity rule in services/severity.py.
"""
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from config import BATCH_SIZE, SEAL_MAX_AGE_SECONDS
from models import Alert, Log, MerkleRoot
from services import agents as agent_service
from services import key_manager as km
from services import ledger
from services.severity import LEVELS, severity


def serialize_log(l: Log) -> dict:
    return {
        "id": l.id,
        "timestamp": ledger.ts_string(l.timestamp),
        "event_time": ledger.ts_string(l.event_time) if l.event_time else None,
        "source": l.source,
        "event_type": l.event_type,
        "severity": severity(l.event_type),
        "username": l.username,
        "ip_address": l.ip_address,
        "message": l.message,
        "agent_id": l.agent_id,
        "previous_hash": l.previous_hash,
        "current_hash": l.current_hash,
        "mac": l.mac,
        "batch_id": l.batch_id,
    }


def event_types_with(db: Session, levels: set) -> list:
    return [et for (et,) in db.query(Log.event_type).distinct() if severity(et) in levels]


def severity_counts(db: Session) -> dict:
    counts = {level: 0 for level in LEVELS}
    for event_type, n in db.query(Log.event_type, func.count(Log.id)).group_by(Log.event_type):
        counts[severity(event_type)] += n
    return counts


def top_ips(db: Session, limit: int = 5) -> list:
    count = func.count(Log.id).label("count")
    rows = (db.query(Log.ip_address, count)
            .filter(Log.ip_address.notin_(["-", ""]))
            .group_by(Log.ip_address).order_by(desc("count")).limit(limit).all())
    return [{"ip": ip, "count": n} for ip, n in rows]


def recent_threats(db: Session, limit: int = 5) -> list:
    types = event_types_with(db, {"critical", "high"})
    if not types:
        return []
    rows = (db.query(Log).filter(Log.event_type.in_(types))
            .order_by(Log.id.desc()).limit(limit).all())
    return [serialize_log(l) for l in rows]


def recent_batches(db: Session, limit: int = 5) -> list:
    rows = db.query(MerkleRoot).order_by(MerkleRoot.batch_id.desc()).limit(limit).all()
    return [{
        "batch_id": r.batch_id,
        "first_log_id": r.first_log_id,
        "last_log_id": r.last_log_id,
        "total_logs": r.total_logs,
        "root_hash": r.root_hash,
        "seal": r.seal,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]


def recent_alerts(db: Session, limit: int = 10) -> list:
    rows = db.query(Alert).order_by(Alert.id.desc()).limit(limit).all()
    return [{
        "id": a.id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "description": a.description,
        "log_id": a.log_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    } for a in rows]


def build_stats(db: Session, integrity: dict) -> dict:
    last = ledger.last_sealed(db)
    latest_log = db.query(Log).order_by(Log.id.desc()).first()
    open_batch = ledger.open_batch_id(db)
    key_state = km.public_state()
    return {
        "total_logs": db.query(Log).count(),
        "total_merkle_roots": db.query(MerkleRoot).count(),
        "latest_batch_id": last.batch_id if last else None,      # last SEALED batch
        "latest_merkle_root": last.root_hash if last else None,
        "open_batch_id": open_batch,
        "open_batch_logs": db.query(Log).filter(Log.batch_id == open_batch).count(),
        "batch_size": BATCH_SIZE,
        "seal_max_age_seconds": SEAL_MAX_AGE_SECONDS,
        "latest_log_id": latest_log.id if latest_log else None,
        "key_version": key_state["key_version"],
        "k0_fingerprint": key_state["k0_fingerprint"],
        "integrity_status": integrity["status"],
        "integrity": integrity,
        "severity_counts": severity_counts(db),
        "top_ips": top_ips(db),
        "recent_threats": recent_threats(db),
        "recent_batches": recent_batches(db),
        "total_alerts": db.query(Alert).count(),
        "agents": agent_service.list_agents(db),
    }