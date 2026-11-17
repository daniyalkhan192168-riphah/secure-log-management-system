"""
Agent heartbeats, silence detection and the rollback witness.

Heartbeat (every 60 s from each agent):
  * keeps agent_status up to date (last seen, host, queue size, version);
  * status CHANGES are written to the tamper-evident ledger:
      AGENT_ONLINE  - first contact, or back after being stopped/silent
      AGENT_STOPPED - the agent said it is stopping (service stop / shutdown)
      AGENT_SILENT  - raised by the monitor when heartbeats stop arriving

Rollback witness:
  Each heartbeat reply tells the agent the server's latest seal; the agent
  stores the newest one it has seen on ITS machine and sends it back next time.
  If the server's database is rolled back (old backup restored) or truncated,
  the agent's witness is newer than anything the server has -> ROLLBACK_DETECTED.
  If the server has the same batch but a different seal -> SEAL_MISMATCH.
"""
from datetime import timedelta

from sqlalchemy.orm import Session

import config
from models import Alert, AgentStatus, MerkleRoot
from services import ledger
from services.auth import parse_agent_keys


def _fmt_duration(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:.1f} h"


def raise_alert(db: Session, alert_type: str, severity: str, description: str,
                username: str = "system", ip: str = "-"):
    """Store an alert for the dashboard and write the same event into the ledger."""
    try:
        db.add(Alert(alert_type=alert_type, severity=severity, description=description[:2000]))
        db.commit()
    except Exception as e:  # noqa: BLE001
        db.rollback()
        print(f"[WARN] could not store alert: {e}")
    ledger.record_server_event(db, alert_type, username, ip, description)
    print(f"[ALERT] {alert_type}: {description}")


# ---------------------------------------------------------------- heartbeat
def heartbeat(db: Session, agent_id: str, ip: str, data: dict) -> dict:
    now = ledger.utcnow()
    row = db.query(AgentStatus).filter(AgentStatus.agent_id == agent_id).first()
    previous_status = row.status if row else None
    previous_seen = row.last_seen if row else None

    if row is None:
        row = AgentStatus(agent_id=agent_id, first_seen=now)
        db.add(row)
    row.last_seen = now
    row.last_ip = (ip or "")[:50]
    row.hostname = (data.get("hostname") or "")[:100]
    row.version = (data.get("version") or "")[:20]
    row.spool_size = int(data.get("spool_size") or 0)
    witness = data.get("witness")
    if witness:
        row.witness_batch = witness["batch_id"]

    host = row.hostname or "unknown host"
    if data.get("stopping"):
        row.status = "stopped"
        db.commit()
        raise_alert(db, "AGENT_STOPPED", "high",
                    f"Agent '{agent_id}' on {host} reported that it is stopping "
                    f"(service stopped or machine shutting down). No logs will arrive "
                    f"until it restarts.", agent_id, ip)
    else:
        row.status = "online"
        db.commit()
        if previous_status is None:
            ledger.record_server_event(db, "AGENT_ONLINE", agent_id, ip,
                                       f"Agent '{agent_id}' on {host} connected for the first time")
        elif previous_status in ("stopped", "silent"):
            gap = _fmt_duration(now - previous_seen) if previous_seen else "unknown time"
            message = (f"Agent '{agent_id}' on {host} is back online after {gap} ({previous_status}). "
                       f"Events from the gap are sent from its saved journal position, unless they "
                       f"were deleted on that machine meanwhile.")
            ledger.record_server_event(db, "AGENT_ONLINE", agent_id, ip, message)
            # Also show the recovery in the alerts panel, right after the problem.
            db.add(Alert(alert_type="AGENT_ONLINE", severity="info", description=message[:2000]))
            db.commit()
    _check_witness(db, row, witness, ip)

    latest = ledger.last_sealed(db)
    return {
        "status": "ok",
        "server_time": ledger.ts_string(now),
        "latest_seal": {"batch_id": latest.batch_id, "seal": latest.seal} if latest else None,
    }


def _check_witness(db: Session, row: AgentStatus, witness, ip: str):
    if not witness:
        return
    wb, ws = witness["batch_id"], witness["seal"]
    latest = ledger.last_sealed(db)
    sealed = db.query(MerkleRoot).filter(MerkleRoot.batch_id == wb).first()

    problem = None
    if latest is None or latest.batch_id < wb:
        problem = ("ROLLBACK_DETECTED",
                   f"Agent '{row.agent_id}' has already seen sealed batch {wb}, but the server's "
                   f"newest sealed batch is {latest.batch_id if latest else 'none'}. The log "
                   f"database was rolled back to an older copy or truncated; logs after "
                   f"batch {latest.batch_id if latest else 0} are missing.")
    elif sealed is not None and sealed.seal != ws:
        problem = ("SEAL_MISMATCH",
                   f"Agent '{row.agent_id}' saw a different seal for batch {wb} than the one "
                   f"now stored. The sealed batch was replaced or forged.")

    if problem is None:
        if row.last_witness_alert:
            row.last_witness_alert = None
            db.commit()
        return
    key = f"{problem[0]}:{wb}"
    if row.last_witness_alert == key:        # already reported
        return
    row.last_witness_alert = key
    db.commit()
    raise_alert(db, problem[0], "critical", problem[1], row.agent_id, ip)


# ---------------------------------------------------------------- silence
def check_silent(db: Session, silence_seconds: int = None) -> list:
    """Mark online agents without a recent heartbeat as silent and alert."""
    limit = silence_seconds or config.AGENT_SILENCE_SECONDS
    cutoff = ledger.utcnow() - timedelta(seconds=limit)
    silent = (db.query(AgentStatus)
              .filter(AgentStatus.status == "online", AgentStatus.last_seen < cutoff).all())
    names = []
    for row in silent:
        row.status = "silent"
        db.commit()
        raise_alert(db, "AGENT_SILENT", "high",
                    f"No heartbeat from agent '{row.agent_id}' on {row.hostname or 'unknown host'} "
                    f"since {ledger.ts_string(row.last_seen)} UTC (over {limit} s). The agent was "
                    f"stopped, crashed, or its machine or network is down.", row.agent_id, row.last_ip)
        names.append(row.agent_id)
    return names


# ---------------------------------------------------------------- listing
def list_agents(db: Session) -> list:
    """All registered agents, including ones that have never connected."""
    rows = {r.agent_id: r for r in db.query(AgentStatus)}
    registered = set(parse_agent_keys(config.AGENT_KEYS).values())
    result = []
    for name in sorted(registered | set(rows)):
        r = rows.get(name)
        result.append({
            "agent_id": name,
            "registered": name in registered,
            "status": r.status if r else "never seen",
            "hostname": r.hostname if r else "",
            "version": r.version if r else "",
            "last_ip": r.last_ip if r else "",
            "last_seen": ledger.ts_string(r.last_seen) if r and r.last_seen else None,
            "spool_size": r.spool_size if r else 0,
            "witness_batch": r.witness_batch if r else None,
        })
    return result