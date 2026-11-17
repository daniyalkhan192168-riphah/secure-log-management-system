from sqlalchemy import Column, Integer, String, Text, DateTime, UniqueConstraint
from datetime import datetime, timezone
from database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)

    source = Column(String(100), nullable=False)
    event_type = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
        # WHO sent the log, decided by the server from the authenticated API key
    # (never taken from the request body), e.g. "ubuntu-vm" or "dashboard:admin".
    agent_id = Column(String(100), nullable=False, index=True)
    # When the event happened on the source machine (journal time), in UTC.
    # `timestamp` is when the backend received it. Both are hashed.
    event_time = Column(DateTime, nullable=True)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)   # entry hash (public chain)
    mac = Column(String(64), nullable=False)            # HMAC with the batch key
    batch_id = Column(Integer, nullable=False, index=True)

    created_at = Column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100))
    severity = Column(String(50))
    description = Column(Text)
    log_id = Column(Integer)
    created_at = Column(DateTime, default=utcnow)


class MerkleRoot(Base):
    """One row per SEALED batch. Rows are append-only: never updated."""
    __tablename__ = "merkle_roots"
    __table_args__ = (UniqueConstraint("batch_id", name="uq_merkle_batch"),)

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(Integer, nullable=False)
    first_log_id = Column(Integer, nullable=False)
    last_log_id = Column(Integer, nullable=False)
    total_logs = Column(Integer, nullable=False)
    root_hash = Column(String(64), nullable=False)

    key_version = Column(Integer, nullable=False)
    previous_seal = Column(String(64), nullable=False)
    seal = Column(String(64), nullable=False)          # HMAC(K_b, header)

    created_at = Column(DateTime, default=utcnow)


class AgentStatus(Base):
    """Live status of each log agent, updated by its heartbeats.
    Not part of the hash chain (heartbeats are frequent); every status CHANGE
    is written to the tamper-evident ledger as an event instead."""
    __tablename__ = "agent_status"

    agent_id = Column(String(100), primary_key=True)
    hostname = Column(String(100), default="")
    version = Column(String(20), default="")
    last_ip = Column(String(50), default="")
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    status = Column(String(20), default="online")          # online | stopped | silent
    spool_size = Column(Integer, default=0)
    witness_batch = Column(Integer, nullable=True)          # newest sealed batch the agent has seen
    last_witness_alert = Column(String(100), nullable=True)  # prevents repeating the same alert