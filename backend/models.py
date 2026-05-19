from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    source = Column(String(100))
    event_type = Column(String(100))
    username = Column(String(100))
    ip_address = Column(String(50))
    message = Column(Text)

    previous_hash = Column(Text)
    current_hash = Column(Text)
    batch_id = Column(Integer, default=1)

    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100))
    severity = Column(String(50))
    description = Column(Text)
    log_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)


class MerkleRoot(Base):
    __tablename__ = "merkle_roots"

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(Integer)
    root_hash = Column(Text)
    total_logs = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)