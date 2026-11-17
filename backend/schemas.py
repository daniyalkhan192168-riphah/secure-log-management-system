from typing import Optional

from pydantic import BaseModel, Field
from datetime import datetime

class LogCreate(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=1, max_length=100)
    ip_address: str = Field(min_length=1, max_length=50)
    message: str = Field(min_length=1, max_length=4000)
    event_time: Optional[datetime] = None

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    username: str
    ip_address: str
    message: str
    previous_hash: str
    current_hash: str
    mac: str
    agent_id: str
    event_time: Optional[datetime] = None
    batch_id: int

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)



class Witness(BaseModel):
    batch_id: int = Field(ge=1)
    seal: str = Field(min_length=64, max_length=64)


class HeartbeatRequest(BaseModel):
    hostname: str = Field("", max_length=100)
    version: str = Field("", max_length=20)
    spool_size: int = Field(0, ge=0)
    uptime_seconds: int = Field(0, ge=0)
    witness: Optional[Witness] = None
    stopping: bool = False