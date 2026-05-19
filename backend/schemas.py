from pydantic import BaseModel
from datetime import datetime

class LogCreate(BaseModel):
    source: str
    event_type: str
    username: str
    ip_address: str
    message: str


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
    batch_id: int

    class Config:
        from_attributes = True