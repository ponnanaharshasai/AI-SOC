from pydantic import BaseModel, IPvAnyAddress, Field
from typing import Optional
from datetime import datetime

class NormalizedEvent(BaseModel):
    event_id: Optional[str] = None
    timestamp: datetime
    source: Optional[str] = None
    source_ip: Optional[IPvAnyAddress] = None
    destination_ip: Optional[IPvAnyAddress] = None
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    username: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
