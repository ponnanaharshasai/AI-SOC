from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"

class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Incident(BaseModel):
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime
    updated_at: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    assigned_to: Optional[str] = None
    summary: Optional[str] = None
    remediation_notes: Optional[str] = None
    detection_ids: List[str] = Field(default_factory=list)

class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    remediation_notes: Optional[str] = None
    summary: Optional[str] = None
