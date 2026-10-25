from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, List
from datetime import datetime


class SOARActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    QUARANTINE_USER = "QUARANTINE_USER"
    ISOLATE_HOST = "ISOLATE_HOST"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    ENFORCE_MFA = "ENFORCE_MFA"


class SOARActionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ROLLED_BACK = "ROLLED_BACK"
    PENDING = "PENDING"


class SOARAction(BaseModel):
    action_id: str
    incident_id: Optional[str] = None
    action_type: SOARActionType
    target: str
    status: SOARActionStatus = SOARActionStatus.ACTIVE
    reason: str
    executed_at: datetime = Field(default_factory=datetime.now)
    rolled_back_at: Optional[datetime] = None


class SOARExecutionRequest(BaseModel):
    incident_id: Optional[str] = None
    action_type: SOARActionType
    target: str
    reason: str
