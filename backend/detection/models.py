from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DetectionResult(BaseModel):
    detection_id: str
    rule_id: str
    detection_type: str
    severity: Severity
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    description: str
    evidence: Dict[str, Any]
    related_event_ids: List[str]