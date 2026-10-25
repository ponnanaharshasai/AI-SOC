from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class AutonomousRunSummary(BaseModel):
    run_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    events_processed: int = 0
    correlations_found: int = 0
    detections_triggered: int = 0
    incidents_created: int = 0
    ai_investigations_completed: int = 0
    containment_actions_executed: int = 0
    overall_threat_level: str = "NORMAL"
    execution_time_seconds: float = 0.0
    action_logs: List[str] = Field(default_factory=list)
    mitre_summary: Dict[str, int] = Field(default_factory=dict)


class AutonomousStatus(BaseModel):
    mode: str = "AUTONOMOUS_READY"
    ai_analyst_status: str = "ONLINE"
    active_incidents: int = 0
    contained_incidents: int = 0
    active_containments: int = 0
    last_run_timestamp: Optional[datetime] = None
