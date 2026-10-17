from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str

class AIAnalysisResult(BaseModel):
    incident_id: str
    title: str
    severity: str
    summary: str
    mitre_attack: List[MitreTechnique] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    full_report_markdown: str
    model_used: str
    timestamp: datetime = Field(default_factory=datetime.now)
