"""
Correlation result models.

A CorrelationResult groups related security events that share common
attributes (source IP, username, time proximity) into one structure.
This is purely relational - it does NOT determine whether the pattern
represents a threat. That decision belongs to the detection engine.
"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class CorrelationResult(BaseModel):
    """A group of related security events identified by the correlation engine."""

    correlation_id: str
    correlation_type: str          # e.g. "source_ip", "user_activity", "network_scan", "auth_sequence"
    start_time: datetime
    end_time: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_count: int
    event_ids: List[str]
    event_types: List[str]
    events: List[dict]             # Full event rows, ordered by timestamp
    reason: str                    # Human-readable explanation of why these events are related
