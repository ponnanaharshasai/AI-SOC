import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from collections import defaultdict
if TYPE_CHECKING:
    from backend.database.manager import DatabaseManager
from backend.incidents.models import Incident, IncidentStatus, IncidentSeverity

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

class IncidentEngine:
    def __init__(self, db_manager: "DatabaseManager"):
        self.db = db_manager

    def generate_incidents_from_detections(self, detections: Optional[List[Dict[str, Any]]] = None) -> List[Incident]:
        """Group related detections into cohesive Incident tickets."""
        if detections is None:
            detections = self.db.get_recent_detections(limit=500)

        if not detections:
            return []

        # Find all detections already attached to existing incidents
        existing_incidents = self.db.get_incidents(limit=200)
        assigned_detection_ids = set()
        for inc in existing_incidents:
            for det_id in inc.get("detection_ids", []):
                assigned_detection_ids.add(det_id)

        # Filter for unassigned detections
        unassigned_detections = [
            d for d in detections if d["detection_id"] not in assigned_detection_ids
        ]

        if not unassigned_detections:
            return []

        # Group detections by primary entity (source_ip or username)
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for det in unassigned_detections:
            key = det.get("source_ip") or det.get("username") or "UNKNOWN_ENTITY"
            groups[key].append(det)

        created_incidents: List[Incident] = []

        for entity_key, group in groups.items():
            detection_ids = [d["detection_id"] for d in group]
            detection_types = list(dict.fromkeys(d.get("detection_type", "SECURITY_ALERT") for d in group))
            
            # Determine max severity
            max_sev_val = 1
            max_sev_name = "LOW"
            for d in group:
                sev_str = d.get("severity", "LOW").upper()
                val = SEVERITY_ORDER.get(sev_str, 1)
                if val > max_sev_val:
                    max_sev_val = val
                    max_sev_name = sev_str

            severity = IncidentSeverity(max_sev_name)

            # Determine title & summary
            source_ip = group[0].get("source_ip")
            username = next((d.get("username") for d in group if d.get("username")), None)

            if len(detection_types) > 1:
                types_str = " -> ".join(detection_types)
                title = f"Multi-Stage Attack: {types_str}"
                if source_ip:
                    title += f" from {source_ip}"
                if username:
                    title += f" ({username})"
            else:
                type_name = detection_types[0] if detection_types else "Suspicious Activity"
                title = f"{type_name} Incident"
                if source_ip:
                    title += f" from {source_ip}"
                if username:
                    title += f" targeting {username}"

            summary = f"Detected {len(group)} related security events for entity {entity_key}. Involves: {', '.join(detection_types)}."

            incident = Incident(
                incident_id=str(uuid.uuid4()),
                title=title,
                severity=severity,
                status=IncidentStatus.NEW,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                source_ip=source_ip,
                username=username,
                summary=summary,
                detection_ids=detection_ids
            )

            if self.db.save_incident(incident):
                created_incidents.append(incident)

        return created_incidents
