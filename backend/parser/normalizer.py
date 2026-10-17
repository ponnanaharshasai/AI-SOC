import uuid
from typing import Dict, Any

def normalize_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    norm = raw_event.copy()
    
    if "event_id" not in norm:
        norm["event_id"] = str(uuid.uuid4())
        
    if "status" in norm and isinstance(norm["status"], str):
        norm["status"] = norm["status"].lower()
        
    if "event_type" in norm and isinstance(norm["event_type"], str):
        norm["event_type"] = norm["event_type"].lower()

    if "action" in norm and isinstance(norm["action"], str):
        norm["action"] = norm["action"].lower()
        
    for port_field in ["source_port", "destination_port"]:
        if port_field in norm and norm[port_field] is not None:
            try:
                norm[port_field] = int(norm[port_field])
            except ValueError:
                norm[port_field] = None
                
    return norm
