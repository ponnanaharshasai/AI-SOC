from fastapi import FastAPI, HTTPException, Query
from contextlib import asynccontextmanager
from backend.config import settings
from backend.collectors.sample import SampleLogCollector
from backend.parser.parser import LogParser
from backend.parser.models import NormalizedEvent
from backend.database.manager import DatabaseManager
from backend.correlation.engine import CorrelationEngine
from backend.detection.engine import DetectionEngine
from backend.incidents.models import IncidentUpdate
from backend.incidents.engine import IncidentEngine
from backend.ai.assistant import AIAssistant
import os
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)

db_manager = DatabaseManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager.initialize_database()
    yield

app = FastAPI(
    title=settings.project_name,
    description="Lightweight AI-SOC Backend API (Deterministic Detection + Single AI Analyst)",
    version="0.1.0",
    lifespan=lifespan
)

@app.get("/")
def read_root():
    return {
        "status": "active",
        "project": settings.project_name,
        "message": "Welcome to the AI-SOC API."
    }

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/api/logs/sample")
def get_sample_logs(filename: str = "events.jsonl"):
    '''Trigger collection from the sample log source and return raw events.'''
    sample_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_logs", filename))
    collector = SampleLogCollector(file_path=sample_file_path)
    events = collector.collect()
    return {
        "status": "success",
        "collected_count": len(events),
        "events": events
    }

@app.post("/api/logs/collect")
def process_sample_logs(filename: str = "events.jsonl"):
    sample_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_logs", filename))
    collector = SampleLogCollector(file_path=sample_file_path)
    raw_events = collector.collect()

    parser = LogParser()
    processed = 0
    stored = 0
    failed = 0

    for raw in raw_events:
        processed += 1
        normalized = parser.parse(raw)
        if normalized:
            if db_manager.save_event(normalized):
                stored += 1
            else:
                failed += 1
        else:
            failed += 1

    return {
        "status": "success",
        "collected": len(raw_events),
        "processed": processed,
        "stored": stored,
        "failed": failed
    }

@app.get("/api/events")
def get_events(limit: int = 100):
    events = db_manager.get_recent_events(limit=limit)
    return {"status": "success", "count": len(events), "events": events}

@app.get("/api/correlation")
def run_correlation(
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    window: Optional[int] = Query(None, description="Correlation time window in seconds"),
):
    '''Run the correlation engine and return grouped event relationships.'''
    engine = CorrelationEngine(db_manager)
    results = engine.correlate_all(
        source_ip=source_ip,
        username=username,
        window_seconds=window,
    )
    return {
        "status": "success",
        "correlation_window_seconds": window or settings.correlation_window_seconds,
        "correlations_found": len(results),
        "results": [r.model_dump(mode="json") for r in results],
    }

@app.post("/api/detection/run")
def run_detection(window: Optional[int] = Query(None, description="Correlation time window in seconds")):
    """Run detection engine against all recent correlated events and raw events."""
    raw_dicts = db_manager.get_recent_events(limit=1000)
    
    events = []
    for d in raw_dicts:
        try:
            events.append(NormalizedEvent(**d))
        except Exception:
            pass

    corr_engine = CorrelationEngine(db_manager)
    correlations = corr_engine.correlate_all(window_seconds=window)

    det_engine = DetectionEngine(db_manager)
    results = det_engine.run_detection(events, correlations)

    return {
        "status": "success",
        "events_analyzed": len(events),
        "correlations_analyzed": len(correlations),
        "detections_found": len(results),
        "results": [r.model_dump(mode="json") for r in results]
    }

@app.get("/api/detections")
def get_detections(limit: int = 100):
    """Retrieve saved detection results."""
    results = db_manager.get_recent_detections(limit=limit)
    return {
        "status": "success",
        "count": len(results),
        "results": results
    }

# --- Phase 6: Incident Management Endpoints ---

@app.post("/api/incidents/generate")
def generate_incidents():
    """Aggregate unassigned detections into new Security Incidents."""
    engine = IncidentEngine(db_manager)
    created = engine.generate_incidents_from_detections()
    return {
        "status": "success",
        "incidents_created": len(created),
        "incidents": [inc.model_dump(mode="json") for inc in created]
    }

@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status (NEW, INVESTIGATING, CONTAINED, CLOSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(100, ge=1, le=500)
):
    """List all incidents with optional filtering."""
    incidents = db_manager.get_incidents(status=status, severity=severity, limit=limit)
    return {
        "status": "success",
        "count": len(incidents),
        "incidents": incidents
    }

@app.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: str):
    """Retrieve an incident with its associated detections and raw event timeline."""
    incident = db_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    detection_ids = incident.get("detection_ids", [])
    detections = db_manager.get_detections_by_ids(detection_ids)

    all_event_ids = []
    for d in detections:
        all_event_ids.extend(d.get("related_event_ids", []))
    unique_event_ids = list(dict.fromkeys(all_event_ids))
    events = db_manager.get_events_by_ids(unique_event_ids)

    return {
        "status": "success",
        "incident": incident,
        "detections": detections,
        "events": events
    }

@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, updates: IncidentUpdate):
    """Update incident status, assigned analyst, or analyst notes."""
    update_dict = updates.model_dump(exclude_unset=True)
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    existing = db_manager.get_incident(incident_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Incident not found")

    success = db_manager.update_incident(incident_id, update_dict)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update incident")

    updated = db_manager.get_incident(incident_id)
    return {
        "status": "success",
        "incident": updated
    }

# --- Phase 7: AI-Assisted Security Analyst Endpoints ---

@app.post("/api/incidents/{incident_id}/ai-analysis")
def analyze_incident_with_ai(incident_id: str):
    """Generate an AI-assisted analysis report, MITRE ATT&CK mapping, and remediation steps."""
    assistant = AIAssistant(db_manager)
    try:
        analysis = assistant.analyze_incident(incident_id)
        return {
            "status": "success",
            "analysis": analysis.model_dump(mode="json")
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")