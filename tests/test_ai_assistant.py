import os
import uuid
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from backend.config import settings
from backend.detection.models import DetectionResult, Severity
from backend.incidents.models import Incident, IncidentStatus, IncidentSeverity


def test_ai_analysis_endpoint():
    db_name = f"test_ai_{uuid.uuid4().hex[:8]}.db"
    settings.sqlite_db_path = f"sqlite:///{db_name}"

    from backend.main import app, db_manager
    db_manager.db_path = db_name
    db_manager.initialize_database()

    try:
        # Create detection and incident
        det = DetectionResult(
            detection_id="det-ai-1",
            rule_id="RULE_PRIVILEGE_ESCALATION_01",
            detection_type="PRIVILEGE_ESCALATION",
            severity=Severity.CRITICAL,
            timestamp=datetime.now(),
            source_ip="192.168.1.185",
            username="sec_admin",
            description="Special privileges assigned / admin granted",
            evidence={"event": "4672"},
            related_event_ids=[]
        )
        db_manager.save_detection(det)

        inc_id = str(uuid.uuid4())
        inc = Incident(
            incident_id=inc_id,
            title="Privilege Escalation on 192.168.1.185",
            severity=IncidentSeverity.CRITICAL,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            source_ip="192.168.1.185",
            username="sec_admin",
            detection_ids=["det-ai-1"]
        )
        db_manager.save_incident(inc)

        with TestClient(app) as client:
            resp = client.post(f"/api/incidents/{inc_id}/ai-analysis")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            analysis = data["analysis"]
            assert analysis["incident_id"] == inc_id
            assert len(analysis["mitre_attack"]) > 0
            assert any(m["technique_id"] == "T1068" for m in analysis["mitre_attack"])
            assert len(analysis["remediation_steps"]) > 0
            assert "Investigation Report" in analysis["full_report_markdown"]

            # Verify incident in DB was updated with the AI summary
            inc_db = db_manager.get_incident(inc_id)
            assert inc_db["summary"] is not None
            assert len(inc_db["remediation_notes"]) > 0

    finally:
        try:
            if os.path.exists(db_name):
                os.remove(db_name)
        except PermissionError:
            pass
