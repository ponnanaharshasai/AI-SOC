import os
import uuid
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from backend.config import settings
from backend.detection.models import DetectionResult, Severity
from backend.incidents.models import IncidentStatus, IncidentSeverity


def test_incident_lifecycle():
    db_name = f"test_incidents_{uuid.uuid4().hex[:8]}.db"
    settings.sqlite_db_path = f"sqlite:///{db_name}"

    from backend.main import app, db_manager
    db_manager.db_path = db_name
    db_manager.initialize_database()

    try:
        # 1. Populate sample detections
        det1 = DetectionResult(
            detection_id="det-1",
            rule_id="RULE_BRUTE_FORCE_01",
            detection_type="BRUTE_FORCE",
            severity=Severity.HIGH,
            timestamp=datetime.now(),
            source_ip="192.168.1.185",
            username="sec_admin",
            description="5 failed logins",
            evidence={"failed_count": 5},
            related_event_ids=["ev-1", "ev-2"]
        )
        det2 = DetectionResult(
            detection_id="det-2",
            rule_id="RULE_SUSPICIOUS_LOGIN_01",
            detection_type="SUSPICIOUS_LOGIN",
            severity=Severity.HIGH,
            timestamp=datetime.now(),
            source_ip="192.168.1.185",
            username="sec_admin",
            description="Success after failures",
            evidence={},
            related_event_ids=["ev-3"]
        )
        db_manager.save_detection(det1)
        db_manager.save_detection(det2)

        with TestClient(app) as client:
            # 2. Generate incidents
            gen_resp = client.post("/api/incidents/generate")
            assert gen_resp.status_code == 200
            gen_data = gen_resp.json()
            assert gen_data["status"] == "success"
            assert gen_data["incidents_created"] == 1
            inc_id = gen_data["incidents"][0]["incident_id"]

            # 3. List incidents
            list_resp = client.get("/api/incidents")
            assert list_resp.status_code == 200
            assert list_resp.json()["count"] == 1

            # 4. Get incident details
            detail_resp = client.get(f"/api/incidents/{inc_id}")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            assert detail["incident"]["incident_id"] == inc_id
            assert len(detail["detections"]) == 2

            # 5. Update incident status and analyst notes
            patch_resp = client.patch(f"/api/incidents/{inc_id}", json={
                "status": "INVESTIGATING",
                "assigned_to": "tier2_analyst",
                "remediation_notes": "Currently analyzing host artifacts."
            })
            assert patch_resp.status_code == 200
            updated = patch_resp.json()["incident"]
            assert updated["status"] == "INVESTIGATING"
            assert updated["assigned_to"] == "tier2_analyst"
            assert "analyzing host" in updated["remediation_notes"]

    finally:
        try:
            if os.path.exists(db_name):
                os.remove(db_name)
        except PermissionError:
            pass
