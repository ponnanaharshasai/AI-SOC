import os
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.config import settings
from backend.main import app, db_manager


def test_autonomous_soc_cycle():
    """Test the complete end-to-end Autonomous AI-SOC cycle including SOAR containment."""
    db_name = f"test_auto_{uuid.uuid4().hex[:8]}.db"
    settings.sqlite_db_path = f"sqlite:///{db_name}"
    db_manager.db_path = db_name
    db_manager.initialize_database()

    try:
        with TestClient(app) as client:
            # 1. Run full autonomous cycle
            resp = client.post("/api/autonomous/run?ingest_sample=true&filename=botsv1_attack_scenario.jsonl")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            summary = data["summary"]
            assert summary["events_processed"] > 0
            assert summary["detections_triggered"] > 0
            assert summary["incidents_created"] > 0
            assert summary["ai_investigations_completed"] > 0
            assert summary["containment_actions_executed"] > 0
            assert summary["overall_threat_level"] in ["CRITICAL", "HIGH", "ELEVATED"]

            # 2. Check Autonomous Status endpoint
            status_resp = client.get("/api/autonomous/status")
            assert status_resp.status_code == 200
            status_data = status_resp.json()["details"]
            assert status_data["active_containments"] > 0
            assert status_data["contained_incidents"] > 0

            # 3. Check SOAR containment actions
            soar_resp = client.get("/api/soar/actions?status=ACTIVE")
            assert soar_resp.status_code == 200
            actions = soar_resp.json()["actions"]
            assert len(actions) > 0
            first_action = actions[0]
            action_id = first_action["action_id"]

            # 4. Test Rollback of SOAR action
            rollback_resp = client.post(f"/api/soar/actions/{action_id}/rollback")
            assert rollback_resp.status_code == 200
            assert rollback_resp.json()["status"] == "success"

            # 5. Test Master Report Generation
            report_resp = client.get("/api/reports/master")
            assert report_resp.status_code == 200
            report_data = report_resp.json()
            assert "AI-SOC Master Security & Incident Audit Report" in report_data["report_markdown"]
            assert "Active SOAR Containment Actions" in report_data["report_markdown"]
    finally:
        import gc
        gc.collect()
        try:
            if os.path.exists(db_name):
                os.remove(db_name)
        except PermissionError:
            pass
