import os
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.config import settings
from backend.main import app, db_manager


def test_botsv1_scenario_pipeline():
    """Test ingestion, correlation, and detection on the real BOTS v1 scenario."""
    db_name = f"test_botsv1_{uuid.uuid4().hex[:8]}.db"
    settings.sqlite_db_path = f"sqlite:///{db_name}"
    db_manager.db_path = db_name
    db_manager.initialize_database()

    try:
        with TestClient(app) as client:
            # 1. Ingest BOTS v1 scenario
            response = client.post("/api/logs/collect?filename=botsv1_attack_scenario.jsonl")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["collected"] > 0
            assert data["stored"] == data["collected"]
            assert data["failed"] == 0

            # 2. Verify events stored in DB
            events_resp = client.get("/api/events?limit=2000")
            assert events_resp.status_code == 200
            assert events_resp.json()["count"] == data["stored"]

            # 3. Run correlation
            corr_resp = client.get("/api/correlation?window=600")
            assert corr_resp.status_code == 200
            corr_data = corr_resp.json()
            assert corr_data["status"] == "success"
            assert corr_data["correlations_found"] > 0

            # 4. Run detection engine
            det_resp = client.post("/api/detection/run?window=600")
            assert det_resp.status_code == 200
            det_data = det_resp.json()
            assert det_data["status"] == "success"
            assert det_data["detections_found"] > 0

            # Verify key threat detections triggered
            detected_types = {d["detection_type"] for d in det_data["results"]}
            assert "BRUTE_FORCE" in detected_types
            assert "SUSPICIOUS_LOGIN" in detected_types
            assert "PRIVILEGE_ESCALATION" in detected_types
            assert "SUSPICIOUS_PROCESS" in detected_types
    finally:
        try:
            if os.path.exists(db_name):
                os.remove(db_name)
        except PermissionError:
            pass
