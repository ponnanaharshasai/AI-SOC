import pytest
import os
import uuid
from fastapi.testclient import TestClient
from backend.config import settings


def test_pipeline_collect_and_store():
    db_name = f"test_pipeline_{uuid.uuid4().hex[:8]}.db"
    settings.sqlite_db_path = f"sqlite:///{db_name}"

    from backend.main import app, db_manager
    db_manager.db_path = db_name
    db_manager.initialize_database()

    try:
        with TestClient(app) as client:
            response = client.post("/api/logs/collect")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["collected"] > 0
            assert data["stored"] > 0

            # Verify DB count matches what was stored in this run
            get_resp = client.get("/api/events")
            assert get_resp.status_code == 200
            events_data = get_resp.json()
            assert events_data["count"] == data["stored"]
    finally:
        try:
            if os.path.exists(db_name):
                os.remove(db_name)
        except PermissionError:
            pass