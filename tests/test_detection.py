"""
Tests for Phase 5 - Rule-Based Threat Detection Engine.
"""

import pytest
import os
import uuid
from datetime import datetime
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.manager import DatabaseManager
from backend.config import settings
from backend.parser.models import NormalizedEvent
from backend.correlation.models import CorrelationResult
from backend.detection.models import DetectionResult, Severity
from backend.detection.engine import DetectionEngine


def _unique_db():
    return f"test_det_{uuid.uuid4().hex[:8]}.db"

def _setup_db(db_name):
    settings.sqlite_db_path = f"sqlite:///{db_name}"
    db = DatabaseManager()
    db.initialize_database()
    return db

def _cleanup_db(db_name):
    try:
        if os.path.exists(db_name):
            os.remove(db_name)
    except PermissionError:
        pass

def _make_event(**overrides) -> NormalizedEvent:
    defaults = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime(2026, 9, 18, 10, 15, 0),
        "source_ip": "192.168.1.10",
        "event_type": "authentication",
        "action": "login",
        "status": "failed",
        "message": "Test event"
    }
    defaults.update(overrides)
    return NormalizedEvent(**defaults)

def _make_correlation(correlation_type: str, events: list, **overrides) -> CorrelationResult:
    defaults = {
        "correlation_id": str(uuid.uuid4()),
        "correlation_type": correlation_type,
        "start_time": events[0].timestamp if events else datetime.utcnow(),
        "end_time": events[-1].timestamp if events else datetime.utcnow(),
        "source_ip": str(events[0].source_ip) if events and events[0].source_ip else None,
        "username": events[0].username if events else None,
        "event_count": len(events),
        "event_ids": [e.event_id for e in events],
        "event_types": list(set(e.event_type for e in events)),
        "events": [e.model_dump(mode="json") for e in events],
        "reason": "Test correlation"
    }
    defaults.update(overrides)
    return CorrelationResult(**defaults)

# ------------------------------------------------------------------ #
# TEST 1 - Brute Force Detection
# ------------------------------------------------------------------ #
def test_brute_force_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        events = [
            _make_event(status="failed"),
            _make_event(status="failed"),
            _make_event(status="failed"),
            _make_event(status="failed"),
            _make_event(status="failed")
        ]
        corr = _make_correlation("source_ip", events)
        
        engine = DetectionEngine(db)
        results = engine.run_detection([], [corr])
        
        assert len(results) == 1
        assert results[0].detection_type == "BRUTE_FORCE"
        assert results[0].severity == Severity.HIGH
        assert results[0].evidence["failed_attempts"] == 5
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 2 - Port Scan Detection
# ------------------------------------------------------------------ #
def test_port_scan_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        events = [
            _make_event(event_type="network", destination_port=21),
            _make_event(event_type="network", destination_port=22),
            _make_event(event_type="network", destination_port=80),
            _make_event(event_type="network", destination_port=443),
            _make_event(event_type="network", destination_port=8080)
        ]
        corr = _make_correlation("network_events", events)
        
        engine = DetectionEngine(db)
        results = engine.run_detection([], [corr])
        
        assert len(results) == 1
        assert results[0].detection_type == "PORT_SCAN"
        assert results[0].severity == Severity.MEDIUM
        assert results[0].evidence["unique_ports"] == 5
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 3 - Suspicious Login Detection
# ------------------------------------------------------------------ #
def test_suspicious_login_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        events = [
            _make_event(status="failed"),
            _make_event(status="failed"),
            _make_event(status="failed"),
            _make_event(status="success")
        ]
        corr = _make_correlation("auth_sequence", events)
        
        engine = DetectionEngine(db)
        results = engine.run_detection([], [corr])
        
        # It shouldn't trigger brute force (only 3 failures), but should trigger suspicious login
        assert len(results) == 1
        assert results[0].detection_type == "SUSPICIOUS_LOGIN"
        assert results[0].severity == Severity.HIGH
        assert results[0].evidence["failed_attempts_before_success"] == 3
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 4 - Privilege Escalation Detection
# ------------------------------------------------------------------ #
def test_privilege_escalation_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        event = _make_event(event_type="system", action="privilege_escalation", message="User ran sudo su")
        
        engine = DetectionEngine(db)
        # Evaluate as a single event
        results = engine.run_detection([event], [])
        
        assert len(results) == 1
        assert results[0].detection_type == "PRIVILEGE_ESCALATION"
        assert results[0].severity == Severity.CRITICAL
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 5 - Suspicious Process Detection
# ------------------------------------------------------------------ #
def test_suspicious_process_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        event = _make_event(event_type="system", message="Executed cat /etc/shadow directly")
        
        engine = DetectionEngine(db)
        results = engine.run_detection([event], [])
        
        assert len(results) == 1
        assert results[0].detection_type == "SUSPICIOUS_PROCESS"
        assert results[0].severity == Severity.HIGH
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 6 - Normal Activity (No False Positives)
# ------------------------------------------------------------------ #
def test_normal_activity_no_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        events = [
            _make_event(status="success"),  # just one successful login
            _make_event(event_type="network", destination_port=443),
            _make_event(event_type="network", destination_port=443)  # repeated normal port
        ]
        corr = _make_correlation("source_ip", events)
        
        engine = DetectionEngine(db)
        results = engine.run_detection(events, [corr])
        
        assert len(results) == 0
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 7 - API Endpoints
# ------------------------------------------------------------------ #
def test_detection_api_endpoints():
    db_name = _unique_db()
    settings.sqlite_db_path = f"sqlite:///{db_name}"
    
    from backend.main import app, db_manager as main_db
    main_db.db_path = db_name
    main_db.initialize_database()

    try:
        with TestClient(app) as client:
            # First, ingest sample data so correlation/detection has something to look at
            res = client.post("/api/logs/collect")
            assert res.status_code == 200
            
            # Now run detection
            res_det = client.post("/api/detection/run")
            assert res_det.status_code == 200
            data = res_det.json()
            assert data["status"] == "success"
            assert data["detections_found"] > 0
            
            # Verify we can fetch them via GET
            res_get = client.get("/api/detections")
            assert res_get.status_code == 200
            get_data = res_get.json()
            assert get_data["count"] == data["detections_found"]
            
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 8 - Lateral Movement Detection (explicit credential logons)
# ------------------------------------------------------------------ #
def test_lateral_movement_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        events = [
            _make_event(event_type="authentication", action="login", status="success",
                        message="Windows Logon (4648) on host SRV01 for user 'admin' using explicit credentials"),
            _make_event(event_type="authentication", action="login", status="success",
                        message="Windows Logon (4648) on host SRV02 for user 'admin' using explicit credentials"),
            _make_event(event_type="authentication", action="login", status="success",
                        message="Windows Logon (4648) on host SRV03 for user 'admin' using explicit credentials"),
        ]
        corr = _make_correlation("auth_sequence", events, username="admin")

        engine = DetectionEngine(db)
        results = engine.run_detection([], [corr])

        lateral = [r for r in results if r.detection_type == "LATERAL_MOVEMENT"]
        assert len(lateral) == 1
        assert lateral[0].severity == Severity.HIGH
        assert lateral[0].evidence["explicit_cred_events"] == 3
    finally:
        _cleanup_db(db_name)

# ------------------------------------------------------------------ #
# TEST 9 - Suspicious Service Installation Detection
# ------------------------------------------------------------------ #
def test_suspicious_service_install_detection():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        event = _make_event(
            event_type="system",
            action="privilege_escalation",
            message="admin granted: New Windows service installed 'psexesvc' on host DC01 from \\temp\\payload.exe"
        )

        engine = DetectionEngine(db)
        results = engine.run_detection([event], [])

        svc = [r for r in results if r.detection_type == "SUSPICIOUS_SERVICE_INSTALL"]
        assert len(svc) == 1
        assert svc[0].severity == Severity.CRITICAL
        assert "psexesvc" in svc[0].evidence["service_message"]
    finally:
        _cleanup_db(db_name)
