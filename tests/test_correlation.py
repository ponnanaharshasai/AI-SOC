"""
Tests for the Event Correlation Engine (Phase 4).
"""

import pytest
import os
import uuid
import sqlite3
from datetime import datetime
from fastapi.testclient import TestClient
from backend.database.manager import DatabaseManager
from backend.parser.models import NormalizedEvent
from backend.correlation.engine import CorrelationEngine
from backend.config import settings


def _unique_db():
    name = f"test_corr_{uuid.uuid4().hex[:8]}.db"
    return name


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
        "message": "Test event",
    }
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def _insert(db, event: NormalizedEvent):
    assert db.save_event(event), f"Failed to insert event {event.event_id}"


# ------------------------------------------------------------------ #
# TEST 1 - Same source IP correlation
# ------------------------------------------------------------------ #
def test_same_ip_correlation():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 15, 0)))
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 15, 5)))
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 15, 10)))

        engine = CorrelationEngine(db)
        results = engine.correlate_by_source_ip()
        assert len(results) >= 1
        r = results[0]
        assert r.source_ip == "192.168.1.10"
        assert r.event_count == 3
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 2 - Same username + IP correlation
# ------------------------------------------------------------------ #
def test_user_activity_correlation():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(username="admin", timestamp=datetime(2026, 9, 18, 10, 15, 0)))
        _insert(db, _make_event(username="admin", timestamp=datetime(2026, 9, 18, 10, 15, 5)))
        _insert(db, _make_event(username="other", source_ip="10.0.0.99", timestamp=datetime(2026, 9, 18, 10, 15, 5)))

        engine = CorrelationEngine(db)
        results = engine.correlate_by_user_activity()
        admin_results = [r for r in results if r.username == "admin"]
        assert len(admin_results) == 1
        assert admin_results[0].event_count == 2
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 3 - Time window respects boundary
# ------------------------------------------------------------------ #
def test_time_window_boundary():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 0, 0)))
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 10, 0)))

        engine = CorrelationEngine(db)
        results = engine.correlate_by_source_ip(window_seconds=300)
        assert len(results) == 0
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 4 - Multiple network events (port grouping)
# ------------------------------------------------------------------ #
def test_network_port_correlation():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        ports = [21, 22, 23, 25, 80, 443]
        for i, port in enumerate(ports):
            _insert(db, _make_event(
                source_ip="192.168.1.50",
                destination_ip="10.0.0.100",
                destination_port=port,
                source_port=40000 + i,
                event_type="network",
                action="connection",
                status="success",
                timestamp=datetime(2026, 9, 18, 10, 20, i * 2),
            ))

        engine = CorrelationEngine(db)
        results = engine.correlate_network_events()
        assert len(results) == 1
        assert results[0].source_ip == "192.168.1.50"
        assert results[0].event_count == 6
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 5 - Ordered authentication sequence
# ------------------------------------------------------------------ #
def test_auth_sequence_correlation():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(username="admin", status="failed", timestamp=datetime(2026, 9, 18, 10, 15, 0)))
        _insert(db, _make_event(username="admin", status="failed", timestamp=datetime(2026, 9, 18, 10, 15, 3)))
        _insert(db, _make_event(username="admin", status="success", timestamp=datetime(2026, 9, 18, 10, 15, 10)))
        _insert(db, _make_event(
            username="admin", event_type="system", action="privilege_escalation",
            status="success", timestamp=datetime(2026, 9, 18, 10, 15, 20),
        ))
        _insert(db, _make_event(
            username="admin", event_type="system", action="process_execution",
            status="success", timestamp=datetime(2026, 9, 18, 10, 15, 30),
        ))

        engine = CorrelationEngine(db)
        results = engine.correlate_auth_sequences()
        assert len(results) >= 1
        seq = results[0]
        assert seq.correlation_type == "auth_sequence"
        timestamps = [e["timestamp"] for e in seq.events]
        assert timestamps == sorted(timestamps)
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 6 - Different IPs are NOT grouped together
# ------------------------------------------------------------------ #
def test_different_ips_not_grouped():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(source_ip="10.0.0.1", timestamp=datetime(2026, 9, 18, 10, 15, 0)))
        _insert(db, _make_event(source_ip="10.0.0.2", timestamp=datetime(2026, 9, 18, 10, 15, 1)))
        _insert(db, _make_event(source_ip="10.0.0.3", timestamp=datetime(2026, 9, 18, 10, 15, 2)))

        engine = CorrelationEngine(db)
        results = engine.correlate_by_source_ip()
        assert len(results) == 0
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 7 - Events outside correlation window
# ------------------------------------------------------------------ #
def test_events_outside_window():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 10, 0, 0)))
        _insert(db, _make_event(timestamp=datetime(2026, 9, 18, 11, 0, 0)))

        engine = CorrelationEngine(db)
        results = engine.correlate_by_source_ip(window_seconds=300)
        assert len(results) == 0
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 8 - Empty database
# ------------------------------------------------------------------ #
def test_empty_database():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        engine = CorrelationEngine(db)
        results = engine.correlate_all()
        assert results == []
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 9 - Missing optional fields
# ------------------------------------------------------------------ #
def test_missing_optional_fields():
    db_name = _unique_db()
    db = _setup_db(db_name)
    try:
        _insert(db, _make_event(
            username=None, destination_ip=None, source_port=None, destination_port=None,
            timestamp=datetime(2026, 9, 18, 10, 15, 0),
        ))
        _insert(db, _make_event(
            username=None, destination_ip=None, source_port=None, destination_port=None,
            timestamp=datetime(2026, 9, 18, 10, 15, 5),
        ))

        engine = CorrelationEngine(db)
        ip_results = engine.correlate_by_source_ip()
        assert len(ip_results) >= 1

        user_results = engine.correlate_by_user_activity()
        assert len(user_results) == 0
    finally:
        _cleanup_db(db_name)


# ------------------------------------------------------------------ #
# TEST 10 - API endpoint response
# ------------------------------------------------------------------ #
def test_correlation_api_endpoint():
    db_name = _unique_db()
    settings.sqlite_db_path = f"sqlite:///{db_name}"

    from backend.main import app, db_manager as main_db
    # Re-point the app-level db_manager to our test DB
    main_db.db_path = db_name
    main_db.initialize_database()

    try:
        _insert(main_db, _make_event(username="admin", timestamp=datetime(2026, 9, 18, 10, 15, 0)))
        _insert(main_db, _make_event(username="admin", timestamp=datetime(2026, 9, 18, 10, 15, 5)))

        with TestClient(app) as client:
            response = client.get("/api/correlation")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert "correlations_found" in data
            assert "results" in data
            assert data["correlations_found"] >= 1
    finally:
        _cleanup_db(db_name)