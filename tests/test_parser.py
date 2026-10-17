import pytest
from backend.parser.normalizer import normalize_raw_event
from backend.parser.parser import LogParser

def test_timestamp_normalization():
    raw = {"timestamp": "2026-09-18T10:15:32", "source_ip": "10.0.0.1"}
    parser = LogParser()
    parsed = parser.parse(raw)
    assert parsed is not None
    assert parsed.timestamp.isoformat() == "2026-09-18T10:15:32"

def test_ip_validation():
    parser = LogParser()
    
    valid_raw = {"timestamp": "2026-09-18T10:15:32", "source_ip": "192.168.1.10"}
    parsed = parser.parse(valid_raw)
    assert parsed is not None
    assert str(parsed.source_ip) == "192.168.1.10"
    
    invalid_raw = {"timestamp": "2026-09-18T10:15:32", "source_ip": "not-an-ip"}
    parsed = parser.parse(invalid_raw)
    assert parsed is None

def test_port_validation():
    parser = LogParser()
    raw = {"timestamp": "2026-09-18T10:15:32", "source_port": "80", "destination_port": 99999}
    parsed = parser.parse(raw)
    assert parsed is None # 99999 is invalid

def test_normalization_logic():
    raw = {"timestamp": "2026-09-18T10:15:32", "status": "FAILED", "event_type": "AUTH", "source_port": "443"}
    norm = normalize_raw_event(raw)
    assert norm["status"] == "failed"
    assert norm["event_type"] == "auth"
    assert norm["source_port"] == 443
    assert "event_id" in norm
