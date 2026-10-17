import os
import tempfile
from backend.collectors.sample import SampleLogCollector

def test_valid_log_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('{"event": "test1"}\n{"event": "test2"}\n')
        temp_path = f.name
    
    try:
        collector = SampleLogCollector(temp_path)
        events = collector.collect()
        assert len(events) == 2
        assert events[0]["event"] == "test1"
    finally:
        os.remove(temp_path)

def test_empty_log_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        temp_path = f.name
    
    try:
        collector = SampleLogCollector(temp_path)
        events = collector.collect()
        assert len(events) == 0
    finally:
        os.remove(temp_path)

def test_missing_file():
    collector = SampleLogCollector("non_existent_file.jsonl")
    events = collector.collect()
    assert len(events) == 0

def test_malformed_json_record():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('{"event": "valid"}\n{"invalid_json": }\n{"event": "valid2"}\n')
        temp_path = f.name
        
    try:
        collector = SampleLogCollector(temp_path)
        events = collector.collect()
        assert len(events) == 2
        assert events[0]["event"] == "valid"
        assert events[1]["event"] == "valid2"
    finally:
        os.remove(temp_path)
