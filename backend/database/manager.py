import json
import sqlite3
import logging
from contextlib import closing
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.parser.models import NormalizedEvent
from backend.detection.models import DetectionResult
from backend.incidents.models import Incident
from backend.config import settings

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = db_path.replace("sqlite:///", "")
        else:
            self.db_path = settings.sqlite_db_path.replace("sqlite:///", "")

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_database(self):
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS normalized_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        source TEXT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        source_port INTEGER,
                        destination_port INTEGER,
                        username TEXT,
                        event_type TEXT,
                        action TEXT,
                        status TEXT,
                        severity TEXT,
                        message TEXT
                    )
                ''')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON normalized_events(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON normalized_events(source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON normalized_events(event_type)')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS detections (
                        detection_id TEXT PRIMARY KEY,
                        rule_id TEXT NOT NULL,
                        detection_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT,
                        username TEXT,
                        description TEXT,
                        evidence TEXT,
                        related_event_ids TEXT,
                        dedup_signature TEXT
                    )
                ''')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_det_timestamp ON detections(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_det_severity ON detections(severity)')
                cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_det_dedup ON detections(dedup_signature)')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        source_ip TEXT,
                        username TEXT,
                        assigned_to TEXT,
                        summary TEXT,
                        remediation_notes TEXT,
                        detection_ids TEXT NOT NULL
                    )
                ''')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_inc_created_at ON incidents(created_at)')
                conn.commit()
                logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    def save_event(self, event: NormalizedEvent) -> bool:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO normalized_events (
                        event_id, timestamp, source, source_ip, destination_ip, 
                        source_port, destination_port, username, event_type, 
                        action, status, severity, message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.source,
                    str(event.source_ip) if event.source_ip else None,
                    str(event.destination_ip) if event.destination_ip else None,
                    event.source_port,
                    event.destination_port,
                    event.username,
                    event.event_type,
                    event.action,
                    event.status,
                    event.severity,
                    event.message
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logger.error(f"Failed to save event {event.event_id}: {e}")
            return False

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to retrieve events: {e}")
            return []

    def get_events_by_ids(self, event_ids: List[str]) -> List[Dict[str, Any]]:
        if not event_ids:
            return []
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                placeholders = ",".join("?" for _ in event_ids)
                cursor.execute(f'SELECT * FROM normalized_events WHERE event_id IN ({placeholders}) ORDER BY timestamp ASC', event_ids)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to retrieve events by IDs: {e}")
            return []

    def save_detection(self, detection: DetectionResult) -> bool:
        """Save detection with deduplication signature to prevent duplicates on repeated runs."""
        dedup_sig = f"{detection.rule_id}:{','.join(sorted(detection.related_event_ids))}"
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                # Check if a detection with this signature already exists
                cursor.execute('SELECT detection_id FROM detections WHERE dedup_signature = ?', (dedup_sig,))
                if cursor.fetchone():
                    logger.debug(f"Detection already exists for signature: {dedup_sig}")
                    return False
                cursor.execute('''
                    INSERT INTO detections (
                        detection_id, rule_id, detection_type, severity, timestamp,
                        source_ip, username, description, evidence, related_event_ids,
                        dedup_signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    detection.detection_id,
                    detection.rule_id,
                    detection.detection_type,
                    detection.severity.value,
                    detection.timestamp.isoformat(),
                    detection.source_ip,
                    detection.username,
                    detection.description,
                    json.dumps(detection.evidence),
                    json.dumps(detection.related_event_ids),
                    dedup_sig
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logger.error(f"Failed to save detection {detection.detection_id}: {e}")
            return False

    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?', (limit,))
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    if d.get("evidence"):
                        d["evidence"] = json.loads(d["evidence"])
                    if d.get("related_event_ids"):
                        d["related_event_ids"] = json.loads(d["related_event_ids"])
                    # Remove internal dedup field from API responses
                    d.pop("dedup_signature", None)
                    results.append(d)
                return results
        except Exception as e:
            logger.error(f"Failed to retrieve detections: {e}")
            return []

    def get_detections_by_ids(self, detection_ids: List[str]) -> List[Dict[str, Any]]:
        if not detection_ids:
            return []
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                placeholders = ",".join("?" for _ in detection_ids)
                cursor.execute(f'SELECT * FROM detections WHERE detection_id IN ({placeholders}) ORDER BY timestamp ASC', detection_ids)
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    if d.get("evidence"):
                        d["evidence"] = json.loads(d["evidence"])
                    if d.get("related_event_ids"):
                        d["related_event_ids"] = json.loads(d["related_event_ids"])
                    d.pop("dedup_signature", None)
                    results.append(d)
                return results
        except Exception as e:
            logger.error(f"Failed to retrieve detections by IDs: {e}")
            return []

    def save_incident(self, incident: Incident) -> bool:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO incidents (
                        incident_id, title, severity, status, created_at, updated_at,
                        source_ip, username, assigned_to, summary, remediation_notes, detection_ids
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident.incident_id,
                    incident.title,
                    incident.severity.value,
                    incident.status.value,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                    incident.source_ip,
                    incident.username,
                    incident.assigned_to,
                    incident.summary,
                    incident.remediation_notes,
                    json.dumps(incident.detection_ids)
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logger.error(f"Failed to save incident {incident.incident_id}: {e}")
            return False

    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM incidents"
                params = []
                conditions = []

                if status:
                    conditions.append("status = ?")
                    params.append(status.upper())
                if severity:
                    conditions.append("severity = ?")
                    params.append(severity.upper())

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    if d.get("detection_ids"):
                        try:
                            d["detection_ids"] = json.loads(d["detection_ids"])
                        except Exception:
                            d["detection_ids"] = []
                    results.append(d)
                return results
        except Exception as e:
            logger.error(f"Failed to retrieve incidents: {e}")
            return []

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                d = dict(row)
                if d.get("detection_ids"):
                    try:
                        d["detection_ids"] = json.loads(d["detection_ids"])
                    except Exception:
                        d["detection_ids"] = []
                return d
        except Exception as e:
            logger.error(f"Failed to retrieve incident {incident_id}: {e}")
            return None

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        if not updates:
            return True
        try:
            with closing(self.get_connection()) as conn:
                cursor = conn.cursor()
                fields = []
                params = []
                for k, v in updates.items():
                    if k in ["title", "severity", "status", "assigned_to", "summary", "remediation_notes"]:
                        val = v.value if hasattr(v, "value") else v
                        fields.append(f"{k} = ?")
                        params.append(val)
                fields.append("updated_at = ?")
                params.append(datetime.now().isoformat())
                params.append(incident_id)

                cursor.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id = ?", params)
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to update incident {incident_id}: {e}")
            return False