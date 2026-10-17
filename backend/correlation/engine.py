"""
Event Correlation Engine.

Examines normalized security events stored in SQLite and identifies
relationships between them based on shared attributes and time proximity.

IMPORTANT: This engine only identifies RELATIONSHIPS between events.
It does NOT determine whether a pattern represents a known threat.
That responsibility belongs to the detection engine (Phase 5).

Correlation asks:  "Which events are related?"
Detection asks:    "Does this related pattern represent a known threat?"
"""

import uuid
import logging
from contextlib import closing
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from collections import defaultdict

from backend.correlation.models import CorrelationResult
from backend.config import settings

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Deterministic event correlation engine.
    Queries stored events and groups related ones based on configurable rules.
    """

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.window_seconds = settings.correlation_window_seconds

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def correlate_all(
        self,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[CorrelationResult]:
        """Run all correlation rules and return deduplicated results."""
        window = window_seconds or self.window_seconds
        results: List[CorrelationResult] = []

        results.extend(self.correlate_by_source_ip(source_ip=source_ip, window_seconds=window))
        results.extend(self.correlate_by_user_activity(username=username, source_ip=source_ip, window_seconds=window))
        results.extend(self.correlate_network_events(source_ip=source_ip, window_seconds=window))
        results.extend(self.correlate_auth_sequences(source_ip=source_ip, window_seconds=window))

        # Deduplicate: if two rules produced the exact same set of event_ids, keep the more specific one
        results = self._deduplicate(results)
        return results

    # ------------------------------------------------------------------
    # RULE 1 — Same Source IP + Time Window
    # ------------------------------------------------------------------

    def correlate_by_source_ip(
        self,
        source_ip: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[CorrelationResult]:
        """Group events sharing the same source_ip within the time window."""
        window = window_seconds or self.window_seconds
        events = self._query_events(source_ip=source_ip)
        groups = self._group_by_field(events, "source_ip")

        results = []
        for ip, ip_events in groups.items():
            if ip is None:
                continue
            for cluster in self._cluster_by_time(ip_events, window):
                if len(cluster) < 2:
                    continue
                results.append(self._build_result(
                    correlation_type="source_ip",
                    events=cluster,
                    source_ip=ip,
                    reason=f"Multiple events from source IP {ip} within {window}s window",
                ))
        return results

    # ------------------------------------------------------------------
    # RULE 2 — Same Username + Source IP + Time Window
    # ------------------------------------------------------------------

    def correlate_by_user_activity(
        self,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[CorrelationResult]:
        """Group events sharing the same username AND source_ip within the time window."""
        window = window_seconds or self.window_seconds
        events = self._query_events(source_ip=source_ip, username=username)

        # Composite key: (username, source_ip)
        composite: Dict[tuple, List[dict]] = defaultdict(list)
        for ev in events:
            user = ev.get("username")
            ip = ev.get("source_ip")
            if user and ip:
                composite[(user, ip)].append(ev)

        results = []
        for (user, ip), group_events in composite.items():
            for cluster in self._cluster_by_time(group_events, window):
                if len(cluster) < 2:
                    continue
                results.append(self._build_result(
                    correlation_type="user_activity",
                    events=cluster,
                    source_ip=ip,
                    username=user,
                    reason=f"Multiple events for user '{user}' from IP {ip} within {window}s window",
                ))
        return results

    # ------------------------------------------------------------------
    # RULE 3 — Multiple Network Connections from Same Source IP
    # ------------------------------------------------------------------

    def correlate_network_events(
        self,
        source_ip: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[CorrelationResult]:
        """Group network/connection events from same source IP hitting multiple ports."""
        window = window_seconds or self.window_seconds
        events = self._query_events(source_ip=source_ip, event_type="network")

        groups = self._group_by_field(events, "source_ip")
        results = []
        for ip, ip_events in groups.items():
            if ip is None:
                continue
            for cluster in self._cluster_by_time(ip_events, window):
                dest_ports = set()
                for ev in cluster:
                    dp = ev.get("destination_port")
                    if dp is not None:
                        dest_ports.add(dp)
                if len(dest_ports) < 2:
                    continue
                results.append(self._build_result(
                    correlation_type="network_scan",
                    events=cluster,
                    source_ip=ip,
                    reason=f"Network events from IP {ip} targeting {len(dest_ports)} distinct ports within {window}s window",
                ))
        return results

    # ------------------------------------------------------------------
    # RULE 4 — Authentication Sequences (failed -> success -> privilege)
    # ------------------------------------------------------------------

    def correlate_auth_sequences(
        self,
        source_ip: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> List[CorrelationResult]:
        """Identify ordered authentication sequences (e.g. failures followed by success)."""
        window = window_seconds or self.window_seconds

        # Fetch auth events AND system events (for privilege escalation / process exec)
        auth_events = self._query_events(source_ip=source_ip, event_type="authentication")
        sys_events = self._query_events(source_ip=source_ip, event_type="system")
        all_events = sorted(auth_events + sys_events, key=lambda e: e.get("timestamp", ""))

        # Deduplicate by event_id (in case source_ip filter overlaps)
        seen_ids = set()
        unique = []
        for ev in all_events:
            eid = ev.get("event_id")
            if eid not in seen_ids:
                seen_ids.add(eid)
                unique.append(ev)
        all_events = unique

        # Group by (username, source_ip) composite
        composite: Dict[tuple, List[dict]] = defaultdict(list)
        for ev in all_events:
            user = ev.get("username")
            ip = ev.get("source_ip")
            if user:
                composite[(user, ip)].append(ev)

        results = []
        for (user, ip), group_events in composite.items():
            for cluster in self._cluster_by_time(group_events, window):
                if len(cluster) < 2:
                    continue
                statuses = [e.get("status") for e in cluster]
                actions = [e.get("action") for e in cluster]
                event_types = [e.get("event_type") for e in cluster]

                # Check for meaningful sequence: at least one failed + one success,
                # OR auth events mixed with system/privilege events
                has_failed = "failed" in statuses
                has_success = "success" in statuses
                has_system = "system" in event_types

                if (has_failed and has_success) or (has_success and has_system):
                    results.append(self._build_result(
                        correlation_type="auth_sequence",
                        events=cluster,
                        source_ip=ip,
                        username=user,
                        reason=f"Authentication sequence for user '{user}' from IP {ip}: "
                               f"statuses={statuses}, includes system activity={has_system}",
                    ))
        return results

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _query_events(
        self,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query normalized_events from SQLite with optional filters."""
        try:
            with closing(self.db_manager.get_connection()) as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM normalized_events WHERE 1=1"
                params: list = []

                if source_ip:
                    query += " AND source_ip = ?"
                    params.append(source_ip)
                if username:
                    query += " AND username = ?"
                    params.append(username)
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)

                query += " ORDER BY timestamp ASC"
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Correlation query failed: {e}")
            return []

    @staticmethod
    def _group_by_field(events: List[dict], field: str) -> Dict[Any, List[dict]]:
        """Group a list of event dicts by a given field value."""
        groups: Dict[Any, List[dict]] = defaultdict(list)
        for ev in events:
            groups[ev.get(field)].append(ev)
        return groups

    @staticmethod
    def _cluster_by_time(events: List[dict], window_seconds: int) -> List[List[dict]]:
        """
        Split an already-sorted list of events into clusters where
        consecutive events are no more than window_seconds apart.
        """
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        clusters: List[List[dict]] = []
        current_cluster: List[dict] = [sorted_events[0]]

        for ev in sorted_events[1:]:
            prev_ts = current_cluster[-1].get("timestamp", "")
            curr_ts = ev.get("timestamp", "")
            try:
                prev_dt = datetime.fromisoformat(prev_ts)
                curr_dt = datetime.fromisoformat(curr_ts)
                gap = (curr_dt - prev_dt).total_seconds()
            except (ValueError, TypeError):
                gap = float("inf")

            if gap <= window_seconds:
                current_cluster.append(ev)
            else:
                clusters.append(current_cluster)
                current_cluster = [ev]

        clusters.append(current_cluster)
        return clusters

    @staticmethod
    def _build_result(
        correlation_type: str,
        events: List[dict],
        reason: str,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
    ) -> CorrelationResult:
        """Create a CorrelationResult from a cluster of events."""
        timestamps = []
        for ev in events:
            try:
                timestamps.append(datetime.fromisoformat(ev["timestamp"]))
            except (KeyError, ValueError, TypeError):
                pass

        return CorrelationResult(
            correlation_id=str(uuid.uuid4()),
            correlation_type=correlation_type,
            start_time=min(timestamps) if timestamps else datetime.min,
            end_time=max(timestamps) if timestamps else datetime.min,
            source_ip=source_ip,
            username=username,
            event_count=len(events),
            event_ids=[e.get("event_id", "") for e in events],
            event_types=list(dict.fromkeys(e.get("event_type", "") for e in events)),
            events=events,
            reason=reason,
        )

    @staticmethod
    def _deduplicate(results: List[CorrelationResult]) -> List[CorrelationResult]:
        """Remove duplicate correlations that cover the exact same event set."""
        seen: dict = {}
        for r in results:
            key = frozenset(r.event_ids)
            if key in seen:
                existing = seen[key]
                # Keep the more specific type (auth_sequence > user_activity > source_ip)
                priority = {"auth_sequence": 3, "network_scan": 3, "user_activity": 2, "source_ip": 1}
                if priority.get(r.correlation_type, 0) > priority.get(existing.correlation_type, 0):
                    seen[key] = r
            else:
                seen[key] = r
        return list(seen.values())
