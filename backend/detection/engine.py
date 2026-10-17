import logging
from typing import List, Optional
from backend.database.manager import DatabaseManager
from backend.correlation.models import CorrelationResult
from backend.parser.models import NormalizedEvent
from backend.detection.models import DetectionResult
from backend.detection.rules import (
    DetectionRule,
    BruteForceRule,
    PortScanRule,
    SuspiciousLoginRule,
    PrivilegeEscalationRule,
    SuspiciousProcessRule,
    LateralMovementRule,
    ServiceInstallationRule,
)

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        # Register rules
        self.rules: List[DetectionRule] = [
            BruteForceRule(),
            PortScanRule(),
            SuspiciousLoginRule(),
            PrivilegeEscalationRule(),
            SuspiciousProcessRule(),
            LateralMovementRule(),
            ServiceInstallationRule(),
        ]

    def _deduplicate(self, results: List[DetectionResult]) -> List[DetectionResult]:
        """
        Remove duplicate detections that describe the exact same event ids
        for the same rule.
        """
        unique = []
        seen_signatures = set()
        for r in results:
            sig = f"{r.rule_id}:{','.join(sorted(r.related_event_ids))}"
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique.append(r)
        return unique

    def run_detection(self, events: List[NormalizedEvent], correlations: List[CorrelationResult]) -> List[DetectionResult]:
        """
        Evaluate all rules against all raw events and correlated event sequences.
        """
        results: List[DetectionResult] = []

        # 1. Evaluate single events (e.g. suspicious process execution)
        for event in events:
            for rule in self.rules:
                res = rule.evaluate_event(event)
                if res:
                    results.append(res)

        # 2. Evaluate correlations (e.g. brute force, port scan, suspicious login)
        for corr in correlations:
            for rule in self.rules:
                res = rule.evaluate_correlation(corr)
                if res:
                    results.append(res)

        # Deduplicate and sort by severity/timestamp
        final_results = self._deduplicate(results)
        
        # Save to DB
        stored = 0
        for res in final_results:
            if self.db_manager.save_detection(res):
                stored += 1
                
        logger.info(f"Detection engine ran: found {len(final_results)} detections, stored {stored}.")
        return final_results
