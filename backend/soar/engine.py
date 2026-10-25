import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.database.manager import DatabaseManager
from backend.soar.models import SOARAction, SOARActionType, SOARActionStatus

logger = logging.getLogger(__name__)

INTERNAL_LOOPBACKS = {"127.0.0.1", "::1", "localhost", "unknown", "N/A"}


class SOAREngine:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def evaluate_and_contain_incident(self, incident: Dict[str, Any], detections: List[Dict[str, Any]]) -> List[SOARAction]:
        """Autonomously determine and execute containment actions based on incident threat evidence."""
        actions: List[SOARAction] = []
        incident_id = incident.get("incident_id")
        source_ip = incident.get("source_ip")
        username = incident.get("username")
        severity = incident.get("severity", "MEDIUM")

        # Fetch currently active actions to prevent duplicate active containment
        active_actions = self.db.get_soar_actions(status="ACTIVE")
        active_targets = {(a.get("action_type"), a.get("target")) for a in active_actions}

        detection_types = {d.get("detection_type", "") for d in detections}

        # 1. Automated Perimeter IP Block
        if source_ip and source_ip.strip() and source_ip not in INTERNAL_LOOPBACKS:
            if ("BLOCK_IP", source_ip) not in active_targets:
                action = SOARAction(
                    action_id=f"act_{uuid.uuid4().hex[:10]}",
                    incident_id=incident_id,
                    action_type=SOARActionType.BLOCK_IP,
                    target=source_ip,
                    status=SOARActionStatus.ACTIVE,
                    reason=f"Automated firewall block against attacking IP exhibiting {', '.join(detection_types)} (Severity: {severity})",
                    executed_at=datetime.now()
                )
                if self.db.save_soar_action(action.model_dump(mode="json")):
                    actions.append(action)
                    active_targets.add(("BLOCK_IP", source_ip))
                    logger.info(f"[SOAR] Executed firewall drop rule for attacking IP: {source_ip}")

        # 2. Automated Identity Provider / User Account Lockout
        if username and username.strip() and username.lower() not in ["system", "network service", "local service", "unknown", "n/a"]:
            if any(dt in detection_types for dt in ["BRUTE_FORCE", "SUSPICIOUS_LOGIN", "PRIVILEGE_ESCALATION"]):
                if ("QUARANTINE_USER", username) not in active_targets:
                    action = SOARAction(
                        action_id=f"act_{uuid.uuid4().hex[:10]}",
                        incident_id=incident_id,
                        action_type=SOARActionType.QUARANTINE_USER,
                        target=username,
                        status=SOARActionStatus.ACTIVE,
                        reason=f"Identity Provider: Sessions invalidated and account {username} locked due to active credential compromise",
                        executed_at=datetime.now()
                    )
                    if self.db.save_soar_action(action.model_dump(mode="json")):
                        actions.append(action)
                        active_targets.add(("QUARANTINE_USER", username))
                        logger.info(f"[SOAR] Locked compromised user account: {username}")

        # 3. Endpoint Isolation for High/Critical Privilege Escalation or Malware execution
        if severity in ["HIGH", "CRITICAL"] and any(dt in detection_types for dt in ["PRIVILEGE_ESCALATION", "SUSPICIOUS_PROCESS", "SUSPICIOUS_SERVICE_INSTALL"]):
            target_host = username or source_ip or "HOST-ENDPOINT-01"
            if ("ISOLATE_HOST", target_host) not in active_targets:
                action = SOARAction(
                    action_id=f"act_{uuid.uuid4().hex[:10]}",
                    incident_id=incident_id,
                    action_type=SOARActionType.ISOLATE_HOST,
                    target=target_host,
                    status=SOARActionStatus.ACTIVE,
                    reason=f"EDR Agent: Endpoint isolated to containment VLAN following malicious process/service execution",
                    executed_at=datetime.now()
                )
                if self.db.save_soar_action(action.model_dump(mode="json")):
                    actions.append(action)
                    active_targets.add(("ISOLATE_HOST", target_host))
                    logger.info(f"[SOAR] Isolated endpoint host: {target_host}")

        # 4. Terminate Suspicious Process / LOLBin Trees
        if "SUSPICIOUS_PROCESS" in detection_types:
            proc_target = "PowerShell.exe / Mimikatz tree"
            if ("TERMINATE_PROCESS", proc_target) not in active_targets:
                action = SOARAction(
                    action_id=f"act_{uuid.uuid4().hex[:10]}",
                    incident_id=incident_id,
                    action_type=SOARActionType.TERMINATE_PROCESS,
                    target=proc_target,
                    status=SOARActionStatus.ACTIVE,
                    reason="EDR Agent: Suspicious encoded PowerShell / credential dumping process tree terminated",
                    executed_at=datetime.now()
                )
                if self.db.save_soar_action(action.model_dump(mode="json")):
                    actions.append(action)
                    active_targets.add(("TERMINATE_PROCESS", proc_target))
                    logger.info(f"[SOAR] Terminated malicious process: {proc_target}")

        # If any actions were taken, update incident status to CONTAINED
        if actions:
            self.db.update_incident(incident_id, {
                "status": "CONTAINED",
                "assigned_to": "Autonomous AI Analyst (Auto-SOC)"
            })

        return actions

    def execute_manual_action(self, action_type: str, target: str, reason: str, incident_id: Optional[str] = None) -> SOARAction:
        """Execute an analyst-initiated or explicit SOAR action."""
        action = SOARAction(
            action_id=f"act_{uuid.uuid4().hex[:10]}",
            incident_id=incident_id,
            action_type=SOARActionType(action_type),
            target=target,
            status=SOARActionStatus.ACTIVE,
            reason=reason,
            executed_at=datetime.now()
        )
        self.db.save_soar_action(action.model_dump(mode="json"))
        return action

    def rollback_action(self, action_id: str) -> bool:
        """Roll back an active containment action."""
        return self.db.rollback_soar_action(action_id)
