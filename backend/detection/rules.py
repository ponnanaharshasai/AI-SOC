from typing import List, Optional
import uuid
from datetime import datetime
from backend.correlation.models import CorrelationResult
from backend.parser.models import NormalizedEvent
from backend.detection.models import DetectionResult, Severity
from backend.config import settings


def _event_timestamp(correlation: CorrelationResult) -> datetime:
    """Anchor detection timestamp to the correlation's latest event time, not wall-clock."""
    return correlation.end_time if correlation.end_time else datetime.now()


class DetectionRule:
    """Base class for all detection rules."""
    @property
    def rule_id(self) -> str:
        raise NotImplementedError

    @property
    def detection_type(self) -> str:
        raise NotImplementedError

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        """Evaluate a sequence of correlated events."""
        return None

    def evaluate_event(self, event: NormalizedEvent) -> Optional[DetectionResult]:
        """Evaluate a single standalone event."""
        return None


class BruteForceRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "RULE_BRUTE_FORCE_01"

    @property
    def detection_type(self) -> str:
        return "BRUTE_FORCE"

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        # Only care about source IP or user activity correlations that contain authentication events
        if correlation.correlation_type not in ["source_ip", "user_activity", "auth_sequence"]:
            return None

        # Count failed logins
        failed_logins = [e for e in correlation.events if e.get("event_type") == "authentication" and e.get("status") == "failed"]
        
        if len(failed_logins) >= getattr(settings, "brute_force_threshold_count", 5):
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.HIGH,
                timestamp=_event_timestamp(correlation),
                source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                username=correlation.username,
                description=f"Possible brute-force attack detected. {len(failed_logins)} failed login attempts from IP {correlation.source_ip}.",
                evidence={
                    "failed_attempts": len(failed_logins),
                    "window_seconds": getattr(settings, "correlation_window_seconds", 300)
                },
                related_event_ids=[e["event_id"] for e in failed_logins]
            )
        return None


class PortScanRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "RULE_PORT_SCAN_01"

    @property
    def detection_type(self) -> str:
        return "PORT_SCAN"

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        # Accept any correlation type that contains network events with multiple ports
        network_events = [e for e in correlation.events if e.get("event_type") == "network"]
        unique_ports = set(e.get("destination_port") for e in network_events if e.get("destination_port"))

        if len(unique_ports) >= getattr(settings, "port_scan_unique_ports", 5):
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.MEDIUM,
                timestamp=_event_timestamp(correlation),
                source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                username=correlation.username,
                description=f"Possible port scan detected from IP {correlation.source_ip}. Contacted {len(unique_ports)} unique ports.",
                evidence={
                    "unique_ports": len(unique_ports),
                    "ports_list": list(unique_ports),
                    "window_seconds": getattr(settings, "correlation_window_seconds", 300)
                },
                related_event_ids=[e["event_id"] for e in network_events if e.get("destination_port") in unique_ports]
            )
        return None


class SuspiciousLoginRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "RULE_SUSPICIOUS_LOGIN_01"

    @property
    def detection_type(self) -> str:
        return "SUSPICIOUS_LOGIN"

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        if correlation.correlation_type not in ["auth_sequence", "user_activity", "source_ip"]:
            return None

        # Look for multiple failures followed by a success
        auth_events = [e for e in correlation.events if e.get("event_type") == "authentication"]
        if not auth_events:
            return None

        failed_count = 0
        related_ids = []
        for e in auth_events:
            if e.get("status") == "failed":
                failed_count += 1
                related_ids.append(e["event_id"])
            elif e.get("status") == "success" and failed_count >= 3:
                # Found a success after at least 3 failures
                related_ids.append(e["event_id"])
                return DetectionResult(
                    detection_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    detection_type=self.detection_type,
                    severity=Severity.HIGH,
                    timestamp=_event_timestamp(correlation),
                    source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                    username=correlation.username or e.get("username"),
                    description=f"Suspicious login: Successful login after {failed_count} failed attempts from IP {correlation.source_ip}.",
                    evidence={
                        "failed_attempts_before_success": failed_count,
                        "successful_event_id": e["event_id"]
                    },
                    related_event_ids=related_ids
                )
            elif e.get("status") == "success":
                # Reset if success without many failures
                failed_count = 0
                related_ids = []

        return None


class PrivilegeEscalationRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "RULE_PRIVILEGE_ESCALATION_01"

    @property
    def detection_type(self) -> str:
        return "PRIVILEGE_ESCALATION"

    def _is_priv_escalation(self, action: str, message: str) -> bool:
        if action == "privilege_escalation":
            return True
        msg = (message or "").lower()
        if "sudo su" in msg or "admin granted" in msg:
            return True
        return False

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        for e in correlation.events:
            if self._is_priv_escalation(e.get("action", ""), e.get("message", "")):
                return DetectionResult(
                    detection_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    detection_type=self.detection_type,
                    severity=Severity.CRITICAL,
                    timestamp=_event_timestamp(correlation),
                    source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                    username=correlation.username or e.get("username"),
                    description=f"Privilege escalation detected: {e.get('message')}",
                    evidence={
                        "escalation_event_id": e["event_id"]
                    },
                    related_event_ids=[e["event_id"]]
                )
        return None

    def evaluate_event(self, event: NormalizedEvent) -> Optional[DetectionResult]:
        if self._is_priv_escalation(event.action, event.message):
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.CRITICAL,
                timestamp=event.timestamp,
                source_ip=str(event.source_ip) if event.source_ip else None,
                username=event.username,
                description=f"Privilege escalation detected: {event.message}",
                evidence={
                    "escalation_event_id": event.event_id
                },
                related_event_ids=[event.event_id]
            )
        return None


class SuspiciousProcessRule(DetectionRule):
    @property
    def rule_id(self) -> str:
        return "RULE_SUSPICIOUS_PROCESS_01"

    @property
    def detection_type(self) -> str:
        return "SUSPICIOUS_PROCESS"

    def _is_suspicious(self, msg: str) -> bool:
        msg = (msg or "").lower()
        suspicious_strings = [
            # Linux credential dumping
            "cat /etc/shadow", "nc -e", "/bin/sh -i",
            # Windows encoded PowerShell (BOTS v1 pattern)
            "powershell -enc", "powershell -e ", "powershell -encoded",
            "powershell -nop", "powershell -w hidden", "powershell -windowstyle hidden",
            # Credential dumping & lateral movement
            "mimikatz", "sekurlsa", "lsadump", "invoke-mimikatz",
            "procdump", "comsvcs.dll", "minidump",
            # Remote access & reverse shells
            "mshta", "regsvr32 /s /u", "certutil -decode", "certutil -urlcache",
            "bitsadmin /transfer", "wscript //e:", "cscript //e:",
            # Persistence via registry
            "reg add.*run", "schtasks /create",
            # Discovery commands
            "net user /domain", "net group /domain", "net localgroup administrators",
            "whoami /priv", "whoami /all",
            # Pass-the-hash / network recon
            "psexec", "wmic process call create",
            # Data exfiltration
            "invoke-webrequest", "wget ", "curl ",
        ]
        for s in suspicious_strings:
            if s in msg:
                return True
        return False

    def evaluate_event(self, event: NormalizedEvent) -> Optional[DetectionResult]:
        if event.event_type == "system" and self._is_suspicious(event.message):
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.HIGH,
                timestamp=event.timestamp,
                source_ip=str(event.source_ip) if event.source_ip else None,
                username=event.username,
                description=f"Suspicious process or command execution detected.",
                evidence={
                    "command_message": event.message
                },
                related_event_ids=[event.event_id]
            )
        return None

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        for e in correlation.events:
            if e.get("event_type") == "system" and self._is_suspicious(e.get("message", "")):
                return DetectionResult(
                    detection_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    detection_type=self.detection_type,
                    severity=Severity.HIGH,
                    timestamp=_event_timestamp(correlation),
                    source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                    username=correlation.username or e.get("username"),
                    description=f"Suspicious process or command execution detected in sequence.",
                    evidence={
                        "command_message": e.get("message")
                    },
                    related_event_ids=[e["event_id"]]
                )
        return None


class LateralMovementRule(DetectionRule):
    """
    Detects lateral movement by identifying explicit-credential logons (EventCode 4648)
    or authentication sequences across multiple unique destination hosts from the same source.
    """
    @property
    def rule_id(self) -> str:
        return "RULE_LATERAL_MOVEMENT_01"

    @property
    def detection_type(self) -> str:
        return "LATERAL_MOVEMENT"

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        # Look for explicit-credential logon events (Windows 4648 – "A logon was attempted using explicit credentials")
        explicit_cred_events = [
            e for e in correlation.events
            if e.get("event_type") == "authentication"
            and e.get("action") == "login"
            and e.get("status") == "success"
            and ("explicit" in (e.get("message") or "").lower() or "4648" in (e.get("message") or ""))
        ]

        # Also detect privilege escalation followed by remote auth from same IP in same window
        priv_events = [e for e in correlation.events if e.get("action") == "privilege_escalation"]
        login_events = [e for e in correlation.events if e.get("event_type") == "authentication" and e.get("status") == "success"]

        related_ids = []
        if len(explicit_cred_events) >= 2:
            related_ids = [e["event_id"] for e in explicit_cred_events]
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.HIGH,
                timestamp=_event_timestamp(correlation),
                source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                username=correlation.username,
                description=f"Possible lateral movement detected: {len(explicit_cred_events)} explicit-credential logons from {correlation.source_ip}.",
                evidence={
                    "explicit_cred_events": len(explicit_cred_events),
                    "window_seconds": getattr(settings, "correlation_window_seconds", 300)
                },
                related_event_ids=related_ids
            )

        if priv_events and len(login_events) >= 2:
            related_ids = [e["event_id"] for e in priv_events + login_events]
            return DetectionResult(
                detection_id=str(uuid.uuid4()),
                rule_id=self.rule_id,
                detection_type=self.detection_type,
                severity=Severity.HIGH,
                timestamp=_event_timestamp(correlation),
                source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                username=correlation.username,
                description=f"Possible lateral movement: privilege escalation followed by multiple authentication events from {correlation.source_ip}.",
                evidence={
                    "priv_events": len(priv_events),
                    "subsequent_logins": len(login_events)
                },
                related_event_ids=related_ids
            )
        return None


class ServiceInstallationRule(DetectionRule):
    """
    Detects suspicious Windows service installations (EventCode 4697) which are commonly
    used for persistence and privilege escalation by adversaries.
    """
    @property
    def rule_id(self) -> str:
        return "RULE_SERVICE_INSTALL_01"

    @property
    def detection_type(self) -> str:
        return "SUSPICIOUS_SERVICE_INSTALL"

    def _is_suspicious_service(self, msg: str) -> bool:
        msg = (msg or "").lower()
        suspicious_svc_patterns = [
            # Common attacker service names
            "psexesvc", "remcomsvc", "meterpreter", "cobaltstrike",
            # Services installed from temp/unusual paths
            "\\temp\\", "\\appdata\\", "\\programdata\\", "%temp%",
            # Services using known LOLBins (Living off the Land Binaries)
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
        ]
        for pattern in suspicious_svc_patterns:
            if pattern in msg:
                return True
        return False

    def evaluate_event(self, event: NormalizedEvent) -> Optional[DetectionResult]:
        if event.action == "privilege_escalation" and "service installed" in (event.message or "").lower():
            if self._is_suspicious_service(event.message):
                return DetectionResult(
                    detection_id=str(uuid.uuid4()),
                    rule_id=self.rule_id,
                    detection_type=self.detection_type,
                    severity=Severity.CRITICAL,
                    timestamp=event.timestamp,
                    source_ip=str(event.source_ip) if event.source_ip else None,
                    username=event.username,
                    description=f"Suspicious Windows service installation detected: potential persistence mechanism.",
                    evidence={"service_message": event.message},
                    related_event_ids=[event.event_id]
                )
        return None

    def evaluate_correlation(self, correlation: CorrelationResult) -> Optional[DetectionResult]:
        for e in correlation.events:
            if e.get("action") == "privilege_escalation" and "service installed" in (e.get("message") or "").lower():
                if self._is_suspicious_service(e.get("message", "")):
                    return DetectionResult(
                        detection_id=str(uuid.uuid4()),
                        rule_id=self.rule_id,
                        detection_type=self.detection_type,
                        severity=Severity.CRITICAL,
                        timestamp=_event_timestamp(correlation),
                        source_ip=str(correlation.source_ip) if correlation.source_ip else None,
                        username=correlation.username or e.get("username"),
                        description=f"Suspicious Windows service installed in correlated attack sequence: potential persistence mechanism.",
                        evidence={"service_message": e.get("message")},
                        related_event_ids=[e["event_id"]]
                    )
        return None
