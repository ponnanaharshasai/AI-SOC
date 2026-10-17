import logging
import httpx
from typing import Dict, Any, List
from datetime import datetime
from backend.config import settings
from backend.database.manager import DatabaseManager
from backend.ai.models import AIAnalysisResult, MitreTechnique
from backend.ai.prompts import SYSTEM_PROMPT, build_incident_analysis_prompt

logger = logging.getLogger(__name__)

# Expert mapping fallback for offline/reliable SOC operation
MITRE_CATALOG = {
    "BRUTE_FORCE": MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description="Adversaries may attempt to guess passwords of valid user accounts using repeated automated login attempts."
    ),
    "SUSPICIOUS_LOGIN": MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion / Initial Access",
        description="Adversaries may obtain and abuse credentials of existing accounts following successful brute-force attempts."
    ),
    "PRIVILEGE_ESCALATION": MitreTechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries may manipulate user rights or permissions to escalate from standard privileges to administrator/root privileges."
    ),
    "SUSPICIOUS_PROCESS": MitreTechnique(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        description="Adversaries may use PowerShell or malicious command lines to execute malicious commands or encode scripts."
    ),
    "PORT_SCAN": MitreTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to discover active services and open ports on a network host."
    ),
    "LATERAL_MOVEMENT": MitreTechnique(
        technique_id="T1021",
        technique_name="Remote Services: Valid Accounts",
        tactic="Lateral Movement",
        description="Adversaries may use explicit credentials and remote services to move laterally across hosts within a network."
    ),
    "SUSPICIOUS_SERVICE_INSTALL": MitreTechnique(
        technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        tactic="Persistence / Privilege Escalation",
        description="Adversaries may install malicious Windows services to maintain persistence or elevate privileges."
    ),
}

DEFAULT_REMEDIATION_PLAYBOOK = {
    "BRUTE_FORCE": [
        "Temporarily lock the targeted user account or enforce an immediate password reset.",
        "Block the attacking source IP address at the perimeter firewall / security group.",
        "Enable or enforce Multi-Factor Authentication (MFA) across all authentication endpoints."
    ],
    "SUSPICIOUS_LOGIN": [
        "Immediately terminate active user sessions for the compromised account.",
        "Revoke existing API keys, OAuth tokens, and Kerberos tickets associated with the account.",
        "Verify all actions taken by the compromised account during the active session window."
    ],
    "PRIVILEGE_ESCALATION": [
        "Audit administrative groups (e.g. Domain Admins, sudoers) and remove unapproved accounts.",
        "Review Windows Event 4672/4703 or audit logs for unauthorized policy modifications.",
        "Inspect the host for persistence mechanisms (scheduled tasks, services, startup registry keys)."
    ],
    "SUSPICIOUS_PROCESS": [
        "Isolate the affected host endpoint from the corporate network.",
        "Terminate the suspicious parent and child process trees.",
        "Capture volatile memory (RAM) and collect forensic artifacts (PowerShell logs, prefetch, event logs)."
    ],
    "PORT_SCAN": [
        "Implement rate-limiting and drop rules for the scanning source IP.",
        "Ensure unused or legacy network ports are closed and filtered by firewall ACLs.",
        "Review network perimeter devices for unauthorized exposure of management ports."
    ],
    "LATERAL_MOVEMENT": [
        "Revoke all active sessions and credentials associated with the compromised account.",
        "Audit all systems accessed via explicit-credential logons during the incident window.",
        "Review east-west network traffic for unauthorized remote desktop (RDP) or SMB connections.",
        "Enable network segmentation and enforce the principle of least privilege across service accounts."
    ],
    "SUSPICIOUS_SERVICE_INSTALL": [
        "Immediately stop and delete the suspicious Windows service via `sc stop <name>` and `sc delete <name>`.",
        "Inspect the service binary path for malicious executables and quarantine if found.",
        "Search for additional persistence in registry Run keys, scheduled tasks, and startup folders.",
        "Review Windows Event 4697 logs for the full timeline of service installation events."
    ]
}


class AIAssistant:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.ollama_url = f"{settings.ollama_host.rstrip('/')}/api/generate"
        self.model = settings.ai_model_name

    def analyze_incident(self, incident_id: str) -> AIAnalysisResult:
        """Run AI-assisted analysis for the specified incident."""
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        # Fetch related detections and raw events
        detection_ids = incident.get("detection_ids", [])
        detections = self.db.get_detections_by_ids(detection_ids)

        all_event_ids = []
        for d in detections:
            all_event_ids.extend(d.get("related_event_ids", []))
        # Unique preserve order
        unique_event_ids = list(dict.fromkeys(all_event_ids))
        events = self.db.get_events_by_ids(unique_event_ids)

        # Attempt to call Ollama
        ai_response_text = self._query_ollama(incident, detections, events)
        model_name = self.model if ai_response_text else "soc-expert-playbook-engine"

        # Extract MITRE techniques and remediation
        detection_types = [d.get("detection_type", "") for d in detections]
        mitre_list = [MITRE_CATALOG[dt] for dt in detection_types if dt in MITRE_CATALOG]

        remediation_steps = []
        for dt in detection_types:
            for step in DEFAULT_REMEDIATION_PLAYBOOK.get(dt, []):
                if step not in remediation_steps:
                    remediation_steps.append(step)

        if not remediation_steps:
            remediation_steps = [
                "Review firewall logs for suspicious outbound connections.",
                "Verify endpoint security agent status on affected host.",
                "Notify security team lead and document incident ticket."
            ]

        # Generate executive summary
        summary = self._build_executive_summary(incident, detections, ai_response_text)

        # Generate full markdown report
        full_report = self._build_full_report(
            incident=incident,
            detections=detections,
            events=events,
            summary=summary,
            mitre_list=mitre_list,
            remediation_steps=remediation_steps,
            ai_notes=ai_response_text,
            model_name=model_name
        )

        result = AIAnalysisResult(
            incident_id=incident_id,
            title=incident.get("title", "Security Incident"),
            severity=incident.get("severity", "MEDIUM"),
            summary=summary,
            mitre_attack=mitre_list,
            remediation_steps=remediation_steps,
            full_report_markdown=full_report,
            model_used=model_name,
            timestamp=datetime.now()
        )

        # Update incident record with AI summary and notes
        self.db.update_incident(incident_id, {
            "summary": summary,
            "remediation_notes": "\n".join(f"- {s}" for s in remediation_steps)
        })

        return result

    def _query_ollama(self, incident: dict, detections: list, events: list) -> str:
        """Query local Ollama instance if available, otherwise return empty string."""
        prompt = build_incident_analysis_prompt(incident, detections, events)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False
        }

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.post(self.ollama_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("response", "").strip()
        except Exception as e:
            logger.info(f"Ollama local service not reachable at {self.ollama_url} ({e}). Using deterministic expert response.")
        return ""

    def _build_executive_summary(self, incident: dict, detections: list, ai_text: str) -> str:
        if ai_text:
            lines = [l.strip() for l in ai_text.splitlines() if l.strip()]
            if lines:
                return lines[0][:300]

        source_ip = incident.get("source_ip") or "an external entity"
        user = incident.get("username") or "system accounts"
        types = [d.get("detection_type", "Threat") for d in detections]
        types_str = ", ".join(dict.fromkeys(types))

        return (
            f"Adversary activity originating from {source_ip} was detected targeting {user}. "
            f"The attack exhibited {types_str} patterns matching known intrusion signatures. "
            f"Correlated evidence confirms malicious actions requiring immediate containment."
        )

    def _build_full_report(
        self,
        incident: dict,
        detections: list,
        events: list,
        summary: str,
        mitre_list: List[MitreTechnique],
        remediation_steps: List[str],
        ai_notes: str,
        model_name: str
    ) -> str:
        report = f"""# 🛡️ SOC Incident Investigation Report

**Incident ID:** `{incident.get('incident_id')}`  
**Title:** {incident.get('title')}  
**Severity:** **{incident.get('severity')}**  
**Status:** `{incident.get('status')}`  
**Attacking Entity (Source IP):** `{incident.get('source_ip', 'N/A')}`  
**Targeted User/Host:** `{incident.get('username', 'N/A')}`  
**Analysis Engine:** `{model_name}`  
**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  

---

## 1. Executive Summary
{summary}

"""
        if ai_notes:
            report += f"### AI Analyst Notes ({model_name})\n{ai_notes}\n\n"

        report += "## 2. Threat Detections & Evidence\n"
        for idx, d in enumerate(detections, 1):
            report += f"### {idx}. {d.get('detection_type')} (Rule: `{d.get('rule_id')}`)\n"
            report += f"- **Severity:** {d.get('severity')}\n"
            report += f"- **Description:** {d.get('description')}\n"
            report += f"- **Evidence:** `{d.get('evidence')}`\n\n"

        report += "## 3. MITRE ATT&CK Mapping\n"
        if mitre_list:
            report += "| Tactic | Technique ID | Technique Name | Description |\n"
            report += "|---|---|---|---|\n"
            for m in mitre_list:
                report += f"| {m.tactic} | **{m.technique_id}** | {m.technique_name} | {m.description} |\n"
            report += "\n"
        else:
            report += "No direct MITRE mapping detected.\n\n"

        report += "## 4. Remediation & Containment Playbook\n"
        for idx, step in enumerate(remediation_steps, 1):
            report += f"{idx}. {step}\n"

        report += f"\n## 5. Event Timeline ({len(events)} Events)\n"
        for e in events[:15]:
            report += f"- `{e.get('timestamp')}`: **{e.get('event_type').upper()}** - {e.get('message')}\n"

        if len(events) > 15:
            report += f"- *... and {len(events) - 15} additional supporting events logged.*\n"

        return report
