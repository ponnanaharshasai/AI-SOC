"""Prompt templates for the AI Security Operations Center Assistant."""

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) Incident Response AI Assistant.
Your task is to analyze security incidents detected by deterministic rules, translate technical telemetry into plain English for human analysts, map the attack to MITRE ATT&CK techniques, and provide actionable remediation steps.

Respond with structured, accurate, and professional analysis."""

def build_incident_analysis_prompt(incident_dict: dict, detections: list, events: list) -> str:
    """Build the prompt describing the incident and its supporting evidence."""
    prompt = f"""### Security Incident for Analysis
Incident ID: {incident_dict.get('incident_id')}
Title: {incident_dict.get('title')}
Severity: {incident_dict.get('severity')}
Source IP: {incident_dict.get('source_ip', 'Unknown')}
Target Username: {incident_dict.get('username', 'Unknown')}
Created At: {incident_dict.get('created_at')}

### Correlated Threat Detections ({len(detections)}):
"""
    for idx, d in enumerate(detections, 1):
        prompt += f"{idx}. Rule: {d.get('rule_id')} | Type: {d.get('detection_type')} | Severity: {d.get('severity')}\n"
        prompt += f"   Description: {d.get('description')}\n"
        prompt += f"   Evidence: {d.get('evidence')}\n"

    prompt += f"\n### Supporting Log Telemetry (Sample of {min(len(events), 10)} events):\n"
    for e in events[:10]:
        prompt += f"- [{e.get('timestamp')}] {e.get('event_type')} | Action: {e.get('action')} | Status: {e.get('status')} | Message: {e.get('message')}\n"

    prompt += """
Please provide:
1. Executive Summary: What happened in clear, concise language?
2. Technical Impact: What was compromised or accessed?
3. MITRE ATT&CK Mapping: Identify the relevant Tactic, Technique ID, and Technique Name.
4. Actionable Remediation: Concrete step-by-step containment and mitigation instructions.
"""
    return prompt
