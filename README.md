# AI-SOC: Security Operations Center

## Overview
This project implements a lightweight Security Operations Center (SOC) for Threat Detection and Incident Response, designed to run on a standard local environment (e.g., Windows laptop with 16 GB RAM). It provides a full deterministic threat detection pipeline with a single, integrated AI assistant.

**Important**: The AI is an assistive layer and NOT the primary security detection mechanism. The rule-based engine handles all detections, and the AI assists analysts in understanding and responding to incidents.

### Target SOC Architecture
```
Log Sources -> Log Collection -> Log Parsing & Normalization -> Log Storage (SQLite)
    -> Event Correlation -> Rule-Based Threat Detection -> Alert Generation
    -> Incident Management -> AI-Assisted Analysis (Ollama/Qwen2.5 7B)
    -> SOC Dashboard (Streamlit) -> Human Analyst
```

---

## Phase 1: Foundation
Project structure, configuration handling (`pydantic-settings`), and basic FastAPI entry point.

## Phase 2: Log Collection
Modular log collection via `BaseCollector` interface. Currently implements `SampleLogCollector` which reads JSONL files from `sample_logs/`. Real OS/network collectors can be added later without rewriting the pipeline.

- **Sample Log Format:** One JSON object per line (`.jsonl`) with fields like `timestamp`, `source_ip`, `event_type`, `action`, `status`.
- **API:** `GET /api/logs/sample` returns raw collected events.

## Phase 3: Parsing, Normalization & Storage
Raw events are validated and normalized using Pydantic (`NormalizedEvent` model) and deterministic Python logic (no AI). Valid events are persisted to SQLite.

- **Normalization:** Timestamps to ISO 8601, statuses/event_types lowercased, ports cast to int, IPs validated.
- **Database:** SQLite with indexes on `timestamp`, `source_ip`, `event_type`.
- **API:** `POST /api/logs/collect` runs the full pipeline. `GET /api/events` retrieves stored events.

## Phase 4: Event Correlation

### What is Event Correlation?
Event correlation examines multiple security events and identifies **relationships** between them. A SOC without correlation would treat every event in isolation, making it impossible to see patterns like "15 failed logins followed by a successful login from the same IP."

### Why Correlation is Necessary
Individual log entries rarely tell the full story. A single failed login is normal. But 10 failed logins from the same IP in 2 minutes, followed by a successful login and a privilege escalation, is a coherent attack narrative. The correlation engine assembles these narratives.

### Correlation vs Detection
| Correlation | Detection |
|---|---|
| "These 5 events are related because they share the same source IP and occurred within 5 minutes." | "This pattern of 5 failed logins + 1 success matches the brute-force attack rule." |
| Asks: **which events are related?** | Asks: **is this pattern a known threat?** |

Detection is **not** implemented yet. Correlation only groups events; threat classification happens in Phase 5.

### Correlation Rules Implemented
1. **Source IP Correlation** - Groups events from the same source IP within the time window.
2. **User Activity Correlation** - Groups events by (username + source IP) within the time window.
3. **Network Event Correlation** - Groups network events from the same source IP targeting multiple destination ports within the time window.
4. **Authentication Sequence Correlation** - Identifies ordered auth sequences (failed logins -> success -> privilege escalation -> process execution).

### Time Window
The correlation window is configurable via `correlation_window_seconds` in `config.py` or the `CORRELATION_WINDOW_SECONDS` environment variable. Default: **300 seconds (5 minutes)**.

### Example Correlation Result
```json
{
  "correlation_id": "a1b2c3d4-...",
  "correlation_type": "auth_sequence",
  "start_time": "2026-09-18T10:15:30",
  "end_time": "2026-09-18T10:16:45",
  "source_ip": "192.168.1.10",
  "username": "admin",
  "event_count": 7,
  "event_ids": ["...", "..."],
  "event_types": ["authentication", "system"],
  "reason": "Authentication sequence for user 'admin' from IP 192.168.1.10: ..."
}
```

### API
- `GET /api/correlation` - Run all correlation rules. Optional query params: `source_ip`, `username`, `window`.


## Phase 5: Rule-Based Threat Detection
A deterministic threat detection engine that evaluates both individual normalized events and correlated event sequences. This acts as the intelligence layer identifying malicious patterns without relying on AI. 

### Correlation vs Detection
- **Correlation (Phase 4):** Grouping related events (e.g., 5 failed logins from one IP in 5 minutes). Output: "These events are related."
- **Detection (Phase 5):** Matching correlated sequences against known threat signatures. Output: "This related pattern matches a Brute Force attack."

### Detection Rules Implemented
1. **Brute Force (`RULE_BRUTE_FORCE_01`)**: Identifies multiple failed authentications from the same source IP. Configurable via `brute_force_threshold_count` (Default: 5). Severity: `HIGH`.
2. **Port Scan (`RULE_PORT_SCAN_01`)**: Detects a single source IP contacting multiple unique destination ports within a short time window. Configurable via `port_scan_unique_ports` (Default: 5). Severity: `MEDIUM`.
3. **Suspicious Login (`RULE_SUSPICIOUS_LOGIN_01`)**: Detects a successful login immediately following multiple failed attempts from the same source IP. Severity: `HIGH`.
4. **Privilege Escalation (`RULE_PRIVILEGE_ESCALATION_01`)**: Detects explicit privilege escalation attempts (e.g., `sudo su` or admin granted events). Severity: `CRITICAL`.
5. **Suspicious Process (`RULE_SUSPICIOUS_PROCESS_01`)**: Detects execution of known suspicious commands (e.g., `cat /etc/shadow`). Severity: `HIGH`.

### Severity Levels
- `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` - Assigned deterministically by the rules based on potential impact.

### Database
Detection results are persistently stored in the `detections` SQLite table, keeping track of the `rule_id`, `severity`, descriptive evidence, and the IDs of the events that triggered it.

### API
- `POST /api/detection/run` - Runs correlation and the detection engine on recent events.
- `GET /api/detections` - Retrieves saved detection results.

---

## Phase 6: Incident Management
Aggregates individual threat detections sharing the same attacking entity (source_ip or username) into cohesive, trackable **Incident tickets**.

- **Models:** Incident with statuses (NEW, INVESTIGATING, CONTAINED, CLOSED), severity levels, and analyst assignment.
- **Database:** Stored persistently in the incidents SQLite table.
- **API:**
  - POST /api/incidents/generate - Automatically clusters new detections into incident tickets.
  - GET /api/incidents - Lists incidents with status/severity filters.
  - GET /api/incidents/{id} - Returns incident details, correlated detections, and event timelines.
  - PATCH /api/incidents/{id} - Updates incident status, assigned analyst, and notes.

---

## Phase 7: AI-Assisted Security Analyst
An intelligent assistant layer powered by local LLMs (Ollama with qwen2.5:7b or llama3) and supported by a robust deterministic expert fallback engine.

- **Capabilities:**
  - **Plain-English Incident Translation:** Converts complex technical logs into clear executive summaries.
  - **MITRE ATT&CK Mapping:** Automatically maps alerts to tactics and techniques (e.g., T1110 Brute Force, T1078 Valid Accounts, T1068 Privilege Escalation, T1059.001 PowerShell).
  - **Actionable Remediation Playbooks:** Generates step-by-step containment and mitigation checklists.
  - **Automated Incident Reports:** Generates professional markdown incident investigation reports ready for export.
- **API:**
  - POST /api/incidents/{id}/ai-analysis - Triggers AI analysis and updates incident records.

---

## Phase 8: SOC Analyst Dashboard (Streamlit)
A modern, dark-themed interactive SOC dashboard located in dashboard/app.py.

- **SOC Command Center:** Real-time metrics on ingested events, active detections, and open incidents.
- **Incident Investigation & AI Workbench:** Single-click AI incident investigation, MITRE ATT&CK table, remediation checklists, and report export.
- **Telemetry Explorer:** Search and filter raw normalized logs.

---

## How to Run the SOC

### 1. Install Dependencies
`ash
pip install -r requirements.txt
`

### 2. Start the FastAPI Backend
`ash
uvicorn backend.main:app --reload
`
API Documentation is available at: http://127.0.0.1:8000/docs

### 3. Launch the SOC Dashboard
`ash
streamlit run dashboard/app.py
`
Access the dashboard in your browser at: http://localhost:8501

### 4. Running Tests
`ash
pytest tests/ -v
`
