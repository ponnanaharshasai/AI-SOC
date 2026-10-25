# AI-SOC — Step-by-Step Workflow Guide

> A detailed walkthrough of every operation in the AI-SOC pipeline, from raw log ingestion to final incident report generation.

---

## Table of Contents

1. [Phase 1: Project Foundation & Configuration](#phase-1-project-foundation--configuration)
2. [Phase 2: Log Collection](#phase-2-log-collection)
3. [Phase 3: Parsing, Normalization & Storage](#phase-3-parsing-normalization--storage)
4. [Phase 4: Event Correlation](#phase-4-event-correlation)
5. [Phase 5: Rule-Based Threat Detection](#phase-5-rule-based-threat-detection)
6. [Phase 6: Incident Management](#phase-6-incident-management)
7. [Phase 7: AI-Assisted Analysis](#phase-7-ai-assisted-analysis)
8. [Phase 8: SOC Dashboard](#phase-8-soc-dashboard)
9. [End-to-End Workflow Summary](#end-to-end-workflow-summary)
10. [API Reference Quick Map](#api-reference-quick-map)

---

## Phase 1: Project Foundation & Configuration

### What It Does
Sets up the project structure, configuration management, and the FastAPI application entry point.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 1.1 | Load configuration | `backend/config.py` | `Settings` class (Pydantic BaseSettings) reads from environment variables or `.env` file |
| 1.2 | Set defaults | `backend/config.py` | `project_name="AI-SOC"`, `sqlite_db_path`, `correlation_window_seconds=300`, `ollama_host`, `brute_force_threshold_count=5`, `port_scan_unique_ports=5` |
| 1.3 | Initialize FastAPI | `backend/main.py` | Create `app = FastAPI(...)` with title, description, version |
| 1.4 | Database lifespan | `backend/main.py` | On startup, `db_manager.initialize_database()` creates SQLite tables if they don't exist |
| 1.5 | Register endpoints | `backend/main.py` | Mount all API routes (11 endpoints across Phases 2–7) |

### Key Configuration Parameters

```
project_name           = "AI-SOC"
sqlite_db_path         = "sqlite:///./soc_data.db"
correlation_window_seconds = 300  (5 minutes)
ollama_host            = "http://localhost:11434"
ai_model_name          = "qwen2.5:7b"
brute_force_threshold_count = 5
port_scan_unique_ports = 5
```

---

## Phase 2: Log Collection

### What It Does
Reads raw security event logs from JSONL files (or BOTS v1 extracted CSV) and returns them as Python dictionaries.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 2.1 | **(Optional) Extract BOTS v1** | `scripts/extract_botsv1.py` | Parses the 15.8 GB Splunk BOTS v1 CSV. Filters by Windows EventCodes (4624, 4634, 4648, 4672, 4673, 4688, 4697). Generates `sample_logs/botsv1_attack_scenario.jsonl` (1,508 events). |
| 2.2 | Determine log file path | `backend/main.py` | Resolves absolute path to `sample_logs/{filename}` (default: `events.jsonl`) |
| 2.3 | Instantiate collector | `backend/collectors/sample.py` | `SampleLogCollector(file_path=...)` is created |
| 2.4 | Check file existence | `backend/collectors/sample.py` | `os.path.exists(self.file_path)` — returns empty list if missing |
| 2.5 | Read file line-by-line | `backend/collectors/sample.py` | Opens file with UTF-8 encoding, iterates over each line |
| 2.6 | Parse JSON per line | `backend/collectors/sample.py` | `json.loads(line)` — skips empty lines, logs malformed JSON with line number |
| 2.7 | Return raw events | `backend/collectors/sample.py` | Returns `List[Dict[str, Any]]` of all successfully parsed events |

### API Trigger
```
GET /api/logs/sample?filename=events.jsonl
→ Returns raw collected events (no normalization, no storage)
```

### Error Handling
- **File not found** → Logs error, returns empty list
- **Permission denied** → Logs error, returns empty list
- **Malformed JSON** → Logs warning with line number, skips line, continues processing

---

## Phase 3: Parsing, Normalization & Storage

### What It Does
Validates and normalizes each raw event using Pydantic, then persists valid events to SQLite.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 3.1 | Trigger collection | `backend/main.py` | `POST /api/logs/collect` calls `SampleLogCollector.collect()` |
| 3.2 | Initialize parser | `backend/parser/parser.py` | `LogParser()` instance created |
| 3.3 | **For each raw event:** | | |
| 3.3a | Normalize fields | `backend/parser/normalizer.py` | `normalize_raw_event(raw)` performs: |
| | | | • Generate `event_id` (UUID4) if missing |
| | | | • Lowercase `status`, `event_type`, `action` |
| | | | • Cast `source_port` and `destination_port` to `int` (or `None` on failure) |
| 3.3b | Validate with Pydantic | `backend/parser/parser.py` | `NormalizedEvent(**normalized_dict)` — validates field types, IP format, timestamps |
| 3.3c | Save to database | `backend/database/manager.py` | `db_manager.save_event(normalized_event)` inserts into `normalized_events` table |
| 3.4 | Return summary | `backend/main.py` | Returns counts: `collected`, `processed`, `stored`, `failed` |

### API Triggers
```
POST /api/logs/collect?filename=events.jsonl
→ Full pipeline: Collect → Parse → Normalize → Store → Return summary

GET /api/events?limit=100
→ Retrieve stored normalized events from SQLite
```

### Database Schema (normalized_events)
```sql
event_id       TEXT PRIMARY KEY
timestamp      TEXT (ISO 8601)
source_ip      TEXT (Indexed)
destination_ip TEXT
source_port    INTEGER
destination_port INTEGER
event_type     TEXT (Indexed)
action         TEXT
status         TEXT
username       TEXT
message        TEXT
raw_data       TEXT (JSON)
```

### Normalization Rules
1. **Timestamps** → ISO 8601 format
2. **Status/Event Type/Action** → Lowercased
3. **Ports** → Cast to integer, set `None` if invalid
4. **Event ID** → Auto-generated UUID4 if not provided
5. **IPs** → Validated format

---

## Phase 4: Event Correlation

### What It Does
Queries stored events from SQLite and identifies **relationships** between them. Does NOT classify threats — only groups related events.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 4.1 | Initialize engine | `backend/correlation/engine.py` | `CorrelationEngine(db_manager)` reads `correlation_window_seconds` from config |
| 4.2 | Call `correlate_all()` | `backend/correlation/engine.py` | Runs all 4 correlation rules sequentially |
| 4.3 | **Rule 1 — Source IP** | | |
| 4.3a | Query all events | `engine.py` | `_query_events(source_ip=...)` via SQL |
| 4.3b | Group by `source_ip` | `engine.py` | `_group_by_field(events, "source_ip")` |
| 4.3c | Cluster by time | `engine.py` | `_cluster_by_time(ip_events, window)` — splits events into temporal clusters where consecutive events are ≤ window seconds apart |
| 4.3d | Build result | `engine.py` | Creates `CorrelationResult` for clusters with ≥ 2 events |
| 4.4 | **Rule 2 — User Activity** | | |
| 4.4a | Query all events | `engine.py` | Optional filters: `source_ip`, `username` |
| 4.4b | Group by `(username, source_ip)` | `engine.py` | Composite key grouping |
| 4.4c | Cluster by time | `engine.py` | Same temporal clustering logic |
| 4.4d | Build result | `engine.py` | CorrelationResult with `correlation_type="user_activity"` |
| 4.5 | **Rule 3 — Network Events** | | |
| 4.5a | Query `event_type="network"` | `engine.py` | Filter for network-type events only |
| 4.5b | Group by `source_ip` | `engine.py` | Same grouping logic |
| 4.5c | Filter multi-port | `engine.py` | Only include clusters where ≥ 2 unique `destination_port` values |
| 4.5d | Build result | `engine.py` | CorrelationResult with `correlation_type="network_scan"` |
| 4.6 | **Rule 4 — Auth Sequence** | | |
| 4.6a | Query auth + system events | `engine.py` | Fetches both `authentication` and `system` event types |
| 4.6b | Merge & sort by timestamp | `engine.py` | Combines both sets, deduplicates by `event_id` |
| 4.6c | Group by `(username, source_ip)` | `engine.py` | Composite key grouping |
| 4.6d | Check sequence patterns | `engine.py` | Looks for: `failed` + `success` statuses, OR `success` + `system` event types |
| 4.6e | Build result | `engine.py` | CorrelationResult with `correlation_type="auth_sequence"` |
| 4.7 | Deduplicate results | `engine.py` | If two rules produce the same `event_ids` set, keep the more specific type (priority: `auth_sequence` > `user_activity` > `source_ip`) |
| 4.8 | Return results | `engine.py` | Returns `List[CorrelationResult]` |

### API Trigger
```
GET /api/correlation?source_ip=...&username=...&window=...
→ Runs all correlation rules with optional filters
```

### Temporal Clustering Algorithm
```
Input:  Sorted events + window_seconds
Output: List of event clusters

For each consecutive pair of events:
  If (event[i+1].timestamp - event[i].timestamp) ≤ window_seconds:
    → Add to current cluster
  Else:
    → Start new cluster
```

### Correlation Type Priority (for deduplication)
```
auth_sequence  = 3  (highest specificity)
network_scan   = 3
user_activity  = 2
source_ip      = 1  (lowest specificity)
```

---

## Phase 5: Rule-Based Threat Detection

### What It Does
Evaluates normalized events and correlated sequences against 7 deterministic detection rules to identify known threat patterns.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 5.1 | Fetch recent events | `backend/main.py` | `db_manager.get_recent_events(limit=1000)` |
| 5.2 | Convert to models | `backend/main.py` | Cast each dict to `NormalizedEvent` Pydantic model |
| 5.3 | Run correlation | `backend/main.py` | `CorrelationEngine.correlate_all()` returns grouped events |
| 5.4 | Initialize detection | `backend/detection/engine.py` | `DetectionEngine(db_manager)` registers all 7 rules |
| 5.5 | **Single-event evaluation** | `engine.py` | For each event × each rule: `rule.evaluate_event(event)` |
| 5.6 | **Correlation evaluation** | `engine.py` | For each correlation × each rule: `rule.evaluate_correlation(corr)` |
| 5.7 | Deduplicate | `engine.py` | Signature = `{rule_id}:{sorted(event_ids)}` — remove exact duplicates |
| 5.8 | Persist to DB | `engine.py` | `db_manager.save_detection(result)` for each unique detection |
| 5.9 | Return results | `engine.py` | Returns `List[DetectionResult]` |

### Detection Rules — Detailed Logic

#### Rule 1: Brute Force (`RULE_BRUTE_FORCE_01`)
```
Trigger:  ≥ 5 failed authentication events from same source_ip
Input:    Correlation (auth_sequence or source_ip type)
Logic:    Count events where status="failed" AND event_type="authentication"
Severity: HIGH
MITRE:    T1110 — Brute Force: Password Guessing
```

#### Rule 2: Suspicious Login (`RULE_SUSPICIOUS_LOGIN_01`)
```
Trigger:  Successful login following ≥ 3 failures from same source_ip
Input:    Correlation (auth_sequence type)
Logic:    Check ordered sequence for failed→success pattern
Severity: HIGH
MITRE:    T1078 — Valid Accounts
```

#### Rule 3: Privilege Escalation (`RULE_PRIVILEGE_ESCALATION_01`)
```
Trigger:  Explicit privilege escalation activity
Input:    Single event
Logic:    Match action containing "privilege_escalation", "admin granted",
          "sudo su", or Windows Event 4672/4703
Severity: CRITICAL
MITRE:    T1068 — Exploitation for Privilege Escalation
```

#### Rule 4: Suspicious Process (`RULE_SUSPICIOUS_PROCESS_01`)
```
Trigger:  Execution of known malicious commands
Input:    Single event
Logic:    Match message/action against 25+ suspicious commands:
          powershell -enc, mimikatz, certutil, whoami, psexec,
          cat /etc/shadow, net user, reg save, etc.
Severity: HIGH
MITRE:    T1059.001 — PowerShell / Command Interpreter
```

#### Rule 5: Port Scan (`RULE_PORT_SCAN_01`)
```
Trigger:  Single IP hitting ≥ 5 unique destination ports
Input:    Correlation (network_scan type)
Logic:    Count distinct destination_port values in cluster
Severity: MEDIUM
MITRE:    T1046 — Network Service Discovery
```

#### Rule 6: Lateral Movement (`RULE_LATERAL_MOVEMENT_01`)
```
Trigger:  Explicit-credential logons (Event 4648) across hosts
Input:    Single event + Correlation
Logic:    Match Event 4648 or priv escalation + multi-host auth
Severity: HIGH
MITRE:    T1021 — Remote Services
```

#### Rule 7: Suspicious Service Installation (`RULE_SERVICE_INSTALL_01`)
```
Trigger:  Malicious Windows service creation
Input:    Single event
Logic:    Match Event 4697 + suspicious service names/paths
          (psexesvc, LOLBins from temp directories)
Severity: CRITICAL
MITRE:    T1543.003 — Windows Service
```

### API Triggers
```
POST /api/detection/run?window=...
→ Runs correlation + detection engine on recent events

GET /api/detections?limit=100
→ Retrieves saved detection results from SQLite
```

---

## Phase 6: Incident Management

### What It Does
Aggregates individual detections sharing the same attacker entity into cohesive, trackable incident tickets.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 6.1 | Fetch recent detections | `backend/incidents/engine.py` | `db.get_recent_detections(limit=500)` |
| 6.2 | Fetch existing incidents | `engine.py` | `db.get_incidents(limit=200)` |
| 6.3 | Identify assigned IDs | `engine.py` | Collect all `detection_id`s already linked to existing incidents |
| 6.4 | Filter unassigned | `engine.py` | Keep only detections whose `detection_id` is NOT in assigned set |
| 6.5 | Group by entity | `engine.py` | Key = `source_ip` or `username` or `"UNKNOWN_ENTITY"` |
| 6.6 | **For each entity group:** | | |
| 6.6a | Collect detection IDs | `engine.py` | List of all `detection_id`s in this group |
| 6.6b | Determine severity | `engine.py` | Max severity across all detections: `LOW(1) < MEDIUM(2) < HIGH(3) < CRITICAL(4)` |
| 6.6c | Generate title | `engine.py` | Multi-type → `"Multi-Stage Attack: TYPE1 -> TYPE2 from {IP}"` / Single-type → `"{TYPE} Incident from {IP}"` |
| 6.6d | Generate summary | `engine.py` | `"Detected N related security events for entity X. Involves: TYPE1, TYPE2."` |
| 6.6e | Create Incident model | `engine.py` | `Incident(incident_id=UUID, title=..., severity=..., status=NEW, ...)` |
| 6.6f | Save to database | `engine.py` | `db.save_incident(incident)` |
| 6.7 | Return created incidents | `engine.py` | Returns `List[Incident]` |

### Incident Lifecycle
```
NEW → INVESTIGATING → CONTAINED → CLOSED
                   ↘ CLOSED (false positive)
```

### API Triggers
```
POST /api/incidents/generate
→ Cluster unassigned detections into incident tickets

GET /api/incidents?status=...&severity=...&limit=100
→ List all incidents with optional filtering

GET /api/incidents/{id}
→ Incident details + linked detections + raw event timeline

PATCH /api/incidents/{id}
→ Update status, assigned analyst, or analyst notes
   Body: { "status": "INVESTIGATING", "assigned_analyst": "John", "notes": "..." }
```

---

## Phase 7: AI-Assisted Analysis

### What It Does
Generates an AI-powered (or expert fallback) analysis report for an incident, including executive summary, MITRE ATT&CK mapping, remediation playbook, and a downloadable markdown report.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 7.1 | Receive incident ID | `backend/main.py` | `POST /api/incidents/{id}/ai-analysis` |
| 7.2 | Initialize assistant | `backend/ai/assistant.py` | `AIAssistant(db_manager)` — sets Ollama URL and model name |
| 7.3 | Fetch incident | `assistant.py` | `db.get_incident(incident_id)` — raises 404 if not found |
| 7.4 | Fetch linked detections | `assistant.py` | `db.get_detections_by_ids(detection_ids)` |
| 7.5 | Fetch raw events | `assistant.py` | Collect all `related_event_ids` from detections → `db.get_events_by_ids(unique_ids)` |
| 7.6 | **Try Ollama LLM** | `assistant.py` | |
| 7.6a | Build prompt | `backend/ai/prompts.py` | `build_incident_analysis_prompt(incident, detections, events)` — structured prompt with all context |
| 7.6b | POST to Ollama | `assistant.py` | `httpx.Client.post(ollama_url, json={model, prompt, system, stream:False})` with 8-second timeout |
| 7.6c | Parse response | `assistant.py` | Extract `response` field from JSON response |
| 7.7 | **If Ollama unavailable → Expert Fallback** | `assistant.py` | Logs info message, returns empty string (triggers fallback path) |
| 7.8 | Map MITRE ATT&CK | `assistant.py` | Look up each `detection_type` in `MITRE_CATALOG` dictionary → returns `List[MitreTechnique]` |
| 7.9 | Compile remediation | `assistant.py` | Look up each `detection_type` in `DEFAULT_REMEDIATION_PLAYBOOK` → deduplicated step list |
| 7.10 | Build executive summary | `assistant.py` | If AI text available: use first line (max 300 chars). Otherwise: deterministic template with source_ip, username, detection types |
| 7.11 | Generate full report | `assistant.py` | Build structured markdown with 5 sections: |
| | | | 1. Executive Summary |
| | | | 2. Threat Detections & Evidence |
| | | | 3. MITRE ATT&CK Mapping Table |
| | | | 4. Remediation & Containment Playbook |
| | | | 5. Event Timeline (up to 15 events) |
| 7.12 | Update incident in DB | `assistant.py` | `db.update_incident(id, {summary, remediation_notes})` |
| 7.13 | Return result | `assistant.py` | Returns `AIAnalysisResult` with all fields |

### MITRE ATT&CK Catalog (7 Techniques)

| Detection Type | MITRE ID | Technique Name | Tactic |
|---|---|---|---|
| `BRUTE_FORCE` | T1110 | Brute Force: Password Guessing | Credential Access |
| `SUSPICIOUS_LOGIN` | T1078 | Valid Accounts | Defense Evasion / Initial Access |
| `PRIVILEGE_ESCALATION` | T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| `SUSPICIOUS_PROCESS` | T1059.001 | PowerShell | Execution |
| `PORT_SCAN` | T1046 | Network Service Discovery | Discovery |
| `LATERAL_MOVEMENT` | T1021 | Remote Services | Lateral Movement |
| `SUSPICIOUS_SERVICE_INSTALL` | T1543.003 | Windows Service | Persistence |

### Remediation Playbook Examples

**BRUTE_FORCE:**
1. Lock targeted account or enforce password reset
2. Block attacking source IP at perimeter firewall
3. Enable/enforce MFA on all authentication endpoints

**PRIVILEGE_ESCALATION:**
1. Audit admin groups and remove unapproved accounts
2. Review Event 4672/4703 for unauthorized policy modifications
3. Inspect host for persistence mechanisms

### API Trigger
```
POST /api/incidents/{id}/ai-analysis
→ Returns AIAnalysisResult with summary, MITRE mapping, remediation, and full markdown report
```

---

## Phase 8: SOC Dashboard

### What It Does
Provides a modern, dark-themed interactive Streamlit dashboard for security analysts to monitor, investigate, and respond to incidents.

### Step-by-Step Flow

| Step | Action | File | Details |
|------|--------|------|---------|
| 8.1 | Launch dashboard | `dashboard/app.py` | `streamlit run dashboard/app.py` — runs on `http://localhost:8501` |
| 8.2 | Configure theme | `app.py` | Dark-mode theme with custom CSS |
| 8.3 | **Tab 1: SOC Command Center** | | |
| 8.3a | Fetch metrics | `app.py` | Calls backend APIs for event count, detection count, incident count |
| 8.3b | Display metric cards | `app.py` | Total Ingested Events, Threat Detections, Total Incidents, Active/Open |
| 8.3c | Show detection feed | `app.py` | Recent threat detections with severity badges (color-coded) |
| 8.3d | Show incident queue | `app.py` | Active incidents table with status and severity |
| 8.4 | **Tab 2: Incident Investigation & AI Workbench** | | |
| 8.4a | Incident selector | `app.py` | Dropdown to select incident by ID |
| 8.4b | Display incident details | `app.py` | Title, severity, status, source IP, username, summary |
| 8.4c | **"Run AI Analysis" button** | `app.py` | Calls `POST /api/incidents/{id}/ai-analysis` |
| 8.4d | Display AI results | `app.py` | Executive summary, MITRE ATT&CK table, remediation checklist |
| 8.4e | **Download Report** | `app.py` | `st.download_button` for full markdown report as `.md` file |
| 8.4f | Status update form | `app.py` | PATCH incident: assign analyst, add notes, change lifecycle status |
| 8.5 | **Tab 3: Telemetry Explorer** | | |
| 8.5a | Search/filter events | `app.py` | Full-text search across all normalized events |
| 8.5b | Display event table | `app.py` | Timestamped log table with all event fields |

### Dashboard Interaction Flow
```
Analyst opens dashboard
    → Views Command Center metrics
    → Notices HIGH severity incident
    → Clicks "Incident Investigation" tab
    → Selects incident from dropdown
    → Clicks "Run AI Incident Analysis & Generate Report"
    → Reviews MITRE ATT&CK mapping
    → Follows remediation checklist
    → Downloads report for documentation
    → Updates incident status to INVESTIGATING → CONTAINED → CLOSED
```

---

## End-to-End Workflow Summary

### Complete Pipeline (7 Steps)

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: DATA INGESTION                                           │
│  User selects log source (BOTS v1 / sample JSONL)                 │
│  Dashboard: Click "📥 Ingest & Normalize Logs"                    │
│  API: POST /api/logs/collect?filename=botsv1_attack_scenario.jsonl │
│  Result: Raw events collected, normalized, stored in SQLite       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: EVENT CORRELATION (automatic inside detection)            │
│  4 strategies run: Source IP, User Activity, Network, Auth Seq     │
│  Temporal clustering with configurable window (default: 5 min)     │
│  Result: Grouped event relationships (CorrelationResults)          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: THREAT DETECTION                                          │
│  Dashboard: Click "🔍 Run Threat Detection"                        │
│  API: POST /api/detection/run                                      │
│  7 rules evaluate single events + correlations                     │
│  Result: DetectionResults saved to SQLite                          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: INCIDENT GENERATION                                       │
│  Dashboard: Click "🚨 Generate Security Incidents"                 │
│  API: POST /api/incidents/generate                                 │
│  Unassigned detections clustered by attacker entity                │
│  Result: Incident tickets created (status: NEW)                    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: AI ANALYSIS                                               │
│  Dashboard: Select incident → Click "Run AI Analysis"              │
│  API: POST /api/incidents/{id}/ai-analysis                         │
│  Tries Ollama LLM → Falls back to expert engine if offline         │
│  Result: MITRE mapping, remediation playbook, markdown report      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 6: ANALYST REVIEW & RESPONSE                                 │
│  Dashboard: Review AI report, MITRE table, remediation checklist   │
│  Download full incident report (.md)                               │
│  Update incident: assign analyst, add notes                        │
│  Change status: NEW → INVESTIGATING → CONTAINED → CLOSED           │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 7: FORENSIC TELEMETRY REVIEW                                 │
│  Dashboard: "Telemetry Explorer" tab                               │
│  Search and filter raw normalized events                           │
│  Full timestamped log table for deep-dive investigation            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## API Reference Quick Map

| # | Method | Endpoint | Phase | Purpose |
|---|--------|----------|-------|---------|
| 1 | `GET` | `/` | 1 | Health check / welcome |
| 2 | `GET` | `/health` | 1 | Service health |
| 3 | `GET` | `/api/logs/sample` | 2 | Return raw collected events |
| 4 | `POST` | `/api/logs/collect` | 3 | Collect → Parse → Normalize → Store |
| 5 | `GET` | `/api/events` | 3 | Retrieve stored normalized events |
| 6 | `GET` | `/api/correlation` | 4 | Run correlation rules |
| 7 | `POST` | `/api/detection/run` | 5 | Run correlation + detection engine |
| 8 | `GET` | `/api/detections` | 5 | Retrieve saved detections |
| 9 | `POST` | `/api/incidents/generate` | 6 | Cluster detections into incidents |
| 10 | `GET` | `/api/incidents` | 6 | List incidents (with filters) |
| 11 | `GET` | `/api/incidents/{id}` | 6 | Incident details + detections + events |
| 12 | `PATCH` | `/api/incidents/{id}` | 6 | Update status / analyst / notes |
| 13 | `POST` | `/api/incidents/{id}/ai-analysis` | 7 | AI-assisted incident analysis |

---

## File-to-Phase Mapping

| File | Phase | Role |
|------|-------|------|
| `backend/config.py` | 1 | Configuration (Pydantic Settings) |
| `backend/main.py` | 1–7 | FastAPI app + all API endpoints |
| `backend/collectors/base.py` | 2 | Abstract collector interface |
| `backend/collectors/sample.py` | 2 | JSONL file reader |
| `scripts/extract_botsv1.py` | 2 | BOTS v1 CSV extraction script |
| `backend/parser/parser.py` | 3 | Log parsing orchestrator |
| `backend/parser/normalizer.py` | 3 | Field normalization functions |
| `backend/parser/models.py` | 3 | NormalizedEvent Pydantic model |
| `backend/database/manager.py` | 3 | SQLite CRUD operations |
| `backend/correlation/engine.py` | 4 | 4 correlation strategies |
| `backend/correlation/models.py` | 4 | CorrelationResult model |
| `backend/detection/rules.py` | 5 | 7 detection rule implementations |
| `backend/detection/engine.py` | 5 | Detection orchestrator |
| `backend/detection/models.py` | 5 | DetectionResult model |
| `backend/incidents/engine.py` | 6 | Incident creation & grouping |
| `backend/incidents/models.py` | 6 | Incident + IncidentUpdate models |
| `backend/ai/assistant.py` | 7 | AI analysis + expert fallback |
| `backend/ai/models.py` | 7 | AIAnalysisResult + MitreTechnique models |
| `backend/ai/prompts.py` | 7 | LLM system prompt + prompt builder |
| `dashboard/app.py` | 8 | Streamlit SOC dashboard |
