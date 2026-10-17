# AI-SOC - Project Review Guide

## 1. Project Overview
This project is a **fully functional, multi-phase Security Operations Center (SOC)** designed to detect enterprise cyber threats and assist security analysts in responding to them.

The system uses **strict, deterministic rules** to detect attacks (no false positives from AI hallucinations). The AI then acts as an expert analyst assistant — translating events, mapping to MITRE ATT&CK, generating remediation playbooks, and producing full incident reports.

**Data Source:** Real enterprise Windows Security Event Logs from the [Splunk BOTS v1](https://github.com/splunk/botsv1) dataset — an authentic red-team simulation against a fictitious organization (Wayne Enterprises).

---

## 2. Complete Architecture

```
[Log Sources (JSONL / BOTS v1 CSV)]
        ↓
[Phase 2: Log Collection]     backend/collectors/
        ↓
[Phase 3: Parsing & Normalization]  backend/parser/
        ↓
[SQLite Database]             backend/database/manager.py
        ↓
[Phase 4: Event Correlation]  backend/correlation/engine.py
        ↓
[Phase 5: Threat Detection (7 Rules)]  backend/detection/
        ↓
[Phase 6: Incident Management]  backend/incidents/
        ↓
[Phase 7: AI Analysis (Ollama + Expert Fallback)]  backend/ai/
        ↓
[Phase 8: SOC Analyst Dashboard (Streamlit)]  dashboard/app.py
```

---

## 3. Real Data Integration — Splunk BOTS v1

The `botsv1.WinEventLog_Security.csv` file (15.8 GB, 13.4M+ rows of authentic Windows Security Events) is extracted using `scripts/extract_botsv1.py` into a lightweight, portable `sample_logs/botsv1_attack_scenario.jsonl` file (1,508 events, 442 KB).

**Windows Event Codes Mapped:**
| Event Code | Meaning | Maps To |
|---|---|---|
| 4624 | Successful logon | `authentication` / `login` / `success` |
| 4634 | Logoff | `authentication` / `logout` / `success` |
| 4648 | Explicit credential logon | `authentication` / `login` / `success` |
| 4672 / 4703 | Special privileges assigned / policy change | `system` / `privilege_escalation` |
| 4673 | Privileged service call failure | `system` / `privilege_escalation` / `failed` |
| 4688 | New process created | `system` / `process_execution` |
| 4697 | Service installed | `system` / `privilege_escalation` (service) |

---

## 4. Event Correlation Engine (Phase 4)

Groups related events within a configurable time window (default: 5 minutes). Four correlation strategies:

| Strategy | How it works |
|---|---|
| **Source IP** | All events sharing the same `source_ip` |
| **User Activity** | Events by `(username + source_ip)` pair |
| **Network Events** | Network connections targeting multiple destination ports |
| **Auth Sequence** | Ordered: Failed logins → Successful login → Privilege escalation → Command execution |

---

## 5. Threat Detection Engine (Phase 5) — 7 Active Rules

| Rule ID | Detection Type | Severity | What it detects |
|---|---|---|---|
| `RULE_BRUTE_FORCE_01` | BRUTE_FORCE | HIGH | 5+ failed logins from same IP |
| `RULE_SUSPICIOUS_LOGIN_01` | SUSPICIOUS_LOGIN | HIGH | Successful login following 3+ failures |
| `RULE_PRIVILEGE_ESCALATION_01` | PRIVILEGE_ESCALATION | CRITICAL | `admin granted`, `sudo su`, Event 4672/4703 |
| `RULE_SUSPICIOUS_PROCESS_01` | SUSPICIOUS_PROCESS | HIGH | 25+ Windows & Linux malicious commands (PowerShell -enc, mimikatz, certutil, whoami, psexec...) |
| `RULE_PORT_SCAN_01` | PORT_SCAN | MEDIUM | Single IP hitting 5+ unique destination ports |
| `RULE_LATERAL_MOVEMENT_01` | LATERAL_MOVEMENT | HIGH | Explicit-credential logons (4648) or priv escalation + multi-host auth |
| `RULE_SERVICE_INSTALL_01` | SUSPICIOUS_SERVICE_INSTALL | CRITICAL | Malicious Windows service installation (psexesvc, LOLBins from temp paths) |

---

## 6. Incident Management (Phase 6)

Detections are automatically aggregated into **Incident tickets** by shared attacking entity (`source_ip` or `username`).

**Incident Lifecycle:**
```
NEW → INVESTIGATING → CONTAINED → CLOSED
```

| API Endpoint | Purpose |
|---|---|
| `POST /api/incidents/generate` | Cluster new detections into incident tickets |
| `GET /api/incidents` | List all incidents (filter by status / severity) |
| `GET /api/incidents/{id}` | Get incident + all detections + event timeline |
| `PATCH /api/incidents/{id}` | Update status, assign analyst, add notes |

---

## 7. AI Security Analyst (Phase 7)

### How It Works
1. **Try Ollama first:** Connects to local LLM (`qwen2.5:7b` or `llama3`) at `http://localhost:11434`.
2. **Fallback if offline:** Uses a pre-built expert engine with MITRE mappings and curated remediation playbooks — the SOC continues working **even without an LLM**.

### Capabilities
- **Plain-English Translation:** Converts technical Windows audit events into executive summaries.
- **MITRE ATT&CK Mapping** (7 techniques covered):

| Detection Type | MITRE ID | MITRE Technique | Tactic |
|---|---|---|---|
| BRUTE_FORCE | T1110 | Brute Force: Password Guessing | Credential Access |
| SUSPICIOUS_LOGIN | T1078 | Valid Accounts | Defense Evasion / Initial Access |
| PRIVILEGE_ESCALATION | T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| SUSPICIOUS_PROCESS | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution |
| PORT_SCAN | T1046 | Network Service Discovery | Discovery |
| LATERAL_MOVEMENT | T1021 | Remote Services: Valid Accounts | Lateral Movement |
| SUSPICIOUS_SERVICE_INSTALL | T1543.003 | Create or Modify System Process: Windows Service | Persistence |

- **Automated Incident Reports:** Full markdown investigation reports with executive summary, evidence tables, MITRE ATT&CK tables, and remediation steps — **downloadable directly from the dashboard**.
- **API:** `POST /api/incidents/{id}/ai-analysis`

---

## 8. SOC Analyst Dashboard (Phase 8)

**Start with:** `streamlit run dashboard/app.py`

Three main workbenches:

### 📊 SOC Command Center
- Live metric cards: Total Ingested Events, Threat Detections, Total Incidents, Active/Open Incidents.
- Recent threat detection feed with severity badges.
- Active incidents queue table.

### 🤖 Incident Investigation & AI Assistant
- Incident selector dropdown.
- **"Run AI Incident Analysis & Generate Report"** button.
- Live MITRE ATT&CK alignment table.
- Step-by-step remediation & containment checklist.
- **Download Report (.md)** button.
- Status update form (analyst assignment, notes, lifecycle status changes).

### 🔍 Correlated Events & Telemetry
- Real-time search and full-text filter across all normalized events.
- Full timestamped log table.

---

## 9. Testing

All **29 tests** pass across 7 test files:

```bash
pytest tests/ -v
```

| Test File | Coverage |
|---|---|
| `test_collectors.py` | Log file reading and JSONL parsing |
| `test_parser.py` | Pydantic normalization, IP/port validation |
| `test_correlation.py` | All 4 correlation strategies |
| `test_detection.py` | All 5 original detection rules |
| `test_incidents.py` | Incident grouping, lifecycle, and PATCH update |
| `test_ai_assistant.py` | AI analysis, MITRE mapping, report generation |
| `test_botsv1_pipeline.py` | End-to-end BOTS v1 real-data ingestion → detection |
| `test_pipeline.py` | Full API pipeline (collect → events → correlation → detection) |

---

## 10. How to Run the Complete SOC

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: (Optional) Start Ollama AI Model
```bash
ollama serve
ollama pull qwen2.5:7b
```
*If Ollama is not running, the SOC uses the deterministic expert fallback engine automatically.*

### Step 3: Start the FastAPI Backend
```bash
uvicorn backend.main:app --reload
```
API Docs: `http://127.0.0.1:8000/docs`

### Step 4: Launch the SOC Dashboard
```bash
streamlit run dashboard/app.py
```
Dashboard: `http://localhost:8501`

### Step 5: Full Workflow in the Dashboard
1. Select **"Splunk BOTS v1"** as the log source.
2. Click **📥 Ingest & Normalize Logs**.
3. Click **🔍 Run Threat Detection**.
4. Click **🚨 Generate Security Incidents**.
5. Go to the **"Incident Investigation & AI Assistant"** tab.
6. Select an incident and click **"Run AI Incident Analysis & Generate Report"**.
7. Download the full incident report.
