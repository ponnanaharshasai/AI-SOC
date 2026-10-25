# 🛡️ AI-SOC: Autonomous Security Operations Center

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32.2-FF4B4B.svg)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-32%20Passed%20(100%25)-brightgreen.svg)]()

## Overview
**AI-SOC** is an autonomous, lightweight Security Operations Center (SOC) designed to run on standard hardware (e.g., standard workstation or cloud VM) without requiring multi-thousand dollar enterprise cloud SIEM licenses.

### Core Architectural Philosophy
> **"Strict, Deterministic Rules Detect Threats — AI Translates, Explains, and Guides Response."**

In production cybersecurity, relying purely on Generative AI for threat detection creates unacceptable risks: hallucinations, non-deterministic alerts, and missed attacks. AI-SOC addresses this by enforcing **100% deterministic Python rules** for threat detection, while leveraging a **Hybrid AI Analyst** (local Ollama with `qwen2.5:7b` / `llama3` backed by an offline expert playbook engine) to synthesize telemetry into plain English, map alerts to the MITRE ATT&CK framework, author audit-ready forensic reports, and deploy automated **SOAR containment actions** (firewall IP blocks, account lockouts, endpoint isolation) with single-click rollback.

---

## 🏛️ System Architecture

```
[ Security Telemetry (Splunk BOTS v1 / JSONL / REST) ]
                          │
                          ▼
             [ Log Parser & Normalizer ] ──► Pydantic validation (NormalizedEvent)
                          │
                          ▼
            [ SQLite Relational Storage ] ──► High-performance indexed storage
                          │
                          ▼
            [ Temporal Correlation Engine ] ──► 4 Correlation Strategies (300-600s window)
                          │
                          ▼
           [ Deterministic Detection Engine ] ──► 7 Active MITRE ATT&CK Rules
                          │
                          ▼
            [ Incident Management Engine ] ──► Entity clustering & severity scoring
                          │
                          ▼
         [ Autonomous AI Analyst & Auto-Pilot ] ──► Forensic reasoning & report authoring
                          │
                          ▼
           [ SOAR Active Containment Hub ] ──► Firewall blocks, account lockout, isolation
                          │
                          ▼
           [ SOC Command Center Dashboard ] ──► Streamlit dark-mode cybersecurity UI
```

---

## ⚡ Core Capabilities & Phases

### 1. Telemetry Ingestion & Normalization
* **Pydantic Validation:** Ingests and strictly validates raw logs into the `NormalizedEvent` schema.
* **Normalization:** Standardizes ISO 8601 timestamps, validates IP addresses/ports, and normalizes Windows Event Codes (4624, 4634, 4648, 4672, 4688, 4697).
* **Batch Ingestion:** High-speed batch saving commits thousands of events in single atomic transactions.

### 2. Temporal Event Correlation
Groups disparate security events across configurable sliding time windows (default: 300–600s):
1. **Source IP Correlation:** Clusters all actions originating from the same network address.
2. **User Activity Correlation:** Reconstructs user behavioral patterns across hosts.
3. **Multi-Port Connection Correlation:** Detects port sweep and network discovery behavior.
4. **Authentication Sequence Correlation:** Detects multi-stage attack chains:
   `Failed Logins` $\rightarrow$ `Successful Auth` $\rightarrow$ `Privilege Escalation` $\rightarrow$ `Process Execution`.

### 3. Deterministic Threat Detection (7 MITRE ATT&CK Rules)
* **RULE_BRUTE_FORCE_01 (`T1110`):** 5+ failed authentication events within the time window.
* **RULE_SUSPICIOUS_LOGIN_01 (`T1078`):** Successful authentication following multiple failed attempts.
* **RULE_PRIVILEGE_ESCALATION_01 (`T1068`):** Special administrative privileges assigned (Event 4672/4703 or sudo/admin).
* **RULE_SUSPICIOUS_PROCESS_01 (`T1059.001`):** Execution of LOLBins or malicious command lines (PowerShell `-enc`, mimikatz, certutil, whoami, vssadmin).
* **RULE_PORT_SCAN_01 (`T1046`):** Single source IP probing 5+ unique destination ports.
* **RULE_LATERAL_MOVEMENT_01 (`T1021`):** Explicit-credential network logons (Event 4648) across internal hosts.
* **RULE_SERVICE_INSTALL_01 (`T1543.003`):** Unauthorized Windows service creation (Event 4697).

### 4. Incident Management & Triage
* Clusters unassigned detections by attacker entity (source IP or username).
* Sets overall severity based on highest detection severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* Tracks full ticket lifecycles: `NEW` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `CLOSED`.

### 5. Hybrid AI Analyst Copilot
* **Dual-Engine Architecture:** Uses local Ollama (`qwen2.5:7b` / `llama3`) when available; automatically falls back to an offline deterministic expert matrix with zero delay if Ollama is unreachable.
* **MITRE ATT&CK Mapping:** Automatically maps alerts to standardized tactics and techniques.
* **Remediation Playbooks:** Authoring actionable step-by-step containment checklists for system administrators.
* **Forensic Reports:** Generates exportable, audit-grade Markdown dossiers.

### 6. SOAR Active Containment Hub (Automated Response)
* **Automated Firewall Drops (`BLOCK_IP`):** Automatically registers drop ACLs for attacking source IPs.
* **Account Quarantine (`QUARANTINE_USER`):** Invalidates active sessions and suspends compromised credentials.
* **Endpoint Isolation (`ISOLATE_HOST`):** Quarantines compromised hosts to a containment VLAN.
* **Process Termination (`TERMINATE_PROCESS`):** Flags malicious process trees for termination.
* **Instant Rollback:** Every containment action can be audited and reversed with a single click.

### 7. Autonomous AI-SOC Auto-Pilot
* **End-to-End Execution:** Runs the complete mission cycle (Ingest $\rightarrow$ Correlate $\rightarrow$ Detect $\rightarrow$ Cluster $\rightarrow$ AI Investigate $\rightarrow$ SOAR Contain $\rightarrow$ Audit Report) with a single click or API call.
* **MTTR Acceleration:** Slashes response time from the industry average of 4.8 hours down to $< 2.5$ seconds.
* **Consolidated Master Dossier:** Compiles an all-in-one Master SOC Audit Report ready for compliance export.

---

## 🚀 How to Run & Deploy

### Option 1: Streamlit Community Cloud (100% Free Public Deployment)
1. Fork or push this repository to your GitHub account (`your-username/AI-SOC`).
2. Log in to [share.streamlit.io](https://share.streamlit.io).
3. Select **"Deploy a public app from GitHub"**.
4. Set:
   * **Repository:** `your-username/AI-SOC`
   * **Branch:** `main`
   * **Main file path:** `dashboard/app.py`
5. Click **Deploy!** The dashboard includes an automatic background bootstrapper that starts the backend engine in the cloud automatically.

### Option 2: Docker & Docker Compose
Run both the FastAPI backend and Streamlit dashboard in containerized isolation:
```bash
docker compose up --build
```
* **Dashboard:** [http://localhost:8501](http://localhost:8501)
* **Backend API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

### Option 3: Local Windows Native Launch
Double-click the included batch script:
```cmd
run_project.bat
```
Or start manually in two terminal windows:
```bash
# Terminal 1: Backend API
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Streamlit Dashboard
python -m streamlit run dashboard/app.py --server.port 8501
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Health check endpoint |
| `POST` | `/api/logs/collect` | Ingest and normalize security event logs |
| `GET` | `/api/events` | Retrieve normalized telemetry events |
| `GET` | `/api/correlation` | Run temporal correlation engine |
| `POST` | `/api/detection/run` | Execute 7 deterministic detection rules |
| `GET` | `/api/detections` | Retrieve active threat detections |
| `POST` | `/api/incidents/generate` | Cluster detections into security incidents |
| `GET` | `/api/incidents` | List security incident tickets |
| `GET` | `/api/incidents/{id}` | Get incident dossier, timeline, and evidence |
| `PATCH`| `/api/incidents/{id}` | Update status, assigned analyst, or notes |
| `POST` | `/api/incidents/{id}/ai-analysis`| Trigger AI forensic investigation |
| `POST` | `/api/autonomous/run` | **Execute complete Autonomous AI-SOC Mission** |
| `GET` | `/api/autonomous/status` | Real-time Auto-Pilot operational metrics |
| `GET` | `/api/soar/actions` | List active and historical containment rules |
| `POST` | `/api/soar/execute` | Manually enforce containment rule |
| `POST` | `/api/soar/actions/{id}/rollback` | **Instant containment rollback / unblock** |
| `GET` | `/api/reports/master` | Generate consolidated Master Audit Report |

---

## 🧪 Testing & Quality Assurance

Run the comprehensive test suite (32 unit & integration tests):
```bash
python -m pytest tests/ -v
```

All 32 tests validate parsing, temporal correlation, detection rules, incident lifecycles, AI assistant fallback, autonomous auto-pilot cycles, and SOAR containment with 100% pass rate.
