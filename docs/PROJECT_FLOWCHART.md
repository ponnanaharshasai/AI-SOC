    # AI-SOC — Project Architecture Flowchart

    ## 1. High-Level End-to-End Pipeline

    ```mermaid
    flowchart TD
        subgraph INPUT["📂 Data Sources"]
            A1["Splunk BOTS v1 CSV\n(15.8 GB / 13.4M rows)"]
            A2["Sample JSONL Logs\n(sample_logs/*.jsonl)"]
        end

        subgraph PHASE2["Phase 2 — Log Collection"]
            B1["BaseCollector Interface\n(backend/collectors/base.py)"]
            B2["SampleLogCollector\n(backend/collectors/sample.py)"]
            B3["BOTSv1 Extraction Script\n(scripts/extract_botsv1.py)"]
        end

        subgraph PHASE3["Phase 3 — Parsing, Normalization & Storage"]
            C1["LogParser\n(backend/parser/parser.py)"]
            C2["normalize_raw_event\n(backend/parser/normalizer.py)"]
            C3["NormalizedEvent Pydantic Model\n(backend/parser/models.py)"]
            C4[("SQLite Database\nsoc_data.db\nnormalized_events table")]
        end

        subgraph PHASE4["Phase 4 — Event Correlation"]
            D0["CorrelationEngine\n(backend/correlation/engine.py)"]
            D1["Rule 1: Source IP Correlation"]
            D2["Rule 2: User Activity Correlation"]
            D3["Rule 3: Network Multi-Port Correlation"]
            D4["Rule 4: Auth Sequence Correlation"]
            D5["Deduplicate & Build CorrelationResult"]
        end

        subgraph PHASE5["Phase 5 — Threat Detection"]
            E0["DetectionEngine\n(backend/detection/engine.py)"]
            E1["RULE_BRUTE_FORCE_01\nT1110 / HIGH"]
            E2["RULE_SUSPICIOUS_LOGIN_01\nT1078 / HIGH"]
            E3["RULE_PRIVILEGE_ESCALATION_01\nT1068 / CRITICAL"]
            E4["RULE_SUSPICIOUS_PROCESS_01\nT1059.001 / HIGH"]
            E5["RULE_PORT_SCAN_01\nT1046 / MEDIUM"]
            E6["RULE_LATERAL_MOVEMENT_01\nT1021 / HIGH"]
            E7["RULE_SERVICE_INSTALL_01\nT1543.003 / CRITICAL"]
            E8[("SQLite\ndetections table")]
        end

        subgraph PHASE6["Phase 6 — Incident Management"]
            F1["IncidentEngine\n(backend/incidents/engine.py)"]
            F2["Cluster by Attacker Entity\n(source_ip / username)"]
            F3["Assign Severity\n(max detection severity)"]
            F4["Create Incident Ticket\nNEW → INVESTIGATING → CONTAINED → CLOSED"]
            F5[("SQLite\nincidents table")]
        end

        subgraph PHASE7["Phase 7 — AI-Assisted Analysis"]
            G1["AIAssistant\n(backend/ai/assistant.py)"]
            G2{"Ollama LLM\navailable?"}
            G3["Ollama qwen2.5:7b / llama3\n(localhost:11434)"]
            G4["Deterministic Expert\nFallback Engine"]
            G5["MITRE ATT&CK Mapping\n(7 Techniques)"]
            G6["Remediation Playbook\nGeneration"]
            G7["Markdown Incident\nReport Generation"]
        end

        subgraph PHASE8["Phase 8 — SOC Dashboard"]
            H1["Streamlit Dashboard\n(dashboard/app.py)"]
            H2["📊 SOC Command Center\nMetrics & Detection Feed"]
            H3["🤖 Incident Investigation\n& AI Workbench"]
            H4["🔍 Telemetry Explorer\nEvent Search & Filter"]
            H5["📥 Download Report (.md)"]
        end

        subgraph API["⚡ FastAPI Backend - backend/main.py"]
            API1["GET  /api/logs/sample"]
            API2["POST /api/logs/collect"]
            API3["GET  /api/events"]
            API4["GET  /api/correlation"]
            API5["POST /api/detection/run"]
            API6["GET  /api/detections"]
            API7["POST /api/incidents/generate"]
            API8["GET  /api/incidents"]
            API9["GET  /api/incidents/{id}"]
            API10["PATCH /api/incidents/{id}"]
            API11["POST /api/incidents/{id}/ai-analysis"]
        end

        subgraph TESTS["🧪 Test Suite - 29 Tests"]
            T1["test_collectors.py"]
            T2["test_parser.py"]
            T3["test_correlation.py"]
            T4["test_detection.py"]
            T5["test_incidents.py"]
            T6["test_ai_assistant.py"]
            T7["test_botsv1_pipeline.py"]
            T8["test_pipeline.py"]
        end

        %% Main Pipeline Flow
        A1 -->|extract_botsv1.py| B3
        B3 -->|Generates JSONL| A2
        A2 --> B2
        B1 -.->|Interface| B2
        B2 -->|Raw Event Dicts| C1
        C1 --> C2
        C2 --> C3
        C3 -->|Validated Events| C4

        C4 -->|Query Events| D0
        D0 --> D1 & D2 & D3 & D4
        D1 & D2 & D3 & D4 --> D5

        C4 -->|Raw Events| E0
        D5 -->|CorrelationResults| E0
        E0 --> E1 & E2 & E3 & E4 & E5 & E6 & E7
        E1 & E2 & E3 & E4 & E5 & E6 & E7 --> E8

        E8 -->|Unassigned Detections| F1
        F1 --> F2 --> F3 --> F4 --> F5

        F5 -->|Incident + Detections + Events| G1
        G1 --> G2
        G2 -->|Yes| G3
        G2 -->|No| G4
        G3 --> G5
        G4 --> G5
        G5 --> G6 --> G7

        G7 -->|Analysis Result| H1
        H1 --> H2 & H3 & H4
        H3 --> H5

        %% API connections
        API1 -.-> B2
        API2 -.-> C1
        API3 -.-> C4
        API4 -.-> D0
        API5 -.-> E0
        API6 -.-> E8
        API7 -.-> F1
        API8 -.-> F5
        API9 -.-> F5
        API10 -.-> F5
        API11 -.-> G1

        %% Test connections
        T1 -.-> B2
        T2 -.-> C1
        T3 -.-> D0
        T4 -.-> E0
        T5 -.-> F1
        T6 -.-> G1
        T7 -.-> B3
        T8 -.-> API2
    ```

    ---

    ## 2. Data Flow Diagram — How a Single Log Event Travels

    ```mermaid
    flowchart LR
        subgraph Source
            LOG["📄 Raw JSONL Line"]
        end

        subgraph Collection
            READ["Read & JSON Parse"]
            VALIDATE["File Existence\n& Permission Check"]
        end

        subgraph Parsing
            NORM["Normalize:\n• UUID assignment\n• Lowercase status/type\n• Port to int\n• IP validation"]
            PYDANTIC["Pydantic Validation\n(NormalizedEvent)"]
        end

        subgraph Storage
            DB[("SQLite\nnormalized_events\nIndexed: timestamp,\nsource_ip, event_type")]
        end

        subgraph Correlation
            QUERY["Query by\nsource_ip / username /\nevent_type"]
            GROUP["Group by field\n+ Time Window"]
            CLUSTER["Cluster by\ntemporal proximity"]
        end

        subgraph Detection
            SINGLE["Single-Event\nRule Evaluation"]
            CORR_EVAL["Correlation-Based\nRule Evaluation"]
            DEDUP["Deduplicate\nDetections"]
            SAVE_DET[("Save to\ndetections table")]
        end

        subgraph Incidents
            FILTER_UNASSIGNED["Filter Unassigned\nDetections"]
            GROUP_ENTITY["Group by\nAttacker Entity"]
            CREATE_INC["Create Incident\nTicket"]
            SAVE_INC[("Save to\nincidents table")]
        end

        subgraph AI_Analysis
            FETCH["Fetch Incident +\nDetections + Events"]
            LLM{"Try Ollama"}
            AI_OK["LLM Analysis"]
            FALLBACK["Expert Playbook\nFallback"]
            MITRE_MAP["Map MITRE\nATT&CK"]
            REMEDIATION["Generate\nRemediation"]
            REPORT["Build Markdown\nReport"]
        end

        subgraph Dashboard
            DISPLAY["📊 Streamlit UI"]
        end

        LOG --> VALIDATE --> READ --> NORM --> PYDANTIC --> DB
        DB --> QUERY --> GROUP --> CLUSTER
        DB --> SINGLE
        CLUSTER --> CORR_EVAL
        SINGLE --> DEDUP
        CORR_EVAL --> DEDUP
        DEDUP --> SAVE_DET
        SAVE_DET --> FILTER_UNASSIGNED --> GROUP_ENTITY --> CREATE_INC --> SAVE_INC
        SAVE_INC --> FETCH --> LLM
        LLM -->|Available| AI_OK --> MITRE_MAP
        LLM -->|Offline| FALLBACK --> MITRE_MAP
        MITRE_MAP --> REMEDIATION --> REPORT --> DISPLAY
    ```

    ---

    ## 3. Detection Rules & MITRE ATT&CK Mapping

    ```mermaid
    flowchart TD
        subgraph Rules["7 Detection Rules"]
            R1["RULE_BRUTE_FORCE_01\n5+ failed logins / same IP"]
            R2["RULE_SUSPICIOUS_LOGIN_01\nSuccess after 3+ failures"]
            R3["RULE_PRIVILEGE_ESCALATION_01\nEvent 4672/4703 / sudo su"]
            R4["RULE_SUSPICIOUS_PROCESS_01\n25+ malicious commands"]
            R5["RULE_PORT_SCAN_01\n5+ unique dest ports"]
            R6["RULE_LATERAL_MOVEMENT_01\nExplicit credential logons"]
            R7["RULE_SERVICE_INSTALL_01\nMalicious service install"]
        end

        subgraph MITRE["MITRE ATT&CK"]
            M1["T1110\nBrute Force\nCredential Access"]
            M2["T1078\nValid Accounts\nInitial Access"]
            M3["T1068\nPrivilege Escalation\nPrivilege Escalation"]
            M4["T1059.001\nPowerShell\nExecution"]
            M5["T1046\nNetwork Discovery\nDiscovery"]
            M6["T1021\nRemote Services\nLateral Movement"]
            M7["T1543.003\nWindows Service\nPersistence"]
        end

        subgraph Severity
            S_CRIT["🔴 CRITICAL"]
            S_HIGH["🟠 HIGH"]
            S_MED["🟡 MEDIUM"]
        end

        R1 --> M1 --> S_HIGH
        R2 --> M2 --> S_HIGH
        R3 --> M3 --> S_CRIT
        R4 --> M4 --> S_HIGH
        R5 --> M5 --> S_MED
        R6 --> M6 --> S_HIGH
        R7 --> M7 --> S_CRIT
    ```

    ---

    ## 4. Incident Lifecycle State Machine

    ```mermaid
    stateDiagram-v2
        [*] --> NEW: Detections clustered\nby attacker entity
        NEW --> INVESTIGATING: Analyst picks up\n(PATCH /api/incidents/id)
        INVESTIGATING --> CONTAINED: Containment actions\nexecuted
        CONTAINED --> CLOSED: Post-incident\nreview complete
        INVESTIGATING --> CLOSED: False positive\ndismissed

        state NEW {
            [*] --> AutoGrouped: IncidentEngine clusters\nunassigned detections
            AutoGrouped --> SeverityAssigned: Max severity\nfrom detections
            SeverityAssigned --> TicketCreated: Title and summary\ngenerated
        }

        state INVESTIGATING {
            [*] --> AIAnalysis: POST /api/incidents/id/ai-analysis
            AIAnalysis --> MITREMapping: Map detection types\nto techniques
            MITREMapping --> RemediationPlan: Generate playbook
            RemediationPlan --> ReportGenerated: Build markdown report
        }
    ```

    ---

    ## 5. AI Analysis Decision Flow

    ```mermaid
    flowchart TD
        START["POST /api/incidents/id/ai-analysis"] --> FETCH["Fetch Incident\nfrom SQLite"]
        FETCH --> FOUND{"Incident\nexists?"}
        FOUND -->|No| ERR404["Return 404"]
        FOUND -->|Yes| DET["Fetch linked Detections\n& raw Events"]
        DET --> TRY["Try Ollama at\nlocalhost:11434"]
        TRY --> AVAIL{"LLM\nreachable?"}
        AVAIL -->|Yes| LLM_CALL["Send prompt\nto qwen2.5:7b"]
        AVAIL -->|No| EXPERT["Use Deterministic\nExpert Playbook Engine"]
        LLM_CALL --> SUMMARY["Build Executive\nSummary"]
        EXPERT --> SUMMARY
        SUMMARY --> MITRE_LOOKUP["Lookup MITRE\nATT&CK Catalog"]
        MITRE_LOOKUP --> REMED["Compile Remediation\nPlaybook Steps"]
        REMED --> REPORT["Generate Full\nMarkdown Report"]
        REPORT --> SAVE["Update Incident in DB\n(summary + remediation notes)"]
        SAVE --> RETURN["Return AIAnalysisResult"]
    ```

    ---

    ## 6. Project Directory Structure

    ```mermaid
    flowchart TD
        ROOT["AI-SOC/"] --> BE["backend/"]
        ROOT --> DASH["dashboard/"]
        ROOT --> SCRIPTS["scripts/"]
        ROOT --> TESTS["tests/"]
        ROOT --> SAMPLE["sample_logs/"]
        ROOT --> ML["MachineLearningCSV/"]
        ROOT --> DOCS["docs/"]
        ROOT --> DB_FILE[("soc_data.db")]
        ROOT --> README["README.md"]
        ROOT --> SUMMARY["PROJECT_SUMMARY.txt"]
        ROOT --> REVIEW["PROJECT_REVIEW_GUIDE.md"]
        ROOT --> REQS["requirements.txt"]

        BE --> MAIN["main.py\n(FastAPI App)"]
        BE --> CONFIG["config.py\n(Pydantic Settings)"]
        BE --> COLL["collectors/\nbase.py, sample.py"]
        BE --> PARSER["parser/\nparser.py, normalizer.py, models.py"]
        BE --> DATABASE["database/\nmanager.py"]
        BE --> CORR["correlation/\nengine.py, models.py"]
        BE --> DETECT["detection/\nengine.py, rules.py, models.py"]
        BE --> INC["incidents/\nengine.py, models.py"]
        BE --> AI["ai/\nassistant.py, models.py, prompts.py"]

        DASH --> APP["app.py\n(Streamlit)"]
        SCRIPTS --> EXTRACT["extract_botsv1.py"]
        TESTS --> T_COLL["test_collectors.py"]
        TESTS --> T_PARSE["test_parser.py"]
        TESTS --> T_CORR["test_correlation.py"]
        TESTS --> T_DET["test_detection.py"]
        TESTS --> T_INC["test_incidents.py"]
        TESTS --> T_AI["test_ai_assistant.py"]
        TESTS --> T_BOTS["test_botsv1_pipeline.py"]
        TESTS --> T_PIPE["test_pipeline.py"]
    ```

    ---

    ## 7. Future Development Roadmap

    ```mermaid
    flowchart LR
        subgraph Current["✅ Implemented"]
            C1["Batch Log Ingestion"]
            C2["7 Detection Rules"]
            C3["4 Correlation Strategies"]
            C4["Incident Management"]
            C5["AI + Expert Fallback"]
            C6["Streamlit Dashboard"]
        end

        subgraph FutureA["Phase A: Live Ingestion"]
            FA1["Syslog UDP Listener\n(RFC 5424, port 514)"]
            FA2["REST Log Push API\nPOST /api/logs/ingest"]
            FA3["Async Background\nWorker Queue"]
        end

        subgraph FutureB["Phase B: SOAR"]
            FB1["Firewall IP Block\nScript Generation"]
            FB2["Host Isolation\nCommands"]
            FB3["Account Lockout\n& Session Revocation"]
            FB4["Dashboard Approval\nModal"]
        end

        subgraph FutureC["Phase C: ML IDS"]
            FC1["CIC-IDS2017 Feature\nEngineering"]
            FC2["XGBoost / LightGBM\n/ Isolation Forest"]
            FC3["Anomaly Score +\nRule Correlation"]
        end

        subgraph FutureD["Phase D: CTI"]
            FD1["AbuseIPDB / VirusTotal\nAPI Lookups"]
            FD2["Local SQLite Cache\n(24h TTL)"]
        end

        subgraph FutureE["Phase E: Visualization"]
            FE1["Interactive Attack\nKill-Chain Graphs"]
            FE2["WebSocket Real-Time\nAlert Feed"]
        end

        C1 --> FA1
        C1 --> FA2
        C2 --> FC3
        C5 --> FB1
        C6 --> FB4
        C6 --> FE1
        C6 --> FE2
        C4 --> FD1
    ```
