# Aegis-Web Architecture

Aegis-Web is an automated access-control security assessment platform designed specifically to detect OWASP A01:2021 (Broken Access Control) flaws, including Horizontal Privilege Escalation (IDOR), Vertical Privilege Escalation, and Unauthenticated Access to protected endpoints.

---

## 1. System Component Architecture

```mermaid
graph TD
    subgraph Client ["Client Browser"]
        UI["React 19 + TypeScript SPA<br/>(Vite, React Router, DiffViewer)"]
    end

    subgraph Backend ["Backend API & Storage"]
        API["FastAPI 0.115+<br/>(/api/v1 - Auth, Targets, Scans, Findings)"]
        DB[("PostgreSQL 16 Database<br/>(Users, Targets, Accounts, Scans, Events, Findings, Audit)")]
    end

    subgraph Engine ["Scan Engine & Queue"]
        WORKER["Worker Daemon<br/>(app.worker.runner)"]
        SCANNER["Aegis Scanner Engine<br/>(aegis_scanner.modules.access_control)"]
        RECORDER["Browser Crawler & Recorder<br/>(Playwright Chromium)"]
        REPLAYER["Differential Replayer<br/>(httpx sync client)"]
        GUARD["SSRF Network Guard<br/>(net_guard.py)"]
    end

    subgraph TargetApp ["Target System"]
        TARGET["Web Application Under Test<br/>(Labs / Production)"]
    end

    UI -->|JSON REST API & Bearer JWT| API
    API -->|SQLAlchemy 2.0 ORM| DB
    WORKER -->|claim_next_job with_for_update| DB
    WORKER -->|run_access_control_scan| SCANNER
    SCANNER -->|record_account| RECORDER
    RECORDER -->|SSRF-Checked Outbound Navigation| TARGET
    SCANNER -->|send as role / anonymous| REPLAYER
    REPLAYER -->|IP-Pinned safe_get & Replays| TARGET
    GUARD -.->|Enforces Host & IP Boundary| RECORDER
    GUARD -.->|Enforces Host & IP Boundary| REPLAYER
    WORKER -->|Stream progress_events & write findings| DB
    API -->|GET /scans/{id}/events polling| UI
```

---

## 2. End-to-End Scan Lifecycle Walkthrough

Below is the step-by-step trace of a complete assessment scan, from user initiation to finding triage:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant UI as Frontend (React)
    participant API as Backend (FastAPI)
    participant DB as PostgreSQL 16
    participant Worker as Scan Worker
    participant Scanner as Access Control Engine
    participant Target as Target Application

    Analyst->>UI: Clicks "Start Access Control Assessment"
    UI->>API: POST /api/v1/scans (target_id, options)
    Note over API: app.services.scan_service:create_scan_job
    API->>DB: INSERT INTO scans (status='queued', progress_percent=0)
    API-->>UI: 202 Accepted (Scan object)
    UI->>UI: Redirects to /scans/:id & begins polling events

    loop Polling Loop (Worker idle)
        Worker->>DB: app.worker.runner:claim_next_job (SELECT FOR UPDATE SKIP LOCKED)
    end
    DB-->>Worker: Returns claimed Scan row (status='running')

    Worker->>DB: Decrypts account passwords in-memory (app.core.crypto:decrypt_secret)
    Worker->>Scanner: aegis_scanner.modules.access_control:run_access_control_scan

    %% Crawl Phase
    critical Browser Recording Phase
        Scanner->>Target: Playwright logs into each account sequentially
        Scanner->>Target: Crawler explores reachable links and records requests
        Scanner-->>Worker: Progress callback ("recording", 0-45%)
        Worker->>DB: INSERT INTO scan_events & UPDATE scans.progress
    end

    %% Planning Phase
    critical Planning & App Shell Detection
        Scanner->>Target: Anonymous HTTP GET to base_url to capture SPA shell
        Scanner->>Scanner: aegis_scanner.replay.planner:build_replay_plan
        Note over Scanner: Filter static assets, non-GET, logout endpoints
    end

    %% Stability Phase
    critical Control Replay & Stability Scoring
        Scanner->>Target: Replay request as original role to test response stability
        Scanner->>Scanner: diff.scoring:similarity(orig, control)
        Scanner-->>Worker: Progress callback ("stability", 50-60%)
        Worker->>DB: INSERT INTO scan_events
    end

    %% Replay & Scoring Phase
    critical Differential Cross-Role Testing
        Scanner->>Target: Replay request as lower privilege role, peer role, and anonymous
        Scanner->>Scanner: diff.normalize:normalize_body & diff.compare:similarity
        Scanner->>Scanner: diff.scoring:is_finding_candidate & confidence_score
        Scanner-->>Worker: Progress callback ("replaying", 60-95%)
        Worker->>DB: INSERT INTO scan_events
    end

    %% Finalizing
    critical Deduplication & Persistence
        Scanner->>Scanner: Deduplicate by fingerprint tuple (type, method, signature, source, tested)
        Scanner-->>Worker: Returns ScanResult (endpoints, findings, stats)
        Worker->>Worker: app.core.fingerprint:compute_fingerprint
        Worker->>Worker: aegis_scanner.redact:redact_headers / redact_body
        Worker->>DB: INSERT INTO endpoints, INSERT INTO findings, status='completed'
        Worker->>DB: record_audit (action="scan.finish")
    end

    UI->>API: GET /api/v1/scans/:id & GET /api/v1/scans/:id/findings
    API->>DB: SELECT findings WHERE scan_id = :id
    DB-->>API: List of findings
    API-->>UI: Findings JSON
    UI->>Analyst: Displays findings in FindingsTable with DiffViewer
```

---

## 3. Function & Module Call Mapping

1. **Target Registration:** `backend/app/api/targets.py:create_target`
   - Validates URL syntax with `aegis_scanner.net_guard:validate_url(allow_private=True, syntax_only=True)`.
   - Generates random token with `app.core.ownership:new_ownership_token`.
2. **Account Onboarding:** `backend/app/api/targets.py:create_account`
   - Encrypts password at rest using `app.core.crypto:encrypt_secret` (AES-128-CBC + HMAC-SHA256 Fernet).
3. **Domain Verification:** `backend/app/api/targets.py:verify_target`
   - Invokes `app.core.ownership:verify_ownership` which triggers outbound `aegis_scanner.net_guard:safe_get` with strict public IP validation.
4. **Scan Submission:** `backend/app/api/scans.py:start_scan`
   - Rate limited by `app.core.rate_limit:RateLimiter` (10 scans/hour).
   - Validates prerequisites with `app.services.scan_service:create_scan_job`.
5. **Job Queue Execution:** `backend/app/worker/runner.py:process_one_job`
   - Atomically claims oldest job via `claim_next_job` using `.with_for_update(skip_locked=True)`.
   - Spawns crawl with `aegis_scanner.modules.access_control:run_access_control_scan`.
6. **Crawler Recording:** `scanner/aegis_scanner/recorder/crawler.py:crawl`
   - Intercepts network routes using Playwright sync API.
   - Extracts URL signatures with `aegis_scanner.signature:make_signature`.
7. **Replay Engine:** `scanner/aegis_scanner/replay/replayer.py:Replayer.send`
   - Issues requests with custom session cookies/headers using `httpx.Client`.
8. **Differential Analysis:**
   - `aegis_scanner.diff.normalize:normalize_body`: Strips volatile timestamps, CSRF tokens, dynamic IDs.
   - `aegis_scanner.diff.compare:similarity`: Computes structural ratio for JSON and SequenceMatcher for HTML.
   - `aegis_scanner.diff.scoring:is_finding_candidate`: Applies Candidate Rules 0–4.
   - `aegis_scanner.diff.scoring:confidence_score`: Calculates deterministic confidence score (0–100).
9. **Triage & Comparison:**
   - `app.api.findings.py:update_finding`: Handles analyst status changes (`open`, `false_positive`, `fixed`, `accepted`).
   - `app.services.compare_service:compare_scans`: Performs set operations on 16-hex canonical fingerprints.
