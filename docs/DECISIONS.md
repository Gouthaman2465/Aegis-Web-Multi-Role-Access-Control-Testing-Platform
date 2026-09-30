# Architectural Decisions Log

This document records decisions made during implementation when the specification allowed choices or required disambiguation. Format: `Phase N: <decision> — <reason>`.

---

Phase 1: `make_signature` outputs uppercase method (e.g. `GET /orders/{id}`) — spec examples and ground-truth contracts explicitly require uppercase `GET /...`.
Phase 3: `pythonpath = . backend` in `pytest.ini` — allows test suites to import `labs.vulnerable_app` directly without module import errors.
Phase 4: Candidate rule 0 evaluates `norm_orig.has_content` (flat dictionary non-empty for JSON, text non-empty for HTML) — correctly discards empty bodies or responses containing only volatile noise like tokens.
Phase 5: Database schema uses generic SQLAlchemy `JSON` types and integer PKs — allows unit tests to run against in-memory SQLite while PostgreSQL 16 runs in production.
Phase 6: `validate_url` supports `syntax_only=True` — avoids DNS timeouts during target creation while reserving strict resolution and SSRF checks for scan/verification time.
Phase 7: `addopts = --import-mode=importlib` in `pytest.ini` — allows multiple test suites across `backend/tests/` and `scanner/tests/` to share module basenames like `test_compare.py` without import collision.
Phase 8: Vite dev and preview proxies configured for `/api` to backend port 8000; session storage used for tab-scoped JWT token to avoid cross-tab CSRF/CORS complexity while keeping security boundary clear.
Phase 9: Comprehensive Hard Constraints verification completed mapping all 20 architectural constraints to enforcing code and test files.
Phase 10: Discovered same-origin GET endpoints without `{}` placeholders fed back into replay pipeline as synthetic `RecordedRequest`s — allows normal stability, cross-role replay, candidate filtering, and scoring to discover hidden access control flaws like `GET /api/legacy/export` without duplicating replay logic.
Phase 11: Dynamic random-token soft-404 baseline probe with similarity threshold < 0.9 before checking exposed files — suppresses false-positive findings on Single Page Applications and custom 404 handlers while guaranteeing detection of genuine `.git/HEAD` and `.env` files.

---

## Hard Constraints Verification Checklist

| # | Constraint Description | Enforcing Implementation File | Automated Verification Test |
|---|---|---|---|
| 1 | Python 3.11+ / React 19 + TypeScript (Vite `react-ts`) | `pyproject.toml`, `frontend/package.json` | `npm run build`, `npm test`, pytest |
| 2 | PostgreSQL 16 (Docker) / SQLAlchemy 2.0 / Alembic (generic JSON) | `backend/app/db.py`, `backend/app/models/*.py` | `backend/tests/conftest.py`, `alembic upgrade head` |
| 3 | No Redis, no Celery: Scans table job queue with `FOR UPDATE SKIP LOCKED` | `backend/app/worker/runner.py` | `backend/tests/test_worker.py::test_process_one_job_happy_path` |
| 4 | Docker used strictly for PostgreSQL and optional Juice Shop | `docker-compose.yml` | `docker compose up -d postgres` health check |
| 5 | Playwright Chromium (sync) & httpx (sync) | `scanner/aegis_scanner/recorder/crawler.py`, `replayer.py` | `scanner/tests/test_recorder_e2e.py`, `test_e2e_access_control.py` |
| 6 | No paid services or cloud provisioning; fully local | Project root config, `docker-compose.yml` | Entire test suite executes offline |
| 7 | Multi-layer SSRF protection on every outbound request | `scanner/aegis_scanner/net_guard.py` | `scanner/tests/test_net_guard.py` (19 test cases) |
| 8 | Target ownership check: scans run only on `verified` or `lab` targets | `backend/app/services/scan_service.py`, `core/ownership.py` | `backend/tests/test_scans_api.py::test_create_scan_validation_and_requirements` |
| 9 | Credentials encrypted at rest with Fernet, decrypted in-memory only | `backend/app/core/crypto.py`, `backend/app/worker/runner.py` | `backend/tests/test_crypto.py`, `backend/tests/test_targets_api.py` |
| 10 | Platform user passwords hashed with Argon2id; no plaintext stored | `backend/app/core/security.py`, `backend/app/api/auth.py` | `backend/tests/test_security.py::test_password_hashing_argon2id` |
| 11 | JWT HS256 pinned, exp & sub required, weak secret (<32 chars) rejected | `backend/app/core/security.py`, `backend/app/config.py` | `backend/tests/test_security.py::test_jwt_alg_none_and_wrong_algorithm_rejected` |
| 12 | Data isolation: queries scoped to `owner_id`, cross-user access returns 404 | `backend/app/api/targets.py`, `scans.py`, `findings.py` | `backend/tests/test_isolation.py::test_user_b_cannot_access_user_a_objects` |
| 13 | Untrusted output rendered as text only; no `dangerouslySetInnerHTML` | `frontend/src/components/DiffViewer.tsx`, `FindingsTable.tsx` | `frontend/src/components/DiffViewer.test.tsx` |
| 14 | Defensive redaction of Authorization, Cookie, and sensitive JSON keys | `scanner/aegis_scanner/redact.py`, `worker/runner.py` | `scanner/tests/test_redact.py`, `scanner/tests/test_e2e_access_control.py` |
| 15 | In-memory sliding window rate limits: login (5/min), scan creation (10/hr) | `backend/app/core/rate_limit.py`, `backend/app/deps.py` | `backend/tests/test_rate_limit.py`, `backend/tests/test_auth_api.py` |
| 16 | Safe replay: GET only, crawler skips logout/signout/delete/destroy routes | `scanner/aegis_scanner/replay/planner.py`, `crawler.py` | `scanner/tests/test_planner.py`, `scanner/tests/test_recorder_e2e.py` |
| 17 | Hostile-target hardening: body caps (200KB/2MB), timeouts, per-scan limit | `scanner/aegis_scanner/replay/replayer.py`, `worker/runner.py` | `backend/tests/test_worker.py::test_process_one_job_timeout_path` |
| 18 | Security headers on every response: nosniff, no-store, no-referrer | `backend/app/main.py` | `backend/tests/test_security.py::test_security_headers_present` |
| 19 | Pydantic v2 request body validation; no raw SQL anywhere | `backend/app/schemas/*.py`, `backend/app/api/*.py` | `backend/tests/test_targets_api.py`, `test_scans_api.py` |
| 20 | Mandatory authorization and ethics notices in README, UI, NewScanPage | `README.md`, `frontend/src/pages/NewScanPage.tsx` | UI verification walkthrough in `scripts/verify_demo_flow.py` |

