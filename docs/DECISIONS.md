# Architectural Decisions Log

This document records decisions made during implementation when the specification allowed choices or required disambiguation. Format: `Phase N: <decision> — <reason>`.

---

Phase 1: `make_signature` outputs uppercase method (e.g. `GET /orders/{id}`) — spec examples and ground-truth contracts explicitly require uppercase `GET /...`.
Phase 3: `pythonpath = . backend` in `pytest.ini` — allows test suites to import `labs.vulnerable_app` directly without module import errors.
Phase 4: Candidate rule 0 evaluates `norm_orig.has_content` (flat dictionary non-empty for JSON, text non-empty for HTML) — correctly discards empty bodies or responses containing only volatile noise like tokens.
Phase 5: Database schema uses generic SQLAlchemy `JSON` types and integer PKs — allows unit tests to run against in-memory SQLite while PostgreSQL 16 runs in production.

