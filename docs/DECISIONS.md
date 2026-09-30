# Architectural Decisions Log

This document records decisions made during implementation when the specification allowed choices or required disambiguation. Format: `Phase N: <decision> — <reason>`.

---

Phase 1: `make_signature` outputs uppercase method (e.g. `GET /orders/{id}`) — spec examples and ground-truth contracts explicitly require uppercase `GET /...`.
Phase 3: `pythonpath = . backend` in `pytest.ini` — allows test suites to import `labs.vulnerable_app` directly without module import errors.

