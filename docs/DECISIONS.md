# Architectural Decisions Log

This document records decisions made during implementation when the specification allowed choices or required disambiguation. Format: `Phase N: <decision> — <reason>`.

---

Phase 1: `make_signature` outputs uppercase method (e.g. `GET /orders/{id}`) — spec examples and ground-truth contracts explicitly require uppercase `GET /...`.

