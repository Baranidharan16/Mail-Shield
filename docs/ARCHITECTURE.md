# Architecture — Phase 1

## Design philosophy

**Modular monolith**, not microservices — appropriate for a 4-day hackathon build and a small team, while keeping clean internal boundaries so it can be split later if needed.

The forensic engine (`backend/app/forensic/`) is **pure Python with zero FastAPI/SQLAlchemy imports**. It takes raw bytes in and returns dataclasses out. This means:
- It is independently unit-testable (see `backend/tests/unit/`) without a database or running server.
- It could be reused in a CLI tool, a batch job, or a different web framework without modification.
- The API/service layer's only job is orchestration and persistence — not analysis logic.

## Data flow

```
Upload (.eml bytes)
  │
  ▼
app/utils/storage.py     — validate extension/size, UUID-named storage, path-traversal-safe
  │
  ▼
app/services/investigation_service.py :: create_investigation()
  │   creates Investigation row (status=QUEUED), hashes evidence (SHA-256)
  ▼
FastAPI BackgroundTask → app/services/investigation_service.py :: run_analysis()
  │   status → PROCESSING
  ▼
app/forensic/engine.py :: run_forensic_analysis()
  │
  ├─ email_parser.py        → ParsedEmail (headers, body, attachments)
  ├─ received_parser.py     → ReceivedHop[] (earliest-first)
  ├─ auth_analyzer.py       → AuthenticationAnalysis (SPF/DKIM/DMARC + alignment)
  ├─ header_anomaly.py      → Finding[] (11 deterministic rules)
  ├─ url_analyzer.py        → URLFinding[] (extraction + risk scoring, no fetching)
  ├─ domain_analyzer.py     → DomainFinding[] (lookalike similarity, punycode, TLD)
  ├─ ip_extractor.py        → IPFinding[] (from hops + IP-based URLs)
  ├─ social_engineering.py  → ContentIndicator[] (keyword/pattern based)
  └─ scoring.py             → ThreatScoreResult (7-dimension noisy-OR, weighted, configurable)
  │
  ▼
investigation_service.py persists every result across 11 related tables,
builds the structured JSON report, sets status=COMPLETED (or FAILED with
error_message on any exception — never silently swallowed)
  │
  ▼
Frontend polls GET /investigations/{id} until status is COMPLETED/FAILED,
then renders the full dashboard from real backend data.
```

## Directory structure

```
backend/
  app/
    main.py              FastAPI app, middleware, startup
    core/
      config.py           Pydantic-settings, env-driven
      rate_limit.py        in-memory sliding-window limiter
      error_handlers.py    global exception handler (never leaks tracebacks)
    api/v1/
      investigations.py    all investigation endpoints
      health.py
    schemas/
      investigation.py     Pydantic request/response models
    services/
      investigation_service.py   orchestration + persistence
    forensic/               <-- pure-Python engine, see above
    models/
      investigation.py     SQLAlchemy ORM (11 tables)
    database/
      session.py           engine/session, works with SQLite or Postgres
    utils/
      storage.py           secure file storage (UUID naming, path-traversal guard)
  tests/
    unit/                  44 tests, one file per forensic module
    integration/            9 tests, full API workflow against real .eml files
    test_data/              synthetic .eml fixtures

frontend/
  src/
    api/client.ts          typed Axios client
    types/investigation.ts  TypeScript types mirroring backend schemas
    components/             Layout, ThreatGauge, Badges
    pages/                  Dashboard, Upload, History, InvestigationDetail
```

## Database schema

11 tables, one investigation aggregate root:

`investigations` (1) ── (1) `email_metadata`
                 ── (N) `email_headers`
                 ── (N) `received_hops`
                 ── (1) `authentication_results`
                 ── (N) `urls`
                 ── (N) `domains`
                 ── (N) `ip_addresses`
                 ── (N) `indicators` (social engineering)
                 ── (N) `findings` (header anomalies)
                 ── (1) `risk_scores`
                 ── (1) `reports`

UUID primary keys stored as CHAR(36) so the same models run unmodified on both SQLite (local/sandbox dev) and PostgreSQL (production, via `docker-compose.yml`).

## Real-time processing model

Analysis runs as a FastAPI `BackgroundTask` triggered immediately on upload — the API returns `202`-equivalent (`201` with `status=QUEUED`) instantly, and the frontend polls `GET /investigations/{id}` every 500ms until `status` becomes `COMPLETED` or `FAILED`. The progress UI reflects the investigation's real database `status` column — `QUEUED → PROCESSING → COMPLETED/FAILED` — never a simulated/fake progress bar. This same job-state model is what a future SSE/WebSocket push layer (Phase 2) would sit on top of without changing the state machine.

## Why a modular monolith and not microservices

- All processing for a single `.eml` is inherently sequential and CPU-light (regex/parsing, no heavy ML in Phase 1) — no benefit from service decomposition yet.
- Reduces operational complexity for a 4-day build: one Postgres, one backend container, one frontend container.
- The forensic engine's clean module boundaries mean it *could* be extracted into a separate service later (e.g., a dedicated scoring microservice in Phase 3) with minimal rework.
