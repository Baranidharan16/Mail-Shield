# Phase 1 — Definition of Done

## Checklist (all verified, not just claimed)

- [x] Frontend runs — `npm run dev` / `npm run build` succeed; verified served on port 5173 via `npm run preview` in this session
- [x] Backend runs — `uvicorn app.main:app` verified starting and serving on port 8000
- [x] Database runs — SQLite verified locally; PostgreSQL wired via `docker-compose.yml` (same ORM models, portable)
- [x] API documentation works — FastAPI auto-generates Swagger UI at `/docs`
- [x] Real `.eml` upload works — verified via live `curl` upload of `test_data/synthetic_emails/03_phishing.eml` against the running server
- [x] Email parsing works — headers, body (text+HTML), attachments extracted via stdlib `email`
- [x] Headers are extracted — every header preserved in `email_headers`, key fields in `email_metadata`
- [x] Received chain is reconstructed — earliest-hop-first, with IP/host/timestamp per hop
- [x] SPF/DKIM/DMARC analyzed when available — verified against both a passing and a failing synthetic email
- [x] URLs are extracted — from both HTML `<a>` tags and plain text, verified on the phishing sample
- [x] Domains are extracted — sender/reply-to/return-path/URL hostnames, each independently risk-scored
- [x] IPs are extracted — from Received hops and IP-based URLs, IPv4 and IPv6 supported
- [x] Spoofing indicators are detected — 11 header-anomaly rules, verified triggering on the spoofed-sender sample
- [x] Social-engineering indicators are detected — 9 categories, verified triggering on phishing/BEC/credential samples
- [x] Explainable threat score is calculated — 7-dimension noisy-OR scoring, weights in config, full breakdown returned
- [x] Findings are stored — `findings` table, verified via live API round-trip
- [x] Investigation is stored — `investigations` table with case ID, status, hash, classification, score
- [x] Evidence SHA-256 is stored — verified matches manually-computed hash in tests
- [x] Frontend displays real results — Dashboard, Upload (live status polling), History, Investigation Detail all fetch from the live API; no mock data anywhere in the frontend source
- [x] Investigation history works — `GET /investigations` + History page
- [x] JSON report works — `GET /investigations/{id}/report`, verified structure via live curl
- [x] Tests pass — **53/53** (44 unit + 9 integration), run via `pytest tests -v`
- [x] No critical security issue knowingly introduced — see `SECURITY.md`

## What was actually run and verified in this build session

1. `pytest tests/unit` — 44/44 passed (forensic engine, framework-independent)
2. `pytest tests/integration` — 9/9 passed (full FastAPI `TestClient` workflow against real `.eml` fixtures)
3. Live `uvicorn` server started; `curl` health check returned `200`
4. Live `curl -X POST .../investigations -F file=@03_phishing.eml` → real upload → real background analysis → `GET` returned a fully-populated `InvestigationDetail` with correct parsed metadata, a reconstructed 1-hop Received chain, SOFTFAIL/NONE authentication results, 3 extracted URLs (correctly flagged IP-based/anchor-mismatch), 2 domain findings, and an overall score of 40.13 (MEDIUM)
5. `GET .../report` returned the full structured JSON report including the required "not a confirmed attacker location" and "no outbound requests were made" disclaimers
6. `npm run build` for the frontend completed with zero TypeScript errors
7. Frontend `npm run preview` served successfully on port 5173 alongside the live backend; 4 synthetic emails uploaded and confirmed retrievable via `GET /investigations`

## Known limitations (see also `SECURITY.md`, `THREAT_MODEL.md`)

- DKIM signatures are parsed, not cryptographically verified (needs DNS lookups — Phase 2/3)
- No IP geolocation (explicitly deferred — the project rules forbid presenting IP location as physical attacker location without real geolocation infrastructure)
- Social-engineering detection is deterministic pattern-matching, not a trained ML model (intentional for Phase 1 explainability)
- No authentication/authorization yet (`created_by` column reserved for this; single-tenant trusted-network assumption for Phase 1, as specified in the brief)
- Rate limiting is in-memory/single-process
- Blockchain evidence-anchoring is explicitly Phase 3, not Phase 1

## Recommended Phase 2 tasks

1. **Real ML-based social-engineering / phishing classifier** behind the existing `social_engineering.py` interface (drop-in replacement, same `ContentIndicator` contract).
2. **DKIM cryptographic verification** via DNS TXT lookup of the signing domain's public key.
3. **URL enrichment service** (optional, explicit opt-in): safe redirect-chain resolution via a sandboxed fetcher, reputation/threat-intel API integration (VirusTotal, URLhaus, etc.) — still never executed/rendered.
4. **Role-based authentication** (the `created_by` column and modular API structure are already in place for this).
5. **WebSocket/SSE push** for investigation status instead of polling, using the same `QUEUED/PROCESSING/COMPLETED/FAILED` state machine already in place.
6. **IP geolocation with appropriate caveats** (ASN/registrar-level, clearly labeled as network-location not physical-attacker-location) integrated into the infrastructure risk dimension.
7. **Attachment deep inspection** in an isolated sandbox (never in the main process), building on the existing SHA-256 hash + metadata cataloging.
8. **Blockchain evidence anchoring** (Phase 3 per the brief) building on the existing SHA-256 evidence hash already computed and stored in Phase 1.
