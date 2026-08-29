# API Reference — Phase 1

Base URL: `http://localhost:8000/api/v1`
Interactive docs (Swagger/OpenAPI): `http://localhost:8000/docs`

All responses are JSON. Errors never leak raw Python tracebacks (see `SECURITY.md`).

---

## `GET /health`

Health check. Verifies the API and database are reachable.

```json
{ "status": "ok", "app_name": "AI-Powered Email Threat Intelligence & Forensic Platform", "database": "ok" }
```

---

## `POST /investigations`

Upload a `.eml` file and create a new investigation. Analysis is kicked off immediately as a background task.

**Request:** `multipart/form-data`, field name `file`.

**Response `201`:**
```json
{
  "id": "d214b194-7cc0-451b-8fb2-171845a281f7",
  "case_id": "CASE-2026-93BF1D37",
  "status": "QUEUED",
  "message": "Investigation created. Analysis has been queued."
}
```

**Errors:**
- `415` — extension not `.eml`
- `413` — file exceeds `MAX_UPLOAD_SIZE_BYTES` or is empty
- `500` — unexpected processing failure (never a raw traceback)

---

## `POST /investigations/{id}/analyze`

Explicitly (re)triggers analysis for an existing investigation, re-reading the stored evidence file from disk.

**Response `200`:** same shape as create, with `status: "PROCESSING"`.

---

## `GET /investigations`

List investigations, most recent first.

**Query params:** `limit` (default 50, max 200), `offset` (default 0).

**Response `200`:** array of investigation summaries (`id`, `case_id`, `filename`, `status`, `classification`, `risk_score`, `confidence`, `created_at`, `analyzed_at`).

---

## `GET /investigations/{id}`

Full investigation detail: email metadata, received hops, authentication result, URLs, domains, IP addresses, findings, indicators, and the risk-score breakdown.

**Errors:** `404` if not found.

---

## `GET /investigations/{id}/findings`

Just the deterministic header-anomaly findings array (rule_id, title, category, severity, explanation, evidence, confidence).

---

## `GET /investigations/{id}/indicators`

Just the social-engineering content indicators array (indicator_type, severity, matched_evidence, explanation, confidence).

---

## `GET /investigations/{id}/report`

The full structured JSON forensic report (case summary, received chain, authentication, findings, URLs, domains, IPs, social-engineering indicators, threat-score breakdown, and disclaimers).

**Errors:** `409` if the report isn't generated yet (investigation not `COMPLETED`).

---

## Rate limiting

All endpoints except `/health` and API docs are limited to `RATE_LIMIT_PER_MINUTE` (default 30) requests per client IP per rolling 60-second window. Exceeding it returns `429`.
