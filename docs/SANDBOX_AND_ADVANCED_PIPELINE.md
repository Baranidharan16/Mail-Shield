# Isolated Sandbox, AI Security, GRC, VAPT & SOC Alarms

This adds a post-detection pipeline to MailShield without changing the existing
forensic / ML pipeline, its stored report, or its ledger anchor.

```
Email ─► AI Threat Detection ─► Suspicious? ─► Quarantine ─► Isolated Sandbox ─► AI-Security + GRC + VAPT
      ─► Consolidated Threat Report ─► Blockchain audit (hash-chain block "<CASE>-SBX") ─► SOC alarm
```

## 1. What was added

| Layer | Files |
|---|---|
| Sandbox service (separate container) | `sandbox/` — `Dockerfile`, `sandbox_app/main.py` (API + HMAC auth), `isolation.py` (per-job forked process with rlimits, sockets disabled), `engine.py`, `analyzers/` (file type, strings/IOCs, Office/VBA, PDF, archives, HTML, PE/LNK, URLs), `data/known_bad_sha256.txt`, `tests/` |
| Backend client | `backend/app/sandbox/client.py` — extracts only attachment bytes, URLs, HTML body; HMAC-signs; retries through Render cold starts |
| Pipeline | `backend/app/advanced/pipeline.py` — quarantine → sandbox → AI security → GRC → VAPT → threat report → ledger → alarms |
| AI security | `backend/app/advanced/ai_security.py` — prompt injection aimed at AI assistants/filters, hidden text (ML poisoning), zero-width / bidi / homoglyph evasion, AI-written-lure heuristic, live status of MailShield's own AI guardrails |
| GRC | `backend/app/advanced/grc.py` — IT Act 2000 (43, 66, 66C, 66D), BNS 2023 (308, 318/319, 336/340), CERT-In Directions 2022 (6-hour reporting), DPDP Act 2023, GoI E-mail Policy, RBI digital-payment / fraud rules, SEBI IA rules, ISO 27001 control gaps — each item with evidence + actions |
| VAPT | `backend/app/advanced/vapt.py` — attacker intent (with confidence + evidence), kill chain, MITRE ATT&CK, located weaknesses (sender DNS, gateway, endpoint, IAM, finance process, people, AI) with likelihood × impact rating and remediation |
| SOC alarms | `backend/app/advanced/soc.py`, models in `backend/app/models/advanced.py` — per-analyst config, alarms, SSRF-guarded HTTPS webhook |
| API | `backend/app/api/v1/advanced.py` (mounted in `backend/main.py`) |
| UI | `frontend/src/components/AdvancedThreatAnalysis.tsx` (on the case / threat-details page), `SOCAlarmCenter.tsx` (global alarm bar + siren), `pages/SOCConfigPage.tsx` (`/soc/config`), `api/advanced.ts` |
| Hooks into existing code (small) | `run_analysis` schedules the pipeline after completion; the three quarantine actions send the case to the sandbox; the ledger block list includes `-SBX` blocks; the PDF forensic report gains the new sections |

Existing pages, components and endpoints are unchanged; the new panels are
inserted below the forensic verdict on the investigation page.

**Bug fixed along the way:** `app/reports/pdf_report.py` crashed on the "—"
character in its own header (core PDF fonts are latin-1) and on consecutive
`multi_cell` calls, so *Download PDF* always failed. Both are fixed.

## 2. Isolation guarantees

| Guarantee | How |
|---|---|
| Suspicious files never opened on the main server | Backend only base64-copies MIME parts; all parsing happens in the sandbox container |
| Nothing executes | Static analysis only (magic bytes, hashes, strings, olevba parse, PDF keywords, zip listing, URL lexing). No rendering, mounting, macro execution or URL fetching |
| No credentials / DB / host FS in the sandbox | Separate image built from `sandbox/` only; its only env var is `SANDBOX_SHARED_SECRET`; no volumes; root `.dockerignore` keeps `sandbox/` out of the app image and vice-versa |
| Minimal data shared | Payload = attachment bytes + URLs + HTML body. No headers, addresses, subject, tokens. The stored manifest keeps names/sizes/SHA-256 only |
| Authenticated calls | HMAC-SHA256 over timestamp + nonce + body hash, ±5 min window, nonce replay cache |
| Per-job containment | Each job runs in a forked child: `RLIMIT_AS` 384 MB, `RLIMIT_CPU` 30 s, `RLIMIT_FSIZE` 0 (cannot write files), `RLIMIT_NOFILE` 64, sockets disabled, 45 s wall-clock kill. A crash/timeout returns SUSPICIOUS rather than taking the service down |
| Network restriction | docker-compose: sandbox sits only on `sandbox_net` (`internal: true`) — no internet, no route to Postgres. Render free tier cannot block egress, so the in-process socket kill + "nothing to steal" design applies there |
| Container hardening (compose) | non-root UID 10001, `read_only`, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, memory/CPU caps, noexec tmpfs |

## 3. Verdict logic

* Every sandbox finding = rule ID + severity + confidence + explanation + evidence (+ MITRE id and predicted behaviour).
* File/URL score = noisy-OR of finding weights. **MALICIOUS** if any near-certain CRITICAL finding (known-bad hash, disguised executable, auto-exec macro launching a shell, remote-template injection, HTML smuggling, credential-harvest form …) or score ≥ 75; **SUSPICIOUS** if ≥ 35; else **SAFE**.
* Consolidated verdict = noisy-OR of detection risk, sandbox score, AI-security score and GRC violations; MALICIOUS if the sandbox is MALICIOUS or detection is CRITICAL.
* "Where it went wrong" lists each checkpoint (authentication, identity, transport, content, links, attachments, HTML behaviour, adversarial AI, threat intel, ML verdict, GRC) as PASS / WARN / FAIL with evidence.

## 4. API (all under `/api/v1`, JWT required)

| Method | Path | Purpose |
|---|---|---|
| GET | `/investigations/{id}/advanced` | Quarantine, sandbox result, AI security, GRC, VAPT, threat report, ledger block |
| POST | `/investigations/{id}/sandbox/run` | Re-submit artefacts to the sandbox and rebuild the report |
| GET | `/investigations/{id}/threat-report` | Consolidated threat report (JSON) |
| GET | `/investigations/{id}/threat-report/pdf` | Full forensic PDF + threat-report sections |
| GET | `/investigations/{id}/report/pdf` | (existing) now also includes the new sections |
| GET / PUT | `/soc/config` | SOC alarm configuration |
| GET | `/soc/alarms?status=ACTIVE` | Alarms (+ active count) |
| POST | `/soc/alarms/{alarm_id}/ack`, `/soc/alarms/ack-all`, `/soc/alarms/test` | Acknowledge / test |
| GET | `/soc/sandbox/health` | Sandbox reachability |

Sandbox service: `GET /health` (public, no data), `POST /v1/analyze` (HMAC only).

## 5. Environment variables

Backend (`mailshield-sih`):

| Var | Default | Notes |
|---|---|---|
| `SANDBOX_URL` | — | `https://mailshield-sandbox.onrender.com` on Render, `http://sandbox:8080` in compose |
| `SANDBOX_SHARED_SECRET` | — | Must equal the sandbox's value |
| `SANDBOX_ENABLED` | `true` | |
| `SANDBOX_TIMEOUT_SECONDS` | `90` | per attempt |
| `SANDBOX_MAX_RETRIES` | `4` | covers free-tier cold start |
| `ADVANCED_PIPELINE_ENABLED` | `true` | `false` switches the whole add-on off |

Sandbox (`mailshield-sandbox`): `SANDBOX_SHARED_SECRET` (required), `SANDBOX_JOB_MEMORY_MB` (384), `SANDBOX_JOB_CPU_SECONDS` (30), `SANDBOX_JOB_TIMEOUT_SECONDS` (45), `SANDBOX_MAX_REQUEST_BYTES` (40 MB), `SANDBOX_MAX_FILE_BYTES` (20 MB), `SANDBOX_BLOCKLIST` (path to extra hash list).

New tables (`advanced_analyses`, `soc_configs`, `soc_alarms`) are created automatically at startup by `init_db()`; no migration step.

## 6. Deploying on Render

**If the site was created from `render.yaml` (Blueprint):** push to GitHub → Render → Blueprints → your blueprint → *Sync*. It creates `mailshield-sandbox`, generates the shared secret and injects it into `mailshield-sih`.

**If `mailshield-sih` was created manually:**
1. Render → **New → Web Service** → same repo. Name `mailshield-sandbox`, Runtime **Docker**, Root Directory **`sandbox`** (Dockerfile path `./Dockerfile`), plan Free, Health check path `/health`.
2. Environment: `SANDBOX_SHARED_SECRET` = output of `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Add nothing else — no DB, Google or Gemini keys.
3. Deploy, then open `https://<sandbox-host>/health` → `{"status":"ok", ... "auth_configured":true}`.
4. On `mailshield-sih` → Environment add `SANDBOX_URL=https://<sandbox-host>` and the **same** `SANDBOX_SHARED_SECRET`. Save (it redeploys).
5. In the app: *SOC Alarm Config* shows "Sandbox online". Upload `backend/tests/test_data/realtime/06_malicious_attachment.eml` → the case page shows the pipeline reaching *Blockchain audit log · ANCHORED*, sandbox verdict **MALICIOUS**, GRC/VAPT panels, and the red SOC alarm bar.

Free-tier note: the sandbox sleeps after 15 min idle; the first submission wakes it (~30–60 s). The backend retries automatically and the UI polls until the result arrives; *Re-run sandbox* is available if it was unreachable.

## 7. Local run

```bash
# docker
export SANDBOX_SHARED_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
docker compose up --build

# without docker (two terminals)
cd sandbox  && pip install -r requirements.txt && SANDBOX_SHARED_SECRET=dev-secret uvicorn sandbox_app.main:app --port 8090
cd backend  && SANDBOX_URL=http://127.0.0.1:8090 SANDBOX_SHARED_SECRET=dev-secret python ../run.py   # or your usual start.bat
```
(Windows PowerShell: `$env:SANDBOX_SHARED_SECRET="dev-secret"` before the command. Forked-process isolation is Linux-only; on Windows the sandbox falls back to a spawned process without rlimits — use Docker/Render for the isolated setup.)

## 8. Tests

```bash
cd sandbox && python -m pytest -q          # 11 tests: EICAR, disguised exe, zip+script, HTML phish, PDF JS, remote template, URLs, HTML smuggling, HMAC/replay
cd backend && python -m pytest -q tests/test_advanced_pipeline.py   # end-to-end incl. owner isolation, SOC config, PDF
```

## 9. Honest limits (prototype)

* Static/controlled analysis only — no dynamic detonation. Behaviour is *predicted* from indicators and labelled as such.
* RAR/7z/CAB/GZIP containers are flagged but not unpacked; encrypted ZIPs are flagged, not cracked.
* AI-written-lure likelihood is a stylometric heuristic, not proof.
* GRC items are an evidence-linked mapping for legal review, not legal advice.
* The "blockchain" is the platform's existing local SHA-256 hash chain (see `app/blockchain/ledger.py`).
