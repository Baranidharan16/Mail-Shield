# MailShield v2 — Real-time Detection & Forensic Intelligence

This document describes what the running system does, how it was built and
how it was evaluated. Numbers below come from `backend/app/ml/artifacts/metrics.json`
and `holdout_pipeline_metrics.json` (re-generate with the commands in §L).

## Coverage of Problem Statement 26106

| PS component | Where it is implemented |
|---|---|
| NLP analysis of subject/body, urgency, impersonation, social engineering | `app/ml/text_model.py` (trained NLP model) + `app/forensic/social_engineering.py` (rule patterns with matched phrases) |
| Spoofed senders, deceptive domains, suspicious attachments, malicious/obfuscated links | `header_anomaly.py`, `domain_analyzer.py` (brand look-alike / homoglyph), `url_analyzer.py`, attachment rules in `scoring.py` |
| AI/ML classification (legitimate / suspicious / phishing / fraud) | `structured_model.py` + `text_model.py` → `app/ai/fusion.py` → SAFE / SUSPICIOUS / THREAT + threat type |
| BEC patterns (payment diversion, invoices, credential harvesting, exec impersonation) | rule patterns + `app/forensic/verdict.py` attack vectors |
| Header & protocol analysis (Return-Path, Received, Message-ID, Reply-To, DKIM/SPF/DMARC, ARC) | `email_parser.py`, `auth_analyzer.py`, `received_parser.py`, verdict `authentication` |
| Origin traceability, earliest reliable node, IP geolocation, VPN/proxy/cloud indicators | verdict `route` + `origin` (OBSERVED / INFERRED / UNKNOWN), `app/intel/providers.py` GeoIP |
| Domain intelligence (WHOIS/RDAP, DNS, MX) | `app/intel/domain_intel.py` (RDAP age/registrar, MX, SPF, DMARC) |
| Correlation, campaigns, graph | `app/intel/campaign.py`, `graph.py`, `global_correlation.py` (per-user) |
| Real-time alerts, dashboard, reports, case management | real-time Gmail monitor, alerts, dashboard, PDF/JSON reports, cases |
| Privacy, chain of custody, retention, masking | per-user isolation, audit log, hash-chain ledger, retention purge, delete-my-data |

## A. Existing features (before v2)
Forensic engine (parser, Received-hop parser, SPF/DKIM/DMARC reader, header rules, URL/domain/IP analysis,
social-engineering patterns, deterministic scoring), fusion layer, campaign matching, attack graph,
attribution levels, agent recommendations, alerts, SHA-256 hash-chain ledger, PDF reports, Gmail OAuth
(connect, list, manual analyse, quarantine), Gemini explanations, Sarvam voice, authentication and
per-user isolation (added in the previous phase).

## B. New in v2
* ML/NLP models retrained on real corpora with a reproducible pipeline (`app/ml/train.py`), versioned artifacts, held-out evaluation (`app/ml/evaluate_pipeline.py`).
* **One canonical pipeline** for uploads, pasted text, manual Gmail analysis and the real-time monitor (previously `/api/analyze-email` used a separate Keras-only path and Gmail analysis created two investigations).
* **Real-time Gmail monitor** (`services/email_monitor.py`) with de-duplication table `processed_emails` and per-user `email_monitor_state`.
* **Forensic verdict** (`GET /api/v1/investigations/{id}/verdict`): conditional deep-forensic agent, identity, authentication meanings (incl. ARC), relay route/hops, Threat Origin (OBSERVED/INFERRED/UNKNOWN), evidence-backed attack vectors, observed threat path, live domain intelligence, one clear conclusion and recommended action.
* GeoIP rewritten: timezone, ASN, reverse DNS, proxy/hosting flags, provider classification and location caveats; synthetic "Demo-Country" data removed.
* Ledger verification now **recalculates** the evidence-file hash and the canonical report hash (VALID / MODIFIED).
* Brand look-alike detection (homoglyphs such as `micros0ft`, brand-embedding such as `sbi-kyc-update.top`), new credential / password-reset / KYC / parcel / BEC patterns, executable & double-extension attachment rules.
* Robustness: malformed headers or URLs no longer abort an analysis (previously caused `FAILED` investigations on real phishing mail).
* Privacy: real privacy page, delete-one / delete-all endpoints, retention purge (`DATA_RETENTION_DAYS`), auto-quarantine off by default.

## C. ML model (structured / forensic-feature model)
* **Type:** RandomForest (300 trees, depth 14, class_weight=balanced) wrapped in isotonic `CalibratedClassifierCV` → calibrated threat probability.
* **Features (37, content/link/attachment/lexical-domain):** reply-to mismatch, display-name impersonation, exec-title on freemail, domain punycode / suspicious TLD / hyphenation / look-alike similarity, URL count, IP-host URL, shortener, punycode URL, suspicious TLD, anchor-text mismatch, credential-style query, avg/max URL risk, link density, 11 social-engineering indicators, attachment count/executable/macro/archive/HTML/double-extension, subject caps ratio, exclamation, HTML form/script. (List: `ML_FEATURE_WHITELIST` in `train.py`.)
* **Deliberately excluded:** authentication, routing and header-count features. In every public corpus available they encode *collection era / mailbox provider* (2002 SpamAssassin ham predates DKIM/DMARC; Enron ham has no transport headers), so a model would learn the dataset, not the threat. They are applied by the rule engine and forensic agent instead.
* **Why v1 was inaccurate:** trained on 240 template-generated synthetic e-mails (8 classes × 30); predictions on real mail were near-arbitrary and fusion converted a hard label to a fixed score.
* **Data:** phishing — `rf-peixoto/phishing_pot` (3,000 sampled real phishing e-mails, 2,634 after de-duplication); legitimate — SpamAssassin easy ham (3,860), hard ham / marketing (250, weighted ×3), Enron business ham (3,930).
* **Process:** validation (size, parse, non-empty) → exact-duplicate removal *before* splitting (prevents leakage) → stratified 70/15/15 split → training → threshold chosen on validation (max F1 with FPR ≤ 2%) → evaluation on the untouched test split.
* **Test results (n=1,602):** precision 0.928, recall 0.848, F1 0.886, ROC-AUC 0.985, FPR 2.2%, FNR 15.2%, confusion TN 1181 / FP 26 / FN 60 / TP 335; marketing (hard-ham) FPR 5.3%.

## D. NLP model
* **Type:** `normalize_text` (URLs, e-mails, numbers, ids → tokens, HTML stripped) → TF-IDF word 1–2-grams (30k) → class-balanced LogisticRegression; the normaliser is saved inside the pipeline so inference preprocessing is identical.
* **Outputs:** threat probability, label vs validated threshold, top contributing terms, the three most suspicious sentences (each sentence scored by the model), plus rule-matched phrases. A single suspicious word cannot flag an e-mail — the whole-message probability must pass the threshold and, for a THREAT, deterministic evidence must corroborate (fusion gating).
* **Test results (n=1,602):** precision 0.985, recall 0.982, F1 0.984, ROC-AUC 0.9997, FPR 0.5%, FNR 1.8%; Enron business ham FPR 0.5%, marketing FPR 7.9%.

### End-to-end pipeline on unseen data (`holdout_pipeline_metrics.json`)
399 phishing e-mails never used in training + 400 unseen Enron business e-mails, full rules+ML+NLP+fusion (no live intel):
* THREAT band (≥50): precision 0.994, recall 0.830, FPR 0.5%.
* Flagged (SUSPICIOUS or THREAT, ≥25): precision 0.99, recall 0.99, FPR 1.0%.

**Limitations (honest):** public ham corpora are old (2002/2004) and phishing_pot is modern, so metrics are optimistic for modern legitimate mail; campaigns in phishing_pot contain near-duplicates across splits. Modern legitimate marketing mail is the main false-positive risk for the learned models — mitigated by fusion gating (models alone cannot declare a THREAT; DMARC-authenticated bulk mail without rule evidence is capped at SAFE). Retrain with your organisation's labelled mail for best results (§L).

## E. Real-time pipeline
```
Gmail (OAuth, read-only list/get) ──every 60 s──► email_monitor.process_user(user)
  → new INBOX ids (after last success − 10 min) → skip ids in processed_emails
  → skip mail sent by the account owner
  → raw RFC 822 → analyze_email_for_user():
       forensic engine (headers, hops, SPF/DKIM/DMARC, URLs, domains, IPs, attachments, SE patterns, rule score)
       → ML (structured) + NLP (text) inference
       → threat intel (GeoIP network owner) → fusion (evidence-gated)
       → correlation (same user only) → attack graph → forensic agent recommendations
       → alert if HIGH/CRITICAL → report → ledger anchor
  → processed_emails row (message id, user id, timestamp, status, investigation id)
UI: dashboard "Real-time Email Threat Monitor" + alerts refresh every 20 s.
```
Each processed e-mail stores: provider message id, user id, timestamps, ML result, NLP result, fused risk/classification, findings/evidence, report and ledger anchor. Polling is used (no Pub/Sub topic needed); on hosting that sleeps when idle the monitor resumes and catches up on wake.

## F. Forensic system
Headers are parsed defensively (compat32 + encoded-word decoding). Received headers are reversed so hop 1 is the earliest observed hop; each hop records from/by host, IP, timestamp, network/ASN/country (GeoIP), role, and is classified as known / suspicious / unknown / internal infrastructure; timestamp inversions and private IPs mid-path are flagged. The **deep forensic agent** is triggered when ML = threat, NLP = high risk, a CRITICAL rule fires or the fused score ≥ 50. The **origin** is the earliest public hop (OBSERVED, with the Received header number as evidence); geography and network are INFERRED from GeoIP; anything missing is UNKNOWN; if no public IP exists the verdict says *"Origin cannot be reliably determined from the available evidence."* Confidence is High only when the hop was recorded by a major receiving provider (hard to forge).

## G. Geolocation
IP → ip-api.com (country, region, city, lat/lon centroid, timezone, ISP/org, ASN, reverse DNS, proxy/hosting/mobile flags), cached in-process. City is withheld for hosting/proxy IPs. Google/Microsoft/Amazon/Cloudflare/hosting/VPN IPs carry an explicit caveat that the location is the service's infrastructure, not the sender. Private/RFC 5737 addresses get no geolocation. Browser GPS is never used.

## H. Blockchain / integrity
Stored per block: index, timestamp, case id, SHA-256(evidence file), SHA-256(canonical report JSON), previous hash, block hash. **Not stored:** e-mail content, addresses, tokens, personal data. Verification recalculates both hashes from current data and the whole chain → VALID / MODIFIED. It is a database-resident hash-chain (tamper evidence, audit trail), not a public blockchain, and does not by itself make e-mail data private.

## I. Privacy
Argon2id passwords; refresh tokens stored hashed; Gmail OAuth tokens Fernet-encrypted, never sent to the browser; minimum scopes (readonly for analysis; modify only for user-initiated quarantine). Owner's own mail skipped. Retention purge (default 90 days), delete-one and delete-all endpoints, privacy page describing third parties (ip-api, rdap.org/DNS, Gemini, Sarvam).

## J. Database
New tables: `processed_emails` (unique `(user_id, provider_message_id)`, index `(user_id, processed_at)`), `email_monitor_state` (per user), plus `user_sessions`, `password_reset_tokens` from the auth phase. Every investigation row has `user_id`; routes with `{investigation_id}`/`{alert_id}` pass a router-level ownership guard; list queries filter `user_id = authenticated user`; campaign correlation and global graph are per-user.

## K. Deployment (Render Blueprint, `render.yaml`)
Env vars: `APP_ENV=production`, `DATABASE_URL` (from Render Postgres), `JWT_SECRET_KEY` (generated), `FRONTEND_URL`, `CORS_ORIGINS`, `LOAD_ML_MODELS=false` (legacy Keras off; v2 models always load), `FERNET_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI=https://<service>.onrender.com/auth/google/callback`, `GEMINI_API_KEY`, `SARVAM_API_KEY`, `GMAIL_MONITOR_ENABLED=true`, `GMAIL_POLL_INTERVAL_SECONDS=60`, `GMAIL_AUTO_QUARANTINE=false`, `DATA_RETENTION_DAYS=90`. `scikit-learn==1.9.1` is pinned because the artifacts were trained with it.

## L. Testing & retraining
```bash
cd backend
python -m pytest tests/test_realtime_forensics.py tests/test_auth_isolation.py tests/unit tests/integration/test_api_workflow.py -q
# retrain on your own labelled data (one raw e-mail per file):
python -m app.ml.train --phish DIR --ham DIR [--hard-ham DIR] [--text-ham DIR] --version 2.1.0
python -m app.ml.evaluate_pipeline --phish UNSEEN_PHISH_DIR --legit UNSEEN_LEGIT_DIR
```
