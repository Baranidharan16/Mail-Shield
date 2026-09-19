# 🛡️ MailShield — AI-Powered Email Threat Detection & Forensic Intelligence Platform

<div align="center">

![MailShield SOC Platform](frontend/src/assets/hero.png)

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-19+-61DAFB.svg?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-6.0+-646CFF.svg?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Google Gemini AI](https://img.shields.io/badge/Gemini_AI-1.5_Flash-4285F4.svg?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

**Smart India Hackathon (SIH) · Problem Statement: 26106 (AICTE CSC)**  
*Next-Generation Email Forensics, Attack Graph Analytics, and SOC Incident Response*

</div>

---

## 📌 Executive Summary

**MailShield** is a comprehensive, enterprise-grade Email Forensics & Threat Intelligence Platform tailored for **SOC Analysts**, **Cybersecurity Teams**, and **Digital Forensic Investigators**.

It ingests raw email artifacts (`.eml`, `.msg`), parses deep RFC 5322 header hierarchies, extracts indicators of compromise (IOCs), correlates lookalike domains and routing hops, calculates deterministic explainable risk scores across 7 forensic dimensions, builds interactive threat infrastructure graphs, and anchors evidence to an immutable cryptographic SHA-256 ledger.

---

## ✨ Key Capabilities & System Features

```
                                  ┌────────────────────────┐
                                  │   RAW EMAIL (.eml)     │
                                  └───────────┬────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        ┌─────────────────────────┐                       ┌─────────────────────────┐
        │   RFC 5322 MIME Parser  │                       │ Cryptographic SHA-256   │
        │   Header Hop Extraction │                       │ Evidence Hash Anchor    │
        └────────────┬────────────┘                       └────────────┬────────────┘
                     │                                                 │
        ┌────────────┴─────────────────────────────────────────────────┴────────────┐
        ▼                                                                           ▼
┌───────────────────────────────┐                                   ┌───────────────────────────────┐
│   FORENSIC ANALYSIS ENGINE    │                                   │   INTELLIGENCE & RESPONSE     │
├───────────────────────────────┤                                   ├───────────────────────────────┤
│ • SPF / DKIM / DMARC Auth     │                                   │ • Attack Graph Visualization  │
│ • Lookalike Domain Levenshtein│                                   │ • Relay Geolocation Intel     │
│ • Deceptive URL Risk Analyzer │                                   │ • SOC Alert Triage Queue      │
│ • Social Engineering Heuristic│                                   │ • Gemini AI Forensic Chatbot  │
│ • 7-Dimension Weighted Scoring│                                   │ • Immutable Integrity Ledger  │
└───────────────────────────────┘                                   └───────────────────────────────┘
```

### 1. 🔍 Deep Forensic Header & Routing Hop Extraction
- Full RFC 5322 / MIME structure disassembly, multi-part attachment analysis, and cryptographic checksumming.
- Chronological relay hop reconstruction through `Received` headers with hop timestamps, host mapping, and IP extraction.

### 2. 🛡️ Email Authentication & Domain Spoofing Verification
- Corroborates SPF, DKIM, and DMARC alignment status.
- Evaluates `From` ↔ `Reply-To` and `From` ↔ `Return-Path` alignment to detect display-name spoofing and cousin-domain impersonation (Levenshtein distance & Unicode homograph detection).

### 3. 🌐 Email Origin Geolocation Intelligence
- Maps public IP infrastructure associated with observed relay hops.
- Determines Autonomous System Number (ASN), ISP, hosting organization, and geographic region.
- *Strict forensic attribution disclaimer*: Reflects observed mail infrastructure, not necessarily the attacker's physical location.

### 4. 🕸️ Interactive Attack Relationship Graph
- Dynamic node-link visualization mapping the campaign topology: Senders, Lookalike Domains, Relay Infrastructure, Embedded URLs, and Suspicious Attachments.

### 5. 🚨 Advanced SOC Threat Center & Incident Triage
- Live alert triage queue with real-time severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Automatic emergency alert banners and helpline protocols for high-risk cases.
- One-click email quarantine action and tier-1/tier-2 escalation playbooks.

### 6. 🤖 Autonomous Gemini AI Forensic Assistant
- Floating conversational AI chatbot grounded directly in the active investigation's extracted artifacts.
- Explains obfuscated payloads, queries threat intent, and formulates incident response actions.

### 7. ⛓️ Evidence Vault & Cryptographic Integrity Ledger
- SHA-256 evidence anchoring with tamper-evident cryptographic block hash chains.
- Guarantees chain of custody and forensic admissibility for digital evidence.

### 8. 🔮 Crystal Transparent Glassmorphism UI
- Ultra-modern dark cybersecurity interface with `backdrop-filter: blur(24px)`, specular light highlights, live telemetry feeds, and ambient glow refraction.

---

## 🏗️ Architecture & Technology Stack

| Layer | Technologies Used | Purpose |
|---|---|---|
| **Frontend** | React 19, TypeScript, Vite, Tailwind CSS v4, Lucide Icons | Reactive SOC dashboard, glassmorphism UI, interactive attack graph |
| **Backend** | Python 3.11+, FastAPI, Uvicorn, Pydantic v2 | High-throughput async REST API, forensic analysis pipeline |
| **Database** | SQLite (default development) / PostgreSQL | Relational storage for cases, IOCs, alerts, and ledger blocks |
| **AI / LLM** | Google Gemini 1.5 Flash API | Multimodal artifact reasoning, intent classification, chatbot |
| **Security & Cryptography** | `hashlib` (SHA-256), Levenshtein distance, regex | Cryptographic integrity, spoof detection, URL sanitization |

---

## 📁 Repository Structure

```
.
├── backend/                        # FastAPI Python Backend
│   ├── app/
│   │   ├── api/v1/                 # REST API Route Endpoints
│   │   │   ├── investigations.py   # Investigation lifecycle & evidence analysis
│   │   │   ├── chat.py             # Forensic AI Chatbot API
│   │   │   ├── alerts.py           # SOC Alert Triage endpoints
│   │   │   ├── blockchain.py       # Cryptographic Integrity Ledger API
│   │   │   ├── dashboard.py        # Real-time telemetry stats
│   │   │   └── reports.py          # PDF / JSON report generation
│   │   ├── core/                   # Global configuration & security settings
│   │   ├── db/                     # Database models, schemas, and sessions
│   │   ├── forensic/               # Core forensic parsing & scoring modules
│   │   │   ├── auth_analyzer.py    # SPF / DKIM / DMARC verification
│   │   │   ├── domain_analyzer.py  # Lookalike / Homograph domain algorithms
│   │   │   ├── url_analyzer.py     # Suspicious link & redirect analysis
│   │   │   ├── received_parser.py  # Relay hop & routing reconstruction
│   │   │   ├── scoring.py          # 7-dimension explainable scoring model
│   │   │   └── social_engineering.py # Cognitive manipulation heuristics
│   │   ├── forensic_ai/            # Gemini AI integration & reasoning engines
│   │   ├── intel/                  # Attack graph & threat intelligence
│   │   └── reports/                # Report templating & PDF exporter
│   ├── requirements.txt            # Python dependencies
│   └── tests/                      # Unit & integration test suites
├── frontend/                       # React 19 + TypeScript + Vite Frontend
│   ├── src/
│   │   ├── api/client.ts           # Axios REST API client
│   │   ├── components/             # Reusable UI & forensic widgets
│   │   │   ├── AttackGraphPanel.tsx# Interactive threat topology graph
│   │   │   ├── GeoOriginIntelPanel.tsx # Source infrastructure intel
│   │   │   ├── SOCAlertPanel.tsx   # Critical incident banner
│   │   │   ├── SOCHelpline.tsx     # Emergency escalation protocol
│   │   │   ├── SOCThreatCenter.tsx # Incident triage console
│   │   │   ├── MailShieldChatbot.tsx # Floating AI assistant
│   │   │   ├── Badges.tsx          # Glassmorphic severity pills
│   │   │   └── forensic-ai/        # AI evidence reasoning panels
│   │   ├── pages/                  # Main route pages
│   │   │   ├── DashboardPage.tsx   # SOC Command Center
│   │   │   ├── UploadPage.tsx      # Email analysis ingestion console
│   │   │   ├── HistoryPage.tsx     # Case history & IOC filter
│   │   │   ├── InvestigationDetailPage.tsx # 18-panel forensic breakdown
│   │   │   ├── AlertsPage.tsx      # Active threat triage
│   │   │   ├── EvidenceVaultPage.tsx # Preserved SHA-256 records
│   │   │   └── IntegrityLedgerPage.tsx # Cryptographic block chain
│   │   ├── index.css               # Glassmorphism design tokens
│   │   └── types/investigation.ts  # TypeScript forensic data interfaces
│   └── package.json                # Frontend dependencies
├── test_data/                      # Synthetic test email corpus (.eml)
├── docs/                           # Architecture, threat model & API specs
├── docker-compose.yml              # Containerized multi-service deployment
├── run.py                          # Unified launcher for Backend + Frontend
├── start.bat                       # Windows double-click launcher
├── test_suite.py                   # Automated end-to-end testing script
└── README.md                       # Comprehensive documentation
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & **npm**
- *(Optional)* **Docker & Docker Compose**

---

### Option A: Unified Launcher (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/Baranidharan16/sih-email-forensics-full.git
   cd sih-email-forensics-full
   ```

2. Run the automated launcher:
   ```bash
   python run.py
   ```
   *This automatically installs dependencies, sets up the virtual environment, and starts both backend (port 8000) and frontend (port 5173).*

---

### Option B: Manual Setup

#### 1. Backend Setup
```bash
cd backend
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

### Option C: Docker Deployment

```bash
docker-compose up --build
```

---

## 🧭 Local Development (new laptop)

1. Install **Python 3.12**, **Node.js 20+**, **Git**.
2. `git clone https://github.com/Baranidharan16/sih-email-forensics-full.git && cd sih-email-forensics-full`
3. Backend:
   ```bash
   cd backend
   python -m venv .venv
   .venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
   pip install -r requirements.txt
   copy .env.example .env            # macOS/Linux: cp .env.example .env
   # edit .env: set JWT_SECRET_KEY (and Google/Gemini keys if you use them)
   uvicorn main:app --reload --port 8000
   ```
   SQLite (`backend/forensics.db`) is created automatically for local work. To share
   accounts with production instead, put the production `DATABASE_URL` in `.env`.
4. Frontend (second terminal):
   ```bash
   cd frontend
   npm ci
   npm run dev          # http://localhost:5173  (add "-- --host" to open from a phone on your Wi-Fi)
   ```
   The Vite dev server proxies `/api` to `http://127.0.0.1:8000` — no URLs to edit.
5. Test: open http://localhost:5173 → Register → you land on the dashboard → refresh (still
   signed in) → Sign out. Backend tests: `cd backend && python -m pytest tests/test_auth_isolation.py -q`.
6. Gmail OAuth locally: add `http://localhost:8000/auth/google/callback` as an authorized
   redirect URI in Google Cloud and set the same value in `GOOGLE_REDIRECT_URI`.

## ☁️ Production Deployment (GitHub → Vercel + Render + PostgreSQL)

```
Browser (any laptop/phone) ──HTTPS──▶ Vercel  (React SPA, sih-email-forensics-full.vercel.app)
                                         │  vercel.json rewrites /api/*  and /auth/google/*
                                         ▼
                                     Render  (FastAPI, sih-email-forensics-full-1.onrender.com)
                                         │
                            ┌────────────┴────────────┐
                            ▼                         ▼
               Render PostgreSQL (ONE shared DB)   Google OAuth / Gmail API
```

The browser only ever talks to the Vercel domain; Vercel forwards API calls to Render. The
login cookie is therefore first-party (works in Safari/Chrome/Firefox, no CORS issues), and
every device uses the same backend and the same database.

### 1. Database (Render PostgreSQL)
Render → **New → PostgreSQL** (name `mailshield-db`) → copy the **Internal Database URL**.
Tables are created automatically on first start. (Neon/Supabase also work — use their URL.)
Note: Render's free PostgreSQL expires after 30 days; upgrade or use Neon for long-term storage.

### 2. Backend (Render Web Service)
Either **New → Blueprint** (uses `render.yaml`, creates DB + service), or configure the existing
service `sih-email-forensics-full-1` → **Settings**:

| Setting | Value |
|---|---|
| Root Directory | `backend` |
| Runtime | Python 3 (`backend/.python-version` pins 3.12) |
| Build Command | `pip install --upgrade pip && pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"` |
| Health Check Path | `/api/v1/health` |
| Auto-Deploy | Yes (every push to `main`) |

Environment variables (Render → Environment):

| Key | Value |
|---|---|
| `APP_ENV` | `production` |
| `DATABASE_URL` | PostgreSQL URL from step 1 |
| `JWT_SECRET_KEY` | random 48+ chars (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) |
| `FRONTEND_URL` | `https://sih-email-forensics-full.vercel.app` |
| `CORS_ORIGINS` | `https://sih-email-forensics-full.vercel.app` |
| `LOAD_ML_MODELS` | `false` on the free 512 MB plan, `true` on ≥2 GB |
| `FERNET_KEY` | Fernet key (see `.env.example`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | from Google Cloud |
| `GOOGLE_REDIRECT_URI` | `https://sih-email-forensics-full-1.onrender.com/auth/google/callback` |
| `GEMINI_API_KEY`, `SARVAM_API_KEY` | optional |
| `UPLOAD_STORAGE_DIR` | `/tmp/evidence` (or a Render Disk mount path) |

Check: `https://sih-email-forensics-full-1.onrender.com/api/v1/health` → `{"status":"ok","database":"ok","database_engine":"postgresql",...}`.

### 3. Frontend (Vercel)
Vercel project → **Settings → General**: Root Directory = `frontend`, Framework = Vite
(`frontend/vercel.json` sets build `npm run build`, output `dist`, SPA fallback and the API
rewrites). No secret environment variables are needed; optionally set
`VITE_API_BASE_URL=/api/v1`. Pushes to `main` deploy automatically.
If the Render URL ever changes, update the three `destination` URLs in `frontend/vercel.json`.

### 4. Google OAuth
Google Cloud Console → APIs & Services → Credentials → your OAuth client:
- Authorized JavaScript origins: `https://sih-email-forensics-full.vercel.app`, `http://localhost:5173`
- Authorized redirect URIs: `https://sih-email-forensics-full-1.onrender.com/auth/google/callback`,
  `http://localhost:8000/auth/google/callback`
- While the consent screen is in "Testing", add every Gmail tester under **Test users**.

### 5. Verify
Open the Vercel site on two devices: register on one, sign in with the same account on the
other; register a second user and confirm neither sees the other's investigations.

## 🌐 Service Access Endpoints

| Service | URL | Description |
|---|---|---|
| **MailShield Web UI** | **[http://localhost:5173](http://localhost:5173)** | SOC Command Dashboard & Investigation Console |
| **Backend REST API** | **[http://localhost:8000](http://localhost:8000)** | Core analysis engine |
| **Interactive API Docs** | **[http://localhost:8000/docs](http://localhost:8000/docs)** | Swagger UI documentation |

---

## 🧪 Testing & Validation

Run the automated end-to-end test suite:
```bash
python test_suite.py
```

Run backend unit tests:
```bash
cd backend
pytest tests/unit/
```

Test with included synthetic test emails located in `test_data/synthetic_emails/`:
- `01_legitimate.eml` — Clean corporate newsletter.
- `02_spoofed_sender.eml` — Mismatched From / Reply-To header spoofing.
- `03_phishing.eml` — Credential harvesting with malicious shortlinks.
- `04_credential_harvesting.eml` — Lookalike domain impersonation.
- `05_bec_payment_request.eml` — Business Email Compromise (BEC) wire transfer.
- `06_suspicious_domain.eml` — Punycode / suspicious TLD attack.
- `07_auth_failure.eml` — SPF / DKIM hardfail breakdown.

---

## ⚖️ Legal & Forensic Disclaimer

1. **Probabilistic Scoring**: The forensic risk score is a deterministic indicator calculated from heuristic signals and threat intelligence. It should be corroborated by a qualified SOC analyst before taking destructive containment actions.
2. **Infrastructure Attribution**: Geolocation and IP intelligence represent the observed network routing infrastructure (mail relays, proxies, cloud nodes), not definitive physical proof of the threat actor's location.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Developed for Smart India Hackathon (SIH 2026) · MailShield Cybersecurity Platform</sub>
</div>