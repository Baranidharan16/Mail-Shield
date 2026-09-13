# MAILSHIELD — AI-Powered Email Forensic Intelligence Platform

MAILSHIELD is an enterprise cybersecurity email forensic and threat detection backend built with Python, FastAPI, and Keras deep learning models.

---

## Architecture Overview

```
EMAIL UPLOAD (.eml or raw text)
        ↓
    FASTAPI (/api/analyze-email)
        ↓
   EMAIL PARSER (Headers, Bodies, URLs, Domains, Attachments)
        ↓
┌───────────────────────┬────────────────────────┬─────────────────────────┐
│                       │                        │                         │
▼                       ▼                        ▼                         │
ML PHISHING MODEL       NLP THREAT MODEL         FORENSIC ANALYZER         │
(mailshield_ml.keras)   (mailshield_nlp.keras)   (SPF, DKIM, DMARC, URLs)  │
│                       │                        │                         │
▼                       ▼                        ▼                         │
Phishing Probability    6 Threat Patterns        Header/URL/Domain Findings│
│                       │                        │                         │
└───────────────────────┴────────────────────────┴─────────────────────────┘
        ↓
   DETERMINISTIC RISK ENGINE (Transparent 0-100 Score & Low/Med/High/Crit Level)
        ↓
   AI REASONING LAYER (GeminiReasoningProvider / OllamaReasoningProvider / Fallback)
        ↓
   STRUCTURED EXPLANATION & INCIDENT RESPONSE ACTIONS
        ↓
   FASTAPI JSON RESPONSE → MAILSHIELD UI
```

---

## 1. How to Install Python Dependencies

Make sure Python 3.13 is installed:
```powershell
# Create or activate virtual environment
py -3.13 -m venv backend\.venv --system-site-packages
backend\.venv\Scripts\activate

# Install dependencies
pip install -r backend\requirements.txt
```

---

## 2. How to Configure `.env`

Copy the example environment configuration:
```powershell
cp backend\.env.example backend\.env
```

Edit `backend\.env`:
```env
# Gemini API Key for online AI reasoning
GEMINI_API_KEY=your_actual_gemini_api_key

# Reasoning Provider: 'gemini', 'ollama', or 'rule_based'
REASONING_PROVIDER=gemini

# Ollama settings (used if REASONING_PROVIDER=ollama)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# API Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=True
```

*Note: If `GEMINI_API_KEY` is not provided or Gemini is unreachable, MAILSHIELD automatically falls back to deterministic rule-based threat explanations without failing.*

---

## 3. Where to Place the `.keras` Models

The models must be placed inside the `backend/models/` directory:
- `backend/models/mailshield_ml.keras` (MailShield ML Phishing Detection Model)
- `backend/models/mailshield_nlp.keras` (MailShield NLP Threat-Pattern Model)

Both models are loaded once into memory during application startup.

---

## 4. How to Start FastAPI

Run the backend server using Uvicorn:
```powershell
# From project root:
backend\.venv\Scripts\uvicorn.exe backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Or directly from the `backend/` directory:
```powershell
cd backend
..\backend\.venv\Scripts\uvicorn.exe main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 5. How to Test `/api/health`

Using curl or PowerShell:
```powershell
curl http://localhost:8000/api/health
```
Expected response:
```json
{
  "status": "ok",
  "app_name": "MAILSHIELD",
  "version": "1.0.0"
}
```

---

## 6. How to Test `/api/model-status`

```powershell
curl http://localhost:8000/api/model-status
```
Expected response:
```json
{
  "ml_model_loaded": true,
  "nlp_model_loaded": true,
  "ml_model_path": "...\\backend\\models\\mailshield_ml.keras",
  "nlp_model_path": "...\\backend\\models\\mailshield_nlp.keras",
  "reasoning_provider": "gemini",
  "gemini_configured": true
}
```

---

## 7. How to Upload an `.eml` for Analysis

Using curl:
```powershell
curl -X POST http://localhost:8000/api/analyze-email `
  -F "file=@test_data/synthetic_emails/03_phishing.eml"
```

Or analyze raw text:
```powershell
curl -X POST http://localhost:8000/api/analyze-email `
  -F "raw_text=URGENT: Your account has been suspended. Click here to verify credentials." `
  -F "subject=Security Notice"
```

Full Response Structure:
```json
{
  "analysis_id": "847a9f73-2d5f-4a41-863a-23d24ea2439c",
  "email": {
    "subject": "URGENT: Unusual sign-in activity detected",
    "sender": "Security Alert <security@chase-security-alert.com>",
    "sender_domain": "chase-security-alert.com",
    "reply_to": "auth-response@suspicious-relay.xyz",
    "reply_to_domain": "suspicious-relay.xyz"
  },
  "ml": {
    "prediction": "phishing",
    "phishing_probability": 0.9954,
    "confidence": 0.9954
  },
  "nlp": {
    "urgency": 0.4917,
    "credential_request": 0.4990,
    "financial_manipulation": 0.4973,
    "impersonation": 0.4989,
    "threat_language": 0.5059,
    "suspicious_action": 0.4977
  },
  "forensics": {
    "spf": "SOFTFAIL",
    "dkim": "NONE",
    "dmarc": "NONE",
    "reply_to_mismatch": true,
    "suspicious_url_count": 1,
    "domains": ["chase-security-alert.com", "suspicious-relay.xyz"]
  },
  "risk": {
    "score": 68,
    "level": "HIGH",
    "contributing_factors": [
      "ML Classifier high phishing probability (99.5%) [+ 34.8 pts]",
      "SPF authentication unverified (SOFTFAIL) [+4.0 pts]",
      "Reply-To domain differs from From domain (domain mismatch) [+8.0 pts]",
      "1 suspicious URL characteristics detected [+4.0 pts]"
    ]
  },
  "ai_reasoning": {
    "summary": "High-severity security risk (68/100 - HIGH)...",
    "why_detected": [
      "The MailShield ML model detected high-probability phishing indicators (99.5% confidence).",
      "Domain mismatch identified: Sender differs from Reply-To destination."
    ],
    "key_indicators": [
      "ML Classifier verdict: Phishing (99.5%)",
      "Reply-To and From header domain spoofing/mismatch",
      "Suspicious URLs detected"
    ],
    "recommended_actions": [
      "Quarantine this email across all enterprise mailboxes immediately.",
      "Block extracted sender domain and suspicious URLs at perimeter firewall."
    ],
    "confidence_note": "Calculated via MailShield deterministic forensic pipeline."
  }
}
```

---

## 8. How the Frontend Connects to the API

The MailShield frontend is located in `frontend/`.
- Frontend dev server: `http://localhost:5173`
- API Base URL: `http://localhost:8000`
- Upload component invokes `POST /api/analyze-email` directly via `apiClient`.
- CORS is enabled on the backend for local development and LAN testing.

---

## 9. How to Replace Gemini with Ollama Later

The reasoning engine is designed around the `ReasoningProvider` abstraction (`backend/services/ai_reasoning_service.py`):
1. Install and start Ollama locally (`ollama run llama3`).
2. Update `.env`:
   ```env
   REASONING_PROVIDER=ollama
   OLLAMA_BASE_URL=http://localhost:11434
   OLLAMA_MODEL=llama3
   ```
3. Restart FastAPI:
   ```powershell
   backend\.venv\Scripts\uvicorn.exe backend.main:app --reload
   ```
4. The frontend API contract (`/api/analyze-email`) remains 100% identical.
