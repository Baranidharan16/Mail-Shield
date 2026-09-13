"""
MailShield Comprehensive Verification Suite
Tests health, model-status, .eml upload, raw text, NLP labels, risk scoring, and error handling.
"""
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from main import app
from fastapi.testclient import TestClient

print("=== STARTING COMPLETE MAILSHIELD VERIFICATION SUITE ===\n")

with TestClient(app) as client:
    # 1. Health Endpoint
    r_health = client.get("/api/health")
    assert r_health.status_code == 200, f"Health check failed: {r_health.text}"
    print("[PASS] 1. GET /api/health: OK ->", r_health.json())

    # 2. Model Status Endpoint
    r_models = client.get("/api/model-status")
    assert r_models.status_code == 200, f"Model status failed: {r_models.text}"
    m_data = r_models.json()
    assert m_data["ml_model_loaded"] is True, "ML model not loaded"
    assert m_data["nlp_model_loaded"] is True, "NLP model not loaded"
    print("[PASS] 2. GET /api/model-status: Both Keras models loaded in RAM.")

    # 3. Phishing .eml Analysis
    with open("test_data/synthetic_emails/03_phishing.eml", "rb") as f:
        r_phish = client.post("/api/analyze-email", files={"file": ("03_phishing.eml", f, "message/rfc822")})
    assert r_phish.status_code == 200, f"Phishing upload failed: {r_phish.text}"
    p_data = r_phish.json()
    ml_pred = p_data["ml"]["prediction"]
    ml_prob = p_data["ml"]["phishing_probability"]
    risk_score = p_data["risk"]["score"]
    risk_lvl = p_data["risk"]["level"]
    assert ml_pred == "phishing", f"Expected phishing, got {ml_pred}"
    assert ml_prob > 0.90, f"Expected high probability, got {ml_prob}"
    print(f"[PASS] 3. POST /api/analyze-email (.eml): Phishing detected (prob={ml_prob}, risk={risk_score}/100 [{risk_lvl}])")

    # 4. All 6 NLP Labels Present and Numeric
    nlp_res = p_data["nlp"]
    required_nlp_labels = [
        "urgency",
        "credential_request",
        "financial_manipulation",
        "impersonation",
        "threat_language",
        "suspicious_action"
    ]
    for lbl in required_nlp_labels:
        assert lbl in nlp_res, f"Missing NLP label: {lbl}"
        assert isinstance(nlp_res[lbl], (int, float)), f"Invalid label value for {lbl}"
    print("[PASS] 4. NLP Threat Patterns: All 6 threat patterns validated:")
    for lbl in required_nlp_labels:
        print(f"       * {lbl}: {nlp_res[lbl]}")

    # 5. Legitimate Email Test
    with open("test_data/synthetic_emails/01_legitimate.eml", "rb") as f:
        r_legit = client.post("/api/analyze-email", files={"file": ("01_legitimate.eml", f, "message/rfc822")})
    assert r_legit.status_code == 200
    l_data = r_legit.json()
    assert l_data["ml"]["prediction"] == "legitimate"
    assert l_data["risk"]["level"] == "LOW"
    print(f"[PASS] 5. Legitimate email test: Classified as legitimate (prob={l_data['ml']['phishing_probability']}, risk={l_data['risk']['score']}/100 [{l_data['risk']['level']}])")

    # 6. Raw Text Analysis
    r_raw = client.post(
        "/api/analyze-email",
        data={
            "raw_text": "URGENT: Click here http://suspicious-login.xyz to verify your bank password.",
            "subject": "Urgent security notice"
        }
    )
    assert r_raw.status_code == 200
    raw_data = r_raw.json()
    assert raw_data["ml"]["prediction"] == "phishing"
    print(f"[PASS] 6. Raw text analysis: Processed (prediction={raw_data['ml']['prediction']}, risk={raw_data['risk']['score']}/100)")

    # 7. Error Handling for Empty File
    r_empty = client.post("/api/analyze-email", files={"file": ("empty.eml", b"", "message/rfc822")})
    assert r_empty.status_code == 400
    print("[PASS] 7. Error Handling: Rejected empty file with HTTP 400.")

print("\n=== ALL 7 VERIFICATION SUITE TESTS PASSED PERFECTLY! ===")
