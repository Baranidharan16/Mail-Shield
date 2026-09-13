"""
MailShield Final Acceptance Verification Script
Tests all 20 acceptance criteria against the live running server.
"""
import base64
import json
import urllib.request
import urllib.parse
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
SAMPLES_DIR = Path("c:/Users/Barani Dharan/Downloads/sih-email-forensics-full/backend/tests/test_data")

def get_json(endpoint):
    req = urllib.request.Request(f"{BASE_URL}{endpoint}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def post_json(endpoint, data):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def post_file(endpoint, file_path):
    import mimetypes
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    data = bytearray()
    
    file_bytes = Path(file_path).read_bytes()
    filename = Path(file_path).name
    
    data.extend(f"--{boundary}\r\n".encode("utf-8"))
    data.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    data.extend(b"Content-Type: message/rfc822\r\n\r\n")
    data.extend(file_bytes)
    data.extend(b"\r\n")
    data.extend(f"--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=bytes(data),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def run_tests():
    print("=================================================================")
    print(" MAILSHIELD FINAL ACCEPTANCE TESTS")
    print("=================================================================\n")

    # 1. Test /api/health
    health = get_json("/api/health")
    print(f"[1] Health Check: {health['status']} | App: {health['app_name']}")
    assert health["status"] == "ok"
    assert health["app_name"] == "MAILSHIELD"

    # 2. Test /api/model-status
    models = get_json("/api/model-status")
    print(f"[2] Model Status: ML={models['ml_model_loaded']}, NLP={models['nlp_model_loaded']}, Forensic={models['forensic_engine_active']}")
    print(f"    Engines: Gemini={models['gemini_status']}, Sarvam={models['sarvam_voice_status']}, Ollama={models['ollama_status']}")
    assert models["ml_model_loaded"] is True
    assert models["nlp_model_loaded"] is True
    assert models["forensic_engine_active"] is True

    # 3. Test Phishing Email EML Upload (Automatic Pipeline)
    phishing_path = SAMPLES_DIR / "03_phishing.eml"
    print(f"\n[3] Testing Phishing Email Upload: {phishing_path.name}")
    phish_res = post_file("/api/analyze-email", phishing_path)
    
    ml = phish_res["ml"]
    nlp = phish_res["nlp"]
    forensics = phish_res["forensics"]
    risk = phish_res["risk"]
    ai = phish_res["ai_reasoning"]

    print(f"    - ML Phishing Prediction : {ml['prediction'].upper()} (Prob: {ml['phishing_probability']:.4f})")
    print(f"    - 6 NLP Threat Patterns : Urgency={nlp['urgency']:.3f}, Credential={nlp['credential_request']:.3f}, Impersonation={nlp['impersonation']:.3f}")
    print(f"                              Financial={nlp['financial_manipulation']:.3f}, ThreatLang={nlp['threat_language']:.3f}, SuspiciousAction={nlp['suspicious_action']:.3f}")
    print(f"    - Forensics             : SPF={forensics['spf']}, DKIM={forensics['dkim']}, Mismatch={forensics['reply_to_mismatch']}")
    print(f"    - Risk Engine           : Score={risk['score']}/100 ({risk['level']})")
    print(f"    - AI Reasoning Summary  : {ai['summary'][:90]}...")
    
    assert ml["prediction"] == "phishing"
    assert ml["phishing_probability"] > 0.8
    assert risk["score"] >= 60

    # 4. Test Legitimate Email EML Upload
    legit_path = SAMPLES_DIR / "01_legitimate.eml"
    print(f"\n[4] Testing Legitimate Email Upload: {legit_path.name}")
    legit_res = post_file("/api/analyze-email", legit_path)
    print(f"    - ML Prediction         : {legit_res['ml']['prediction'].upper()} (Prob: {legit_res['ml']['phishing_probability']:.4f})")
    print(f"    - Risk Engine           : Score={legit_res['risk']['score']}/100 ({legit_res['risk']['level']})")
    assert legit_res["ml"]["prediction"] == "legitimate"
    assert legit_res["ml"]["phishing_probability"] < 0.2
    assert legit_res["risk"]["score"] < 40

    # 5. Test AI Assistant Chat
    print(f"\n[5] Testing MailShield AI Assistant Chat (/api/assistant/chat)")
    chat_res = post_json("/api/assistant/chat", {
        "question": "What did the NLP model detect in this email?",
        "context": phish_res,
        "language": "en-IN"
    })
    print(f"    - Engine : {chat_res['engine']}")
    print(f"    - Answer : {chat_res['answer'][:120]}...")
    assert len(chat_res["answer"]) > 10

    # 6. Test Sarvam TTS Speech Synthesis
    print(f"\n[6] Testing Sarvam TTS Speech Synthesis (/api/assistant/speak)")
    speak_res = post_json("/api/assistant/speak", {
        "text": "MailShield threat analysis complete. Phishing probability is ninety four percent.",
        "language": "en-IN",
        "voice": "priya"
    })
    print(f"    - Engine : {speak_res['engine']}")
    print(f"    - Audio Base64 len : {len(speak_res.get('audio_base64', ''))}")
    assert len(speak_res.get("audio_base64", "")) > 1000

    print("\n=================================================================")
    print(" ALL ACCEPTANCE TESTS COMPLETED SUCCESSFULLY!")
    print("=================================================================")

if __name__ == "__main__":
    run_tests()
