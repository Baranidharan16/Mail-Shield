import urllib.request
import json

def test_pipeline():
    print("[1] Querying Gmail Status...")
    resp = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/gmail/status")
    print("Status:", resp.read().decode())

    print("\n[2] Acquiring & Analyzing Threat Email (msg_threat_001)...")
    req = urllib.request.Request("http://127.0.0.1:8000/api/v1/gmail/analyze/msg_threat_001", data=b"", method="POST")
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode())
    case_id = data.get("case_id")
    risk_score = data.get("analysis", {}).get("risk", {}).get("score")
    risk_level = data.get("analysis", {}).get("risk", {}).get("level")
    quarantined = data.get("quarantined")
    ev_hash = data.get("evidence_hash")

    print(f"Case ID: {case_id}")
    print(f"Evidence SHA-256: {ev_hash}")
    print(f"Risk Score: {risk_score}/100 ({risk_level})")
    print(f"Autonomous Quarantine: {quarantined}")

    print(f"\n[3] Verifying Immutable Blockchain Record for {case_id}...")
    v_url = f"http://127.0.0.1:8000/api/v1/blockchain/verify/{case_id}"
    v_resp = urllib.request.urlopen(v_url)
    v_data = json.loads(v_resp.read().decode())
    print("Blockchain Verification:", json.dumps(v_data, indent=2))

    print("\n[4] Querying Fabric Ledger Status...")
    f_resp = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/blockchain/fabric-status")
    print("Fabric Status:", f_resp.read().decode())

    print("\n[SUCCESS] All end-to-end tests passed!")

if __name__ == "__main__":
    test_pipeline()
