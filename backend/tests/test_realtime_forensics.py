"""
End-to-end tests for the real-time forensic pipeline (v2).

Covers the 10 required scenarios through the REAL pipeline (forensic engine ->
ML -> NLP -> rules -> fusion -> verdict -> ledger), false-positive / false-negative
counting, per-user isolation of verdicts, ledger tamper detection, and the
real-time monitor's de-duplication (Gmail API calls are replaced by a local
stub in this test only — the pipeline under test is the production one).

Run:  python -m pytest tests/test_realtime_forensics.py -q -s
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="mailshield-rt-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'rt.db').as_posix()}"
os.environ["UPLOAD_STORAGE_DIR"] = str(_TMP / "evidence")
os.environ["JWT_SECRET_KEY"] = "test-secret-" + "y" * 40
os.environ["GMAIL_MONITOR_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

DATA = Path(__file__).parent / "test_data" / "realtime"
PW = "Str0ngPassw0rd!"

# expected: True = must be flagged (THREAT), False = must NOT be a THREAT
EXPECTED = {
    "01_personal.eml": False,
    "02_marketing.eml": False,
    "03_phishing_bank.eml": True,
    "04_spoofed_sender.eml": True,
    "05_suspicious_url.eml": True,
    "06_malicious_attachment.eml": True,
    "07_credential_phishing.eml": True,
    "08_bec.eml": True,
    "09_auth_fail.eml": None,          # benign content, failed auth: SUSPICIOUS or THREAT both defensible
    "10_legit_unusual_format.eml": False,
}


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:
        yield c


def _user(c, email):
    r = c.post("/api/auth/register", json={"name": "RT User", "email": email, "password": PW, "confirm_password": PW})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _analyze(c, h, name):
    with open(DATA / name, "rb") as fh:
        r = c.post("/api/v1/analyze-email", headers=h, files={"file": (name, fh, "message/rfc822")})
    assert r.status_code == 200, r.text
    inv_id = r.json()["analysis_id"]
    v = c.get(f"/api/v1/investigations/{inv_id}/verdict", headers=h)
    assert v.status_code == 200, v.text
    return inv_id, v.json()


def test_ten_scenarios_and_error_rates(client):
    h = _user(client, "rt-a@example.com")
    fp = fn = tp = tn = 0
    rows = []
    for name, expect in EXPECTED.items():
        _, v = _analyze(client, h, name)
        c = v["conclusion"]
        flagged = c["status"] == "THREAT"
        rows.append(f'{name:32s} {c["status"]:10s} risk={c["risk_score"]:5.1f} ML={c["ml_risk"]} NLP={c["nlp_risk"]} '
                    f'type={c["threat_type"]} vectors={[x["key"] for x in v["attack_vectors"]]}')
        # every verdict is generated from evidence and carries integrity
        assert v["integrity"]["status"] == "VALID"
        assert c["recommended_action"]
        if expect is True:
            tp += flagged
            fn += not flagged
            assert v["forensic_agent"]["triggered"], name
            assert v["attack_vectors"], f"{name}: threat without evidence-backed vector"
        elif expect is False:
            tn += not flagged
            fp += flagged
    print("\n" + "\n".join(rows))
    print(f"\nTP={tp} FN={fn} TN={tn} FP={fp}  FNR={fn / max(1, tp + fn):.2f}  FPR={fp / max(1, tn + fp):.2f}")
    assert fp == 0, "a legitimate e-mail was classified as THREAT"
    assert fn <= 1, "more than one threat was missed"


def test_origin_never_fabricated(client):
    h = _user(client, "rt-origin@example.com")
    _, v = _analyze(client, h, "03_phishing_bank.eml")
    o = v["origin"]
    assert o and o["determined"]
    assert o["observed_ip"]["value"] == "185.220.101.34"          # exactly what the Received header says
    assert o["observed_ip"]["status"] == "OBSERVED"
    for k in ("country", "city", "asn", "network"):
        assert o[k]["status"] in ("INFERRED", "UNKNOWN", "OBSERVED")
        if o[k]["value"] is None:
            assert o[k]["status"] == "UNKNOWN"
    assert "does not prove" in o["disclaimer"]


def test_verdict_isolation(client):
    a = _user(client, "rt-owner@example.com")
    b = _user(client, "rt-other@example.com")
    inv_id, _ = _analyze(client, a, "08_bec.eml")
    assert client.get(f"/api/v1/investigations/{inv_id}/verdict", headers=b).status_code == 404
    assert client.get(f"/api/v1/investigations/{inv_id}/evidence/verify", headers=b).status_code == 404
    assert client.delete(f"/api/v1/investigations/{inv_id}", headers=b).status_code == 404
    assert client.get(f"/api/v1/investigations/{inv_id}/verdict").status_code == 401


def test_ledger_detects_tampering(client):
    from app.database.session import SessionLocal
    from app.models.investigation import Report
    h = _user(client, "rt-ledger@example.com")
    inv_id, v = _analyze(client, h, "07_credential_phishing.eml")
    assert v["integrity"]["status"] == "VALID"
    db = SessionLocal()
    rep = db.query(Report).filter(Report.investigation_id == inv_id).first()
    data = dict(rep.report_json)
    data["tampered"] = "risk score edited after the fact"
    rep.report_json = data
    db.commit()
    db.close()
    r = client.get(f"/api/v1/investigations/{inv_id}/evidence/verify", headers=h).json()
    assert r["status"] == "MODIFIED" and r["forensic_report"]["status"] == "MODIFIED"


def test_realtime_monitor_dedup(client, monkeypatch):
    """New messages are analysed exactly once; the owner's own mail is skipped."""
    from app.database.session import SessionLocal
    from app.models.gmail_account import GmailAccount
    from app.models.investigation import Investigation
    from app.models.processed_email import ProcessedEmail
    from app.models.user import User
    import services.email_monitor as mon
    import services.gmail_service as gs

    h = _user(client, "rt-monitor@example.com")
    db = SessionLocal()
    uid = db.query(User.id).filter(User.email == "rt-monitor@example.com").scalar()
    db.add(GmailAccount(user_id=uid, google_email="me@gmail.com", encrypted_access_token="x"))
    db.commit()

    inbox = {
        "m1": (DATA / "03_phishing_bank.eml").read_bytes(),
        "m2": (DATA / "01_personal.eml").read_bytes(),
        "m3": b"From: me@gmail.com\r\nSubject: note to self\r\n\r\nhello",
    }

    class StubSession:
        _access_token = "stub"
        user_email = "me@gmail.com"

        async def get_raw_email(self, mid):
            return inbox[mid]

    async def fake_list(token, after, limit):
        return list(inbox)

    monkeypatch.setattr(gs, "load_user_gmail_session", lambda user_id, db: StubSession())
    monkeypatch.setattr(mon, "_list_new_ids", fake_list)

    first = asyncio.run(mon.process_user(uid))
    second = asyncio.run(mon.process_user(uid))
    assert first == 2 and second == 0
    rows = db.query(ProcessedEmail).filter(ProcessedEmail.user_id == uid).all()
    assert {r.provider_message_id: r.status for r in rows} == {"m1": "ANALYZED", "m2": "ANALYZED", "m3": "SKIPPED"}
    assert db.query(Investigation).filter(Investigation.user_id == uid).count() == 2
    recent = client.get("/api/v1/monitor/recent", headers=h).json()
    assert {r["message_id"] for r in recent} == {"m1", "m2", "m3"}
    assert any(r["verdict"] == "THREAT" for r in recent)
    db.close()


def test_delete_my_data(client):
    h = _user(client, "rt-erase@example.com")
    _analyze(client, h, "01_personal.eml")
    r = client.delete("/api/v1/privacy/my-data", headers=h)
    assert r.status_code == 200 and r.json()["deleted_investigations"] == 1
    assert client.get("/api/v1/investigations", headers=h).json() == []
