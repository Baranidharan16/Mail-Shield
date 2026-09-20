import os
import time
import tempfile

# IMPORTANT: env vars must be set BEFORE any `app.*` module is imported
# anywhere in the process (including by other test files collected in the
# same session), otherwise the SQLAlchemy engine/Base singletons bind to
# the wrong database. This mirrors how the real app reads config once at
# startup from the environment.
_TMP_DIR = tempfile.mkdtemp(prefix="forensic_platform_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DIR}/test.db"
os.environ["UPLOAD_STORAGE_DIR"] = f"{_TMP_DIR}/evidence"

import pytest
from fastapi.testclient import TestClient

from app.database.session import Base, engine
from app.main import app

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


@pytest.fixture()
def client():
    # Fresh schema for every test for isolation
    from app.models import investigation as _models  # noqa: F401
    from app.models import user as _u, auth_session as _s, gmail_account as _g  # noqa: F401
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as c:
        # All data routes now require an authenticated user.
        r = c.post("/api/auth/register", json={
            "name": "Integration Tester", "email": "it@example.com",
            "password": "Integr4tion-Pass", "confirm_password": "Integr4tion-Pass",
        })
        assert r.status_code == 201, r.text
        c.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        yield c


def _upload(client, filename):
    path = os.path.join(TEST_DATA_DIR, filename)
    with open(path, "rb") as f:
        response = client.post(
            "/api/v1/investigations",
            files={"file": (filename, f, "message/rfc822")},
        )
    return response


def _wait_for_completion(client, investigation_id, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        r = client.get(f"/api/v1/investigations/{investigation_id}")
        if r.json()["status"] in ("COMPLETED", "FAILED"):
            return r
        time.sleep(0.1)
    raise TimeoutError("Investigation did not complete in time")


def test_health_endpoint(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_upload_creates_investigation(client):
    r = _upload(client, "01_legitimate.eml")
    assert r.status_code == 201
    body = r.json()
    assert body["case_id"].startswith("CASE-")
    assert body["status"] == "QUEUED"


def test_full_pipeline_completes_and_scores_phishing_higher(client):
    r1 = _upload(client, "01_legitimate.eml")
    inv1 = r1.json()["id"]
    d1 = _wait_for_completion(client, inv1).json()
    assert d1["status"] == "COMPLETED"

    r2 = _upload(client, "03_phishing.eml")
    inv2 = r2.json()["id"]
    d2 = _wait_for_completion(client, inv2).json()
    assert d2["status"] == "COMPLETED"

    assert d2["risk_score"] > d1["risk_score"]
    assert d1["email_metadata"]["from_address"] == "bob@acmecorp.example"
    assert len(d2["urls"]) >= 1
    assert d2["risk_score_breakdown"] is not None


def test_rejects_non_eml_upload(client):
    r = client.post(
        "/api/v1/investigations",
        files={"file": ("malware.exe", b"not an email", "application/octet-stream")},
    )
    assert r.status_code == 415


def test_list_investigations(client):
    _upload(client, "01_legitimate.eml")
    r = client.get("/api/v1/investigations")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) >= 1


def test_get_nonexistent_investigation_returns_404(client):
    r = client.get("/api/v1/investigations/does-not-exist")
    assert r.status_code == 404


def test_report_endpoint_returns_structured_json(client):
    r = _upload(client, "05_bec_payment_request.eml")
    inv_id = r.json()["id"]
    _wait_for_completion(client, inv_id)
    report = client.get(f"/api/v1/investigations/{inv_id}/report")
    assert report.status_code == 200
    data = report.json()
    assert "threat_score" in data
    assert "disclaimers" in data
    assert data["case_id"]


def test_findings_and_indicators_endpoints(client):
    r = _upload(client, "04_credential_harvesting.eml")
    inv_id = r.json()["id"]
    _wait_for_completion(client, inv_id)

    findings = client.get(f"/api/v1/investigations/{inv_id}/findings")
    assert findings.status_code == 200
    assert isinstance(findings.json(), list)

    indicators = client.get(f"/api/v1/investigations/{inv_id}/indicators")
    assert indicators.status_code == 200
    types = {i["indicator_type"] for i in indicators.json()}
    assert "credential_request" in types


def test_no_raw_exception_leaked_on_bad_request(client):
    # Missing file entirely -> FastAPI validation error, not a raw traceback
    r = client.post("/api/v1/investigations")
    assert r.status_code == 422
    assert "Traceback" not in r.text


def test_origin_trace_endpoint_includes_sender_tracking(client):
    r = _upload(client, "03_phishing.eml")
    assert r.status_code in (200, 201, 202), r.text
    inv_id = r.json()["id"]
    _wait_for_completion(client, inv_id, timeout=60)
    t = client.get(f"/api/v1/investigations/{inv_id}/origin-trace")
    assert t.status_code == 200, t.text
    body = t.json()
    assert "sender_infrastructure" in body and "client_origin_detected" in body
    assert body["total_hops"] == len(body["relay_path"])
    for n in body["relay_path"]:
        assert "source" in n and "reputation" in n


def test_manual_ledger_registration_keeps_integrity_valid(client):
    r = _upload(client, "01_legitimate.eml")
    inv_id = r.json()["id"]
    _wait_for_completion(client, inv_id, timeout=60)
    reg = client.post(f"/api/v1/blockchain/register/{inv_id}")
    assert reg.status_code == 200, reg.text
    assert reg.json()["integrity_status"] == "VERIFIED"
    assert client.get("/api/v1/blockchain/verify").json()["verified"] is True
    blocks = client.get("/api/v1/blockchain/blocks").json()
    assert blocks and all(b["integrity_status"] == "VERIFIED" for b in blocks)
    integ = client.get(f"/api/v1/investigations/{inv_id}/evidence/verify").json()
    assert integ["status"] == "VALID", integ  # was falsely "MODIFIED" after manual registration


def test_concurrent_ledger_appends_do_not_fork():
    import threading
    from app.blockchain.ledger import anchor_evidence, verify_chain
    from app.database.session import SessionLocal
    from app.models import investigation as _m  # noqa: F401
    Base.metadata.create_all(bind=engine)

    def worker(i):
        db = SessionLocal()
        try:
            anchor_evidence(db, f"CASE-{i}", "a" * 64, "b" * 64)
        finally:
            db.close()
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    db = SessionLocal()
    try:
        assert verify_chain(db)["verified"] is True
    finally:
        db.close()
