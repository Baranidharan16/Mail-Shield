"""
Integration tests that run the full API workflow against a REAL PostgreSQL
database, not SQLite. This closes the gap where the rest of the suite only
ever exercised SQLite in this sandbox.

Requires a reachable Postgres instance; set POSTGRES_TEST_URL to point at
it (defaults to the local dev instance used by docker-compose.yml /
the README setup instructions). If Postgres is not reachable, the whole
module is skipped rather than failing the suite.
"""
import os
import time

POSTGRES_TEST_URL = os.environ.get(
    "POSTGRES_TEST_URL",
    "postgresql+psycopg2://forensics:forensics_dev_password@localhost:5432/email_forensics_test",
)

import pytest

try:
    import psycopg2
    from urllib.parse import urlparse

    def _pg_reachable(url: str) -> bool:
        # Convert SQLAlchemy-style URL to a plain psycopg2 DSN check
        plain = url.replace("postgresql+psycopg2://", "postgresql://")
        try:
            conn = psycopg2.connect(plain, connect_timeout=2)
            conn.close()
            return True
        except Exception:
            return False

    _PG_UP = _pg_reachable(POSTGRES_TEST_URL)
except Exception:
    _PG_UP = False

pytestmark = pytest.mark.skipif(not _PG_UP, reason="PostgreSQL not reachable at POSTGRES_TEST_URL")

if _PG_UP:
    os.environ["DATABASE_URL"] = POSTGRES_TEST_URL
    os.environ.setdefault("UPLOAD_STORAGE_DIR", "/tmp/forensic_pg_test_evidence")

    from fastapi.testclient import TestClient
    from app.database.session import Base, engine
    from app.main import app

    TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")

    @pytest.fixture()
    def pg_client():
        from app.models import investigation as _models  # noqa: F401
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        with TestClient(app) as c:
            yield c

    def _upload(client, filename):
        path = os.path.join(TEST_DATA_DIR, filename)
        with open(path, "rb") as f:
            return client.post("/api/v1/investigations", files={"file": (filename, f, "message/rfc822")})

    def _wait(client, inv_id, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            r = client.get(f"/api/v1/investigations/{inv_id}")
            if r.json()["status"] in ("COMPLETED", "FAILED"):
                return r
            time.sleep(0.1)
        raise TimeoutError

    def test_postgres_health(pg_client):
        r = pg_client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["database"] == "ok"

    def test_postgres_full_pipeline(pg_client):
        r = _upload(pg_client, "03_phishing.eml")
        assert r.status_code == 201
        inv_id = r.json()["id"]
        detail = _wait(pg_client, inv_id).json()
        assert detail["status"] == "COMPLETED"
        assert detail["risk_score"] > 0
        assert len(detail["urls"]) >= 1
        assert detail["email_metadata"]["sender_domain"] == "secure-victimcorp-login.top"

    def test_postgres_relationships_persist_correctly(pg_client):
        r = _upload(pg_client, "02_spoofed_sender.eml")
        inv_id = r.json()["id"]
        detail = _wait(pg_client, inv_id).json()
        assert detail["authentication_result"]["spf_result"] == "FAIL"
        assert len(detail["findings"]) > 0
        assert detail["risk_score_breakdown"] is not None

    def test_postgres_list_and_report(pg_client):
        r = _upload(pg_client, "05_bec_payment_request.eml")
        inv_id = r.json()["id"]
        _wait(pg_client, inv_id)
        listing = pg_client.get("/api/v1/investigations")
        assert listing.status_code == 200
        report = pg_client.get(f"/api/v1/investigations/{inv_id}/report")
        assert report.status_code == 200
        assert "threat_score" in report.json()
