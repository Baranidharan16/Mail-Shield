"""
End-to-end tests for authentication, sessions and per-user data isolation.

Run (from backend/):   python -m pytest tests/test_auth_isolation.py -q
Uses its own throw-away SQLite database; your forensics.db is never touched.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="mailshield-auth-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["UPLOAD_STORAGE_DIR"] = str(_TMP / "evidence")
os.environ["JWT_SECRET_KEY"] = "test-secret-" + "x" * 40
os.environ["APP_ENV"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

EML = Path(__file__).parent / "test_data" / "03_phishing.eml"
PW = "Str0ngPassw0rd!"


@pytest.fixture(scope="module")
def app_client():
    with TestClient(main.app) as c:
        yield c


def _client():
    return TestClient(main.app)


def _register(c, name, email, password=PW):
    return c.post("/api/auth/register", json={
        "name": name, "email": email, "password": password, "confirm_password": password,
    })


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_register_login_refresh_logout(app_client):
    c = _client()
    r = _register(c, "Alice Analyst", "Alice@Example.com")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "password" not in r.text and "password_hash" not in r.text
    assert "ms_refresh" in r.headers.get("set-cookie", "")
    assert "httponly" in r.headers["set-cookie"].lower()

    # duplicate (case-insensitive)
    assert _register(_client(), "Alice Two", "ALICE@example.com").status_code == 409

    # page reload: no access token in memory, cookie restores the session
    r = c.post("/api/auth/refresh")
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    assert c.get("/api/auth/me", headers=_auth(tok)).json()["name"] == "Alice Analyst"

    # logout revokes the session: both the access token and the cookie stop working
    assert c.post("/api/auth/logout", headers=_auth(tok)).status_code == 200
    assert c.get("/api/auth/me", headers=_auth(tok)).status_code == 401
    assert c.post("/api/auth/refresh").status_code == 401

    # login again (e.g. from another browser)
    c2 = _client()
    r = c2.post("/api/auth/login", json={"email": "alice@example.com", "password": PW, "remember_me": True})
    assert r.status_code == 200
    assert "max-age" in r.headers["set-cookie"].lower()


def test_login_errors_do_not_leak(app_client):
    c = _client()
    _register(c, "Carol", "carol@example.com")
    wrong_pw = c.post("/api/auth/login", json={"email": "carol@example.com", "password": "nope-nope1"})
    no_user = c.post("/api/auth/login", json={"email": "ghost@example.com", "password": "nope-nope1"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_validation_messages(app_client):
    c = _client()
    assert _register(c, "Dan", "dan@example.com", "short").status_code == 422
    assert _register(c, "Dan", "dan@example.com", "password123").status_code == 422   # common
    assert _register(c, "Dan", "not-an-email").status_code == 422
    r = c.post("/api/auth/register", json={"name": "Dan", "email": "dan@example.com",
                                          "password": PW, "confirm_password": PW + "x"})
    assert r.status_code == 422


def test_protected_routes_require_auth(app_client):
    c = _client()
    for path in ["/api/v1/investigations", "/api/v1/alerts", "/api/v1/dashboard/stats",
                 "/api/v1/cases", "/api/v1/system/campaigns", "/api/v1/blockchain/blocks",
                 "/api/auth/me"]:
        assert c.get(path).status_code == 401, path
    assert c.get("/api/v1/investigations", headers=_auth("garbage")).status_code == 401
    # forged token signed with another key
    import jwt
    forged = jwt.encode({"sub": "x", "sid": "y", "iat": 0, "exp": 9999999999}, "attacker", algorithm="HS256")
    assert c.get("/api/v1/investigations", headers=_auth(forged)).status_code == 401


def test_user_data_isolation(app_client):
    a, b = _client(), _client()
    ta = _register(a, "User A", "usera@example.com").json()["access_token"]
    tb = _register(b, "User B", "userb@example.com").json()["access_token"]

    with EML.open("rb") as fh:
        r = a.post("/api/v1/investigations", headers=_auth(ta),
                   files={"file": ("a.eml", fh, "message/rfc822")})
    assert r.status_code == 201, r.text
    inv_id = r.json()["id"]

    # A sees it
    assert any(i["id"] == inv_id for i in a.get("/api/v1/investigations", headers=_auth(ta)).json())
    assert a.get(f"/api/v1/investigations/{inv_id}", headers=_auth(ta)).status_code == 200

    # B sees nothing and cannot reach any sub-resource by id (IDOR)
    assert b.get("/api/v1/investigations", headers=_auth(tb)).json() == []
    for sub in ["", "/findings", "/indicators", "/report", "/graph", "/timeline", "/geo",
                "/forensic-ai", "/whatif", "/campaign", "/attribution", "/story", "/report/pdf"]:
        r = b.get(f"/api/v1/investigations/{inv_id}{sub}", headers=_auth(tb))
        assert r.status_code == 404, (sub, r.status_code)
    assert b.get(f"/api/v1/cases/{inv_id}", headers=_auth(tb)).status_code == 404
    assert b.post("/api/v1/system/action", headers=_auth(tb),
                  json={"investigation_id": inv_id, "action": "MARK_SAFE"}).status_code == 404
    assert b.get("/api/v1/dashboard/stats", headers=_auth(tb)).json()["total_investigations"] == 0
    assert b.get(f"/api/v1/blockchain/verify/{inv_id}", headers=_auth(tb)).status_code == 404
