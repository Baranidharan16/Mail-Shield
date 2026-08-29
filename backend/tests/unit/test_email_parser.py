import os
from app.forensic.email_parser import parse_eml_bytes

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def test_parses_legitimate_email_basic_fields():
    parsed = parse_eml_bytes(_load("01_legitimate.eml"))
    assert parsed.from_address == "bob@acmecorp.example"
    assert parsed.from_display_name == "Bob Smith"
    assert "alice@acmecorp.example" in parsed.to_addresses
    assert parsed.subject == "Q3 project timeline review"
    assert parsed.sender_domain == "acmecorp.example"
    assert parsed.message_id is not None
    assert parsed.date_parsed is not None
    assert len(parsed.received_headers_raw) == 3


def test_parses_html_body():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    assert "verify your" in parsed.html_body.lower()
    assert "identity" in parsed.html_body.lower()
    assert parsed.content_type == "text/html"


def test_reply_to_and_return_path_domains_differ_for_spoofed_email():
    parsed = parse_eml_bytes(_load("02_spoofed_sender.eml"))
    assert parsed.reply_to_domain == "protonmail.com"
    assert parsed.return_path_domain == "mailer-svc-77.example"
    assert parsed.sender_domain == "gmail.com"


def test_no_exception_on_malformed_bytes():
    # Should not raise, and should degrade gracefully
    parsed = parse_eml_bytes(b"Not a real email at all just bytes")
    assert parsed is not None
