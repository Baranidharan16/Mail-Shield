import os
from app.forensic.email_parser import parse_eml_bytes
from app.forensic.social_engineering import analyze_social_engineering

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def test_detects_credential_request_and_urgency():
    parsed = parse_eml_bytes(_load("04_credential_harvesting.eml"))
    indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")
    types = {i.indicator_type for i in indicators}
    assert "credential_request" in types
    assert "urgency" in types or "password_reset_pressure" in types


def test_detects_payment_diversion_language():
    parsed = parse_eml_bytes(_load("05_bec_payment_request.eml"))
    indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")
    types = {i.indicator_type for i in indicators}
    assert "invoice_payment_diversion" in types
    assert "payment_request" in types


def test_detects_executive_impersonation_language():
    parsed = parse_eml_bytes(_load("02_spoofed_sender.eml"))
    indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")
    types = {i.indicator_type for i in indicators}
    assert "executive_impersonation" in types


def test_legitimate_email_has_no_or_minimal_indicators():
    parsed = parse_eml_bytes(_load("01_legitimate.eml"))
    indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")
    assert len(indicators) == 0


def test_every_indicator_has_explanation_and_evidence():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    indicators = analyze_social_engineering(parsed.text_body, parsed.html_body, parsed.subject or "")
    assert len(indicators) > 0
    for i in indicators:
        assert i.explanation
        assert i.matched_evidence
