import os
from app.forensic.email_parser import parse_eml_bytes
from app.forensic.url_analyzer import extract_urls

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def test_extracts_urls_from_html_phishing_email():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    urls = extract_urls(parsed.text_body, parsed.html_body)
    assert len(urls) >= 1
    ip_based = [u for u in urls if u.is_ip_based]
    assert len(ip_based) >= 1
    assert ip_based[0].risk_score > 0


def test_anchor_text_mismatch_detected():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    urls = extract_urls(parsed.text_body, parsed.html_body)
    mismatched = [u for u in urls if u.anchor_text_mismatch]
    assert len(mismatched) >= 1


def test_shortener_detected():
    parsed = parse_eml_bytes(_load("04_credential_harvesting.eml"))
    urls = extract_urls(parsed.text_body, parsed.html_body)
    shortened = [u for u in urls if u.is_shortened]
    assert len(shortened) >= 1


def test_https_url_scores_lower_than_http_ip_url():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    urls = extract_urls(parsed.text_body, parsed.html_body)
    ip_url = next(u for u in urls if u.is_ip_based)
    assert ip_url.is_https is False
    assert ip_url.risk_score >= 25


def test_no_urls_in_plain_legitimate_email():
    parsed = parse_eml_bytes(_load("01_legitimate.eml"))
    urls = extract_urls(parsed.text_body, parsed.html_body)
    assert urls == []
