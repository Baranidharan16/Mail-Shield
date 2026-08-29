import os
from app.forensic.email_parser import parse_eml_bytes
from app.forensic.auth_analyzer import analyze_authentication

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def _analyze(filename):
    parsed = parse_eml_bytes(_load(filename))
    return analyze_authentication(
        parsed.authentication_results_raw,
        parsed.dkim_signature_raw,
        parsed.sender_domain,
        parsed.reply_to_domain,
        parsed.return_path_domain,
    )


def test_legitimate_email_passes_all_checks():
    auth = _analyze("01_legitimate.eml")
    assert auth.spf.result == "PASS"
    assert auth.dkim.result == "PASS"
    assert auth.dmarc.result == "PASS"
    assert auth.source == "OBSERVED"


def test_auth_failure_email_detected():
    auth = _analyze("07_auth_failure.eml")
    assert auth.spf.result == "FAIL"
    assert auth.dkim.result == "FAIL"
    assert auth.dmarc.result == "FAIL"


def test_spoofed_sender_spf_fail_dmarc_fail():
    auth = _analyze("02_spoofed_sender.eml")
    assert auth.spf.result == "FAIL"
    assert auth.dmarc.result == "FAIL"


def test_missing_authentication_results_reports_insufficient_data():
    from app.forensic.auth_analyzer import analyze_authentication as aa
    result = aa([], [], "example.com", None, None)
    assert result.source == "INSUFFICIENT_DATA"
    assert result.spf.result == "UNKNOWN"
    assert len(result.notes) > 0


def test_valid_results_are_normalized_to_known_set():
    from app.forensic.auth_analyzer import VALID_RESULTS
    auth = _analyze("01_legitimate.eml")
    assert auth.spf.result in VALID_RESULTS
    assert auth.dkim.result in VALID_RESULTS
    assert auth.dmarc.result in VALID_RESULTS
