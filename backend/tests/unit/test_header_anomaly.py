import os
from app.forensic.email_parser import parse_eml_bytes
from app.forensic.received_parser import parse_received_headers
from app.forensic.auth_analyzer import analyze_authentication
from app.forensic.header_anomaly import run_header_anomaly_rules

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def _run(filename):
    parsed = parse_eml_bytes(_load(filename))
    hops = parse_received_headers(parsed.received_headers_raw)
    auth = analyze_authentication(
        parsed.authentication_results_raw, parsed.dkim_signature_raw,
        parsed.sender_domain, parsed.reply_to_domain, parsed.return_path_domain,
    )
    return run_header_anomaly_rules(parsed, auth, len(hops))


def test_spoofed_sender_triggers_reply_to_mismatch():
    findings = _run("02_spoofed_sender.eml")
    rule_ids = {f.rule_id for f in findings}
    assert "HDR-001" in rule_ids  # From/Reply-To mismatch


def test_spoofed_sender_triggers_display_name_or_exec_impersonation():
    findings = _run("02_spoofed_sender.eml")
    rule_ids = {f.rule_id for f in findings}
    assert "HDR-009" in rule_ids or "HDR-010" in rule_ids


def test_every_finding_has_required_fields():
    findings = _run("03_phishing.eml")
    assert len(findings) > 0
    for f in findings:
        assert f.rule_id
        assert f.title
        assert f.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert f.explanation
        assert f.confidence > 0


def test_legitimate_email_has_few_or_no_high_severity_findings():
    findings = _run("01_legitimate.eml")
    high_severity = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
    assert len(high_severity) == 0


def test_auth_failure_email_triggers_spf_and_dmarc_rules():
    findings = _run("07_auth_failure.eml")
    rule_ids = {f.rule_id for f in findings}
    assert "HDR-005" in rule_ids or "HDR-006" in rule_ids
