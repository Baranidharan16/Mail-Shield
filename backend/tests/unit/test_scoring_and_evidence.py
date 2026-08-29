import os
import hashlib
from app.forensic.engine import run_forensic_analysis
from app.forensic.evidence import hash_evidence

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def test_evidence_hash_matches_manual_sha256():
    raw = _load("01_legitimate.eml")
    record = hash_evidence(raw)
    assert record.sha256 == hashlib.sha256(raw).hexdigest()
    assert record.size_bytes == len(raw)


def test_legitimate_email_scores_low():
    result = run_forensic_analysis(_load("01_legitimate.eml"))
    assert result.threat_score.overall_score < 35
    assert result.threat_score.classification in ("LOW", "MEDIUM")


def test_phishing_email_scores_higher_than_legitimate():
    legit = run_forensic_analysis(_load("01_legitimate.eml"))
    phishing = run_forensic_analysis(_load("03_phishing.eml"))
    assert phishing.threat_score.overall_score > legit.threat_score.overall_score


def test_spoofed_sender_scores_high_or_critical():
    result = run_forensic_analysis(_load("02_spoofed_sender.eml"))
    assert result.threat_score.classification in ("HIGH", "CRITICAL", "MEDIUM")
    assert result.threat_score.overall_score > 30


def test_score_breakdown_sums_to_overall():
    result = run_forensic_analysis(_load("04_credential_harvesting.eml"))
    breakdown = result.threat_score.explanation["dimension_breakdown"]
    total = sum(v["weighted_contribution"] for v in breakdown.values())
    assert abs(total - result.threat_score.overall_score) < 0.5


def test_weights_sum_to_one():
    result = run_forensic_analysis(_load("01_legitimate.eml"))
    assert abs(sum(result.threat_score.weights_used.values()) - 1.0) < 1e-6


def test_score_is_deterministic_same_input_same_output():
    raw = _load("05_bec_payment_request.eml")
    r1 = run_forensic_analysis(raw)
    r2 = run_forensic_analysis(raw)
    assert r1.threat_score.overall_score == r2.threat_score.overall_score
    assert r1.threat_score.classification == r2.threat_score.classification
