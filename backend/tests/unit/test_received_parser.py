import os
from app.forensic.email_parser import parse_eml_bytes
from app.forensic.received_parser import parse_received_headers, describe_originating_infrastructure

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "test_data")


def _load(name: str) -> bytes:
    with open(os.path.join(TEST_DATA_DIR, name), "rb") as f:
        return f.read()


def test_received_chain_ordering_earliest_first():
    parsed = parse_eml_bytes(_load("01_legitimate.eml"))
    hops = parse_received_headers(parsed.received_headers_raw)
    assert len(hops) == 3
    assert hops[0].hop_index == 0
    # Earliest header (last in file) mentions smtp-relay.acmecorp.example
    assert "smtp-relay.acmecorp.example" in (hops[0].from_host or "")


def test_ip_extraction_from_received_header():
    parsed = parse_eml_bytes(_load("03_phishing.eml"))
    hops = parse_received_headers(parsed.received_headers_raw)
    assert len(hops) == 1
    assert hops[0].ip_address == "192.0.2.44"


def test_originating_infrastructure_note_uses_cautious_language():
    parsed = parse_eml_bytes(_load("01_legitimate.eml"))
    hops = parse_received_headers(parsed.received_headers_raw)
    note = describe_originating_infrastructure(hops)
    assert note is not None
    assert "not a confirmed" in note.lower() or "not confirmed" in note.lower()


def test_empty_received_headers_returns_empty_list():
    assert parse_received_headers([]) == []
