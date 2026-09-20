from app.forensic.origin_tracer import analyze_origin_trace
from app.forensic.received_parser import parse_received_headers
from app.forensic.sender_trace import dnsbl_check, extract_client_ips


def test_client_ip_headers_extracted_in_trust_order():
    hdrs = [("X-Forwarded-For", "8.8.4.4, 10.0.0.1"), ("X-Originating-IP", "[41.58.12.7]"),
            ("Subject", "hi 1.2.3.4")]
    ips = extract_client_ips(hdrs)
    assert [i["ip"] for i in ips] == ["41.58.12.7", "8.8.4.4"]
    assert ips[0]["header"] == "x-originating-ip" and ips[0]["is_public"]


def test_client_ip_becomes_earliest_origin_candidate():
    hops = [{"hop_index": 0, "ip_address": "209.85.220.41", "from_host": "mail-sor-f41.google.com",
             "by_host": "mx.google.com", "with_protocol": "SMTPS"}]
    geo = [{"ip_address": "41.58.12.7", "geo": {"available": True, "country": "Nigeria", "lat": 6.45, "lon": 3.39}}]
    res = analyze_origin_trace(hops, geo, client_ips=extract_client_ips([("X-Originating-IP", "41.58.12.7")]))
    assert res.earliest_node.ip_address == "41.58.12.7"
    assert res.earliest_node.source == "client_ip_header"
    assert res.client_origin_detected
    assert res.relay_path[1].infrastructure_type == "MAIL_PROVIDER"  # Google relay is not a rented VPS


def test_ipv6_literal_in_received_header():
    hops = parse_received_headers([
        "from mail.example.org (mail.example.org [IPv6:2a00:1450:4864:20::62c]) by mx.test with ESMTPS; "
        "Tue, 1 Sep 2026 10:00:00 +0000"])
    assert hops[0].ip_address == "2a00:1450:4864:20::62c"


def test_dnsbl_skips_private_addresses():
    assert dnsbl_check("10.1.2.3")["checked"] is False
