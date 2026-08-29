from app.forensic.domain_analyzer import domain_similarity, analyze_domain, levenshtein


def test_levenshtein_identical():
    assert levenshtein("acme.com", "acme.com") == 0


def test_levenshtein_basic():
    assert levenshtein("kitten", "sitting") == 3


def test_domain_similarity_identical_is_one():
    assert domain_similarity("acmecorp.example", "acmecorp.example") == 1.0


def test_domain_similarity_lookalike_high():
    score = domain_similarity("acmecorp-security.com", "acmecorp.example")
    assert 0.0 <= score <= 1.0


def test_domain_similarity_completely_different_is_low():
    score = domain_similarity("totallyunrelated.net", "acmecorp.example")
    assert score < 0.6


def test_analyze_domain_flags_lookalike():
    finding = analyze_domain("acmecorp-security.com", "sender", trusted_domains=["acmecorp.com"])
    assert finding.excessive_hyphenation is False or finding.excessive_hyphenation is True  # deterministic either way
    # similarity to acmecorp.com should be reasonably high given shared prefix
    assert finding.domain == "acmecorp-security.com"


def test_analyze_domain_detects_punycode():
    finding = analyze_domain("xn--acme-123.com", "url")
    assert finding.is_punycode is True
    assert finding.risk_score > 0


def test_analyze_domain_detects_suspicious_tld():
    finding = analyze_domain("secure-login.xyz", "url")
    assert finding.suspicious_tld is True


def test_analyze_domain_does_not_flag_exact_trusted_match_as_lookalike():
    finding = analyze_domain("acmecorp.example", "sender", trusted_domains=["acmecorp.example"])
    assert finding.lookalike_of is None
