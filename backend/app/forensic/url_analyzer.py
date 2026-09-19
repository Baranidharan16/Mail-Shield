"""
URL extraction and deterministic risk analysis.

Per project security rules: this module NEVER makes an outbound network
request to any URL found in a message. All indicators are computed purely
from the URL string / surrounding anchor text. Redirect-chain analysis is
explicitly deferred to an optional Phase-2 enrichment service.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, unquote

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id", "lnkd.in",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click",
    "link", "support", "loan", "kim", "men", "party", "review", "country",
}

SUSPICIOUS_QUERY_PARAM_KEYS = {
    "verify", "confirm", "login", "signin", "secure", "update", "account",
    "password", "token", "session", "auth", "redirect", "next", "reset",
}

_URL_RE = re.compile(r"""(?xi)
    \b((?:https?://|www\.)
    [^\s<>"'\)\]]+)
""")

_MAX_REASONABLE_URL_LENGTH = 90


@dataclass
class URLFinding:
    url: str
    hostname: Optional[str]
    scheme: Optional[str]
    source_location: str
    anchor_text: Optional[str] = None

    is_https: Optional[bool] = None
    is_ip_based: bool = False
    is_shortened: bool = False
    is_punycode: bool = False
    has_suspicious_tld: bool = False
    excessive_subdomains: bool = False
    has_encoded_chars: bool = False
    suspicious_query_params: bool = False
    anchor_text_mismatch: bool = False
    url_length: int = 0

    risk_score: float = 0.0  # 0-100, this URL's individual risk contribution
    risk_reasons: List[str] = field(default_factory=list)


class _AnchorExtractor(HTMLParser):
    """Extracts (href, visible_text) pairs from <a> tags in an HTML body."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[tuple[str, str]] = []
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None
            self._current_text = []


def extract_urls(text_body: str, html_body: str) -> List[URLFinding]:
    findings: List[URLFinding] = []
    seen = set()

    if html_body:
        parser = _AnchorExtractor()
        try:
            parser.feed(html_body)
        except Exception:
            pass
        for href, anchor_text in parser.links:
            if not href.lower().startswith(("http://", "https://")):
                continue
            key = (href, "html_body")
            if key in seen:
                continue
            seen.add(key)
            _safe_append(findings, _build_finding, (href, "html_body", anchor_text or None))

        for match in _URL_RE.findall(html_body):
            url = match if match.lower().startswith("http") else f"http://{match}"
            key = (url, "html_body")
            if key in seen:
                continue
            seen.add(key)
            _safe_append(findings, _build_finding, (url, "html_body", None))

    if text_body:
        for match in _URL_RE.findall(text_body):
            url = match if match.lower().startswith("http") else f"http://{match}"
            key = (url, "text_body")
            if key in seen:
                continue
            seen.add(key)
            _safe_append(findings, _build_finding, (url, "text_body", None))

    return findings


def _safe_append(findings: List[URLFinding], fn, args) -> None:
    """Malformed URLs (e.g. broken IPv6 brackets, common in phishing) must never abort the analysis."""
    try:
        findings.append(fn(*args))
    except (ValueError, UnicodeError):
        pass


def _build_finding(raw_url: str, source_location: str, anchor_text: Optional[str]) -> URLFinding:
    raw_url = raw_url.strip().rstrip(".,;)")
    parsed = urlparse(raw_url)
    hostname = parsed.hostname or ""
    finding = URLFinding(
        url=raw_url,
        hostname=hostname or None,
        scheme=parsed.scheme or None,
        source_location=source_location,
        anchor_text=anchor_text,
        url_length=len(raw_url),
    )

    reasons: List[str] = []
    score = 0.0

    # HTTPS vs HTTP
    finding.is_https = parsed.scheme == "https"
    if not finding.is_https:
        score += 10
        reasons.append("URL does not use HTTPS")

    # IP-based URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) or ":" in hostname.strip("[]") and re.match(r"^[0-9a-fA-F:]+$", hostname.strip("[]")):
        finding.is_ip_based = True
        score += 25
        reasons.append("URL host is a raw IP address rather than a domain name")

    # Shortener
    bare_host = hostname.lower().lstrip("www.")
    if bare_host in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS:
        finding.is_shortened = True
        score += 15
        reasons.append("URL uses a known link-shortening service, which can hide the true destination")

    # Punycode
    if "xn--" in hostname.lower():
        finding.is_punycode = True
        score += 20
        reasons.append("Hostname contains punycode (xn--), often used to spoof lookalike international domains")

    # Suspicious TLD
    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        finding.has_suspicious_tld = True
        score += 10
        reasons.append(f"Top-level domain '.{tld}' is commonly abused in phishing campaigns")

    # Excessive subdomains
    label_count = hostname.count(".")
    if label_count >= 4:
        finding.excessive_subdomains = True
        score += 10
        reasons.append(f"Hostname has an unusually high number of subdomain labels ({label_count + 1})")

    # Encoded characters
    if "%" in raw_url and unquote(raw_url) != raw_url:
        finding.has_encoded_chars = True
        score += 8
        reasons.append("URL contains percent-encoded characters that may obscure its true content")

    # Suspicious query params
    qs = parse_qs(parsed.query)
    if any(k.lower() in SUSPICIOUS_QUERY_PARAM_KEYS for k in qs.keys()):
        finding.suspicious_query_params = True
        score += 8
        matched = [k for k in qs if k.lower() in SUSPICIOUS_QUERY_PARAM_KEYS]
        reasons.append(f"Query parameters suggest a credential/verification flow: {', '.join(matched)}")

    # Anchor text mismatch (displayed text looks like a different domain than the href)
    if anchor_text:
        anchor_domain_match = re.search(r"([a-zA-Z0-9-]+\.[a-zA-Z]{2,})", anchor_text)
        if anchor_domain_match:
            displayed_domain = anchor_domain_match.group(1).lower()
            if displayed_domain not in hostname.lower() and hostname.lower() not in displayed_domain:
                finding.anchor_text_mismatch = True
                score += 20
                reasons.append(
                    f"Displayed link text ('{displayed_domain}') does not match the actual destination host ('{hostname}')"
                )

    # URL length
    if finding.url_length > _MAX_REASONABLE_URL_LENGTH:
        score += 5
        reasons.append(f"URL is unusually long ({finding.url_length} characters)")

    finding.risk_score = min(100.0, score)
    finding.risk_reasons = reasons
    return finding
