"""
MailShield - Text & URL Processing Utilities
"""
from __future__ import annotations

import re
from typing import List, Set, Tuple
from urllib.parse import urlparse
import tldextract


# Pre-compile URL regex for robust extraction
URL_REGEX = re.compile(
    r'(?:https?:\/\/|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’])',
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "club", "click", "vip", "men", "bid", "stream",
    "gq", "cf", "tk", "ml", "ga", "buzz", "rest", "fit", "racing", "date"
}

SUSPICIOUS_KEYWORDS = [
    "verify", "suspended", "security-update", "login", "signin", "banking",
    "account-update", "confirm-identity", "secure-alert", "wallet-connect",
    "invoice", "payment-due", "kyc-verification", "refund", "password-reset"
]


def clean_text_for_model(text: str, max_chars: int = 10000) -> str:
    """Cleans and standardizes email text for Keras ML and NLP models."""
    if not text:
        return ""
    # Strip HTML tags if any leaked through
    text = re.sub(r'<[^>]+>', ' ', text)
    # Normalize whitespaces
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text[:max_chars]


def extract_urls(text_body: str, html_body: str = "") -> List[str]:
    """Extracts all unique URLs found across plain text and HTML bodies."""
    urls: Set[str] = set()
    combined = f"{text_body or ''} {html_body or ''}"
    
    # Extract href attributes if HTML
    if html_body:
        hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', html_body, re.IGNORECASE)
        for h in hrefs:
            if h.startswith(("http://", "https://")):
                urls.add(h.strip())

    # Regex extraction
    for match in URL_REGEX.finditer(combined):
        url = match.group(0).strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        urls.add(url)

    return sorted(list(urls))


def extract_domain(input_str: str) -> str:
    """Extracts registered domain (e.g., example.com from sub.example.com or user@example.com)."""
    if not input_str:
        return ""
    
    # Handle email addresses
    if "@" in input_str:
        input_str = input_str.split("@")[-1].strip(">").strip()

    # Handle URLs
    if "://" in input_str or "/" in input_str:
        parsed = urlparse(input_str if "://" in input_str else f"http://{input_str}")
        input_str = parsed.hostname or input_str

    ext = tldextract.extract(input_str)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return input_str.lower().strip()


def check_suspicious_url(url: str) -> Tuple[bool, List[str]]:
    """Identifies suspicious characteristics in a URL."""
    reasons: List[str] = []
    lower_url = url.lower()

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. Plain HTTP instead of HTTPS
    if parsed.scheme == "http":
        reasons.append("Insecure HTTP protocol")

    # 2. IP address instead of domain name
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        reasons.append("Direct IP address used instead of domain")

    # 3. Suspicious TLD
    ext = tldextract.extract(hostname)
    if ext.suffix.lower() in SUSPICIOUS_TLDS:
        reasons.append(f"High-risk TLD (.{ext.suffix})")

    # 4. Excessive subdomains (e.g. secure.bank.com.attacker.xyz)
    if ext.subdomain.count('.') >= 2:
        reasons.append("Abnormal number of subdomains (potential spoofing)")

    # 5. Phishing keywords in hostname
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in hostname and not (ext.domain and kw == ext.domain):
            reasons.append(f"Suspicious keyword in hostname: '{kw}'")
            break

    # 6. '@' symbol in URL path or authority
    if "@" in url:
        reasons.append("URL contains '@' symbol (credential masking/obfuscation)")

    # 7. Hex or percent-encoding tricks
    if "%" in url and re.search(r'%[0-9a-fA-F]{2}', url):
        reasons.append("Percent-encoded characters in URL")

    return (len(reasons) > 0, reasons)
