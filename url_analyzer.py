"""Offline structural URL analysis. This module never makes network requests."""

import ipaddress
import re
from urllib.parse import urlsplit


URL_PATTERN = re.compile(
    r"(?i)(?<![\w@])(?:https?://|www\.)[^\s<>\"']+"
)
TRAILING_PUNCTUATION = ".,!?;:)]}>'\""
SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "t.ly",
    "is.gd", "rebrand.ly", "tiny.cc", "goo.gl", "shorturl.at",
    "buff.ly", "ow.ly", "lnkd.in", "s.id",
})
BRAND_DOMAINS = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "phonepe": ("phonepe.com",),
    "paytm": ("paytm.com",),
    "googlepay": ("google.com",),
}


def extract_urls(text):
    """Extract URL-shaped tokens without dereferencing them."""
    if not isinstance(text, str):
        return []
    extracted = []
    for match in URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(TRAILING_PUNCTUATION)
        if candidate and candidate not in extracted:
            extracted.append(candidate)
    return extracted


def _indicator(code, reason):
    return {"code": code, "reason": reason}


def _inspect_url(raw_url):
    candidate = raw_url if "://" in raw_url else "http://" + raw_url
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        # Accessing port validates malformed/non-numeric ports.
        port = parsed.port
    except (ValueError, UnicodeError):
        return {
            "url": raw_url,
            "host": None,
            "indicators": [_indicator("malformed_url", "URL could not be parsed safely.")],
            "identified_indicators": [
                _indicator("malformed_url", "URL could not be parsed safely.")
            ],
            "risk_level": "UNKNOWN",
            "detection_reason": "URL could not be parsed safely; its destination remains UNKNOWN.",
            "recommended_action": "Do not open this URL unless you verify it through a trusted source.",
            "analysis_limitations": [
                "The URL was not visited and its reputation was not checked."
            ],
            "reputation_checked": False,
            "reputation_status": "not_checked",
        }

    indicators = []
    try:
        ipaddress.ip_address(host.strip("[]"))
        indicators.append(_indicator("ip_address_host", "URL uses a literal IP-address host."))
    except ValueError:
        pass
    if parsed.username is not None or parsed.password is not None:
        indicators.append(_indicator("userinfo", "URL contains user-info before its hostname."))
    if any(label.startswith("xn--") for label in host.split(".")):
        indicators.append(_indicator("punycode_host", "Hostname contains an encoded internationalized label."))
    if sum(1 for part in host.split(".") if part) > 4:
        indicators.append(_indicator("excessive_subdomains", "Hostname has an unusually deep subdomain structure."))
    if port is not None and port not in {80, 443}:
        indicators.append(_indicator("unusual_port", "URL specifies a non-standard web port."))

    shortener_host = host.removeprefix("www.")
    if shortener_host in SHORTENERS:
        indicators.append(_indicator("known_shortener", "Hostname is a known URL-shortening service; its destination was not checked."))

    host_labels = host.split(".")
    for brand, trusted_hosts in BRAND_DOMAINS.items():
        brand_words = {brand, brand.replace("googlepay", "googlepay"), brand.replace("phonepe", "phonepe")}
        if not any(host == trusted or host.endswith("." + trusted) for trusted in trusted_hosts):
            if any(brand_word in label for brand_word in brand_words for label in host_labels):
                indicators.append(_indicator(
                    "lookalike_brand_host",
                    f"Hostname includes a {brand} brand-like label outside its listed official hostname pattern; ownership was not verified.",
                ))
                break

    reason = (
        " ".join(item["reason"] for item in indicators)
        if indicators else "No URL-structure warning was found; its reputation remains UNKNOWN."
    )
    return {
        "url": raw_url,
        "host": host or None,
        "indicators": indicators,
        "identified_indicators": indicators,
        "risk_level": "SUSPICIOUS" if indicators else "UNKNOWN",
        "detection_reason": reason,
        "recommended_action": (
            "Avoid opening this URL until you verify the destination independently."
            if indicators else "Confirm the destination independently before opening it."
        ),
        "analysis_limitations": [
            "Structural checks do not visit the URL or confirm its current reputation."
        ],
        "reputation_checked": False,
        "reputation_status": "not_checked",
    }


def analyze_urls(text):
    """Return structural URL findings only; never open or query a URL."""
    urls = [_inspect_url(url) for url in extract_urls(text)]
    return {
        "urls": urls,
        "risk_level": (
            "SUSPICIOUS" if any(item["risk_level"] == "SUSPICIOUS" for item in urls)
            else "UNKNOWN"
        ),
        "detection_reason": (
            f"{len(urls)} URL(s) were inspected for structure; reputation was not checked."
            if urls else "No supported HTTP or HTTPS URL was found."
        ),
        "identified_indicators": [
            indicator for item in urls for indicator in item["indicators"]
        ],
        "recommended_action": (
            "Verify each destination independently before opening it."
            if urls else "No URL action is available from this scan."
        ),
        "analysis_limitations": [
            "Structural checks do not establish that a URL is malicious or safe."
        ],
        "reputation_checked": False,
        "reputation_status": "not_checked",
    }
