"""Bounded Google Safe Browsing lookups with privacy-conscious results.

This module only submits a URL string to the reputation provider. It never
visits the submitted URL or downloads content from its host.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import math
import re
import socket
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from url_analyzer import analyze_urls


GOOGLE_SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GOOGLE_THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
)
MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 64 * 1024
MAX_PROVIDER_ATTEMPTS = 2
RETRY_BACKOFF_SECONDS = 0.1
SAFE_CACHE_TTL_SECONDS = 30
UNKNOWN_CACHE_TTL_SECONDS = 15
MAX_CACHE_ENTRIES = 2048


class ProviderFailure(Exception):
    """A provider failure identified by a safe, fixed public error code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _close_response(response):
    try:
        response.close()
    except Exception:
        pass


_cache = OrderedDict()
_cache_lock = threading.Lock()


def clear_reputation_cache():
    """Clear process-local cached checks, primarily for tests and maintenance."""
    with _cache_lock:
        _cache.clear()


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_url(value):
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        return False
    if value != value.strip() or any(ord(char) < 32 or char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        hostname = parsed.hostname
        if not hostname or "%" in hostname:
            return False
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            ascii_hostname = hostname.encode("idna").decode("ascii").rstrip(".")
            labels = ascii_hostname.split(".")
            if not ascii_hostname or len(ascii_hostname) > 253:
                return False
            if any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label)
                for label in labels
            ):
                return False
        parsed.port  # Access validates malformed and out-of-range ports.
    except (ValueError, UnicodeError):
        return False
    return True


def _provider_url(value):
    """Add a scheme to the `www.` URLs already recognized by the SMS parser."""
    return "http://" + value if isinstance(value, str) and value.lower().startswith("www.") else value


def _base_result(url, *, provider, risk_level="UNKNOWN", status="error", reason, error=None):
    if risk_level == "MALICIOUS":
        recommended_action = "Do not open this URL or enter information there. Verify the sender independently."
    elif risk_level == "SUSPICIOUS":
        recommended_action = "Avoid opening this URL until you verify its destination independently."
    elif risk_level == "SAFE":
        recommended_action = "No known threat matched; verify the sender and destination before acting."
    else:
        recommended_action = "The destination is UNKNOWN. Do not rely on this result as a safety confirmation."
    return {
        "url": url,
        "risk_level": risk_level,
        "reputation_status": status,
        "detection_reason": reason,
        "identified_indicators": [],
        "recommended_action": recommended_action,
        "analysis_limitations": [
            "A reputation result is time-sensitive and may miss new threats or misclassify a safe URL.",
            "The URL may be sent to the configured reputation provider; no URL is visited by this app.",
        ],
        "provider": provider,
        "checked_timestamp": _timestamp(),
        "error_status": error,
        "cache_hit": False,
    }


def unchecked_result(url, *, settings=None, error="scan_limit_exceeded"):
    """Describe a URL intentionally left unchecked without implying safety."""
    settings = settings or {}
    provider = str(settings.get("URL_REPUTATION_PROVIDER", "google_safe_browsing")).strip().lower()
    return _base_result(
        url,
        provider=provider or "google_safe_browsing",
        status="not_checked",
        reason="This URL was not sent to a reputation provider.",
        error=error,
    )


def _safe_browsing_payload(url):
    return {
        "client": {"clientId": "upi-shield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(GOOGLE_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def _google_lookup(url, api_key, timeout):
    endpoint = f"{GOOGLE_SAFE_BROWSING_ENDPOINT}?{urlencode({'key': api_key})}"
    body = json.dumps(_safe_browsing_payload(url), separators=(",", ":")).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise ProviderFailure("provider_error")
    except HTTPError as error:
        # Google may report invalid API keys as HTTP 400; inspect only for a
        # generic credential marker and never expose provider text or the key.
        if error.code in {401, 403}:
            _close_response(error)
            raise ProviderFailure("authentication_failed") from None
        if error.code == 429:
            _close_response(error)
            raise ProviderFailure("rate_limited") from None
        if error.code >= 500:
            _close_response(error)
            raise ProviderFailure("provider_unavailable") from None
        if error.code == 400:
            try:
                detail = error.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="ignore").lower()
            except Exception:
                detail = ""
            finally:
                _close_response(error)
            if "api key" in detail and any(word in detail for word in ("invalid", "not valid", "denied")):
                raise ProviderFailure("authentication_failed") from None
        else:
            _close_response(error)
        raise ProviderFailure("provider_error") from None
    except (TimeoutError, socket.timeout):
        raise ProviderFailure("timeout") from None
    except URLError as error:
        if isinstance(getattr(error, "reason", None), (TimeoutError, socket.timeout)):
            raise ProviderFailure("timeout") from None
        raise ProviderFailure("provider_unavailable") from None
    except ProviderFailure:
        raise
    except Exception:
        raise ProviderFailure("provider_unavailable") from None

    try:
        data = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderFailure("provider_error") from None
    if not isinstance(data, dict):
        raise ProviderFailure("provider_error")
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        raise ProviderFailure("provider_error")
    threat_types = []
    match_ttls = []
    missing_cache_duration = False
    for match in matches:
        if not isinstance(match, dict):
            raise ProviderFailure("provider_error")
        threat_type = match.get("threatType")
        if threat_type not in GOOGLE_THREAT_TYPES:
            raise ProviderFailure("provider_error")
        if threat_type not in threat_types:
            threat_types.append(threat_type)
        duration = match.get("cacheDuration")
        if isinstance(duration, str) and re.fullmatch(r"\d+(?:\.\d+)?s", duration):
            seconds = float(duration[:-1])
            if 0 < seconds <= 31_536_000 and math.isfinite(seconds):
                match_ttls.append(seconds)
            else:
                missing_cache_duration = True
        else:
            missing_cache_duration = True
    # Google requires matched threat entries to be cached for their returned
    # cacheDuration. If a response omits that field, return the finding without
    # caching it.
    match_ttl = min(match_ttls) if threat_types and match_ttls and not missing_cache_duration else None
    return threat_types, match_ttl


class GoogleSafeBrowsingAdapter:
    """Provider adapter contract: return threat types and positive-cache TTL."""

    name = "google_safe_browsing"

    def lookup(self, url, api_key, timeout):
        return _google_lookup(url, api_key, timeout)


PROVIDER_ADAPTERS = {
    GoogleSafeBrowsingAdapter.name: GoogleSafeBrowsingAdapter(),
}


def _cache_key(url, provider, api_key):
    # Store only hashes in the process cache, never raw URLs or API keys.
    url_hash = sha256(url.encode("utf-8")).hexdigest()
    key_hash = sha256((api_key or "").encode("utf-8")).hexdigest()
    return provider, key_hash, url_hash


def _get_cached(key, now):
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        expires_at, result = entry
        if expires_at <= now:
            _cache.pop(key, None)
            return None
        _cache.move_to_end(key)
        return dict(result)


def _store_cached(key, result, ttl):
    with _cache_lock:
        cached_result = {field: value for field, value in result.items() if field != "url"}
        _cache[key] = (time.monotonic() + ttl, cached_result)
        _cache.move_to_end(key)
        while len(_cache) > MAX_CACHE_ENTRIES:
            _cache.popitem(last=False)


def check_url(url, *, settings=None):
    """Check a URL and return a structured result; failures always remain UNKNOWN."""
    settings = settings or {}
    provider = str(settings.get("URL_REPUTATION_PROVIDER", "google_safe_browsing")).strip().lower()
    if not provider:
        provider = "google_safe_browsing"
    provider_url = _provider_url(url)
    if not _validate_url(provider_url):
        return _base_result(
            url if isinstance(url, str) else "",
            provider=provider,
            status="invalid",
            reason="URL is malformed or uses an unsupported scheme; no provider request was made.",
            error="invalid_url",
        )

    adapter = PROVIDER_ADAPTERS.get(provider)
    if adapter is None:
        return _base_result(
            url,
            provider=provider,
            reason="The configured reputation provider is unavailable.",
            error="provider_unavailable",
        )

    api_key = settings.get("GOOGLE_SAFE_BROWSING_API_KEY")
    if not isinstance(api_key, str) or not api_key.strip():
        return _base_result(
            url,
            provider=provider,
            reason="URL reputation is not configured; this URL was not checked.",
            error="missing_credentials",
        )
    api_key = api_key.strip()
    try:
        timeout = float(settings.get("URL_REPUTATION_TIMEOUT_SECONDS", 4))
        if not 0.1 <= timeout <= 30:
            timeout = 4.0
    except (TypeError, ValueError):
        timeout = 4.0

    key = _cache_key(provider_url, provider, api_key)
    cached = _get_cached(key, time.monotonic())
    if cached is not None:
        cached["url"] = url
        cached["cache_hit"] = True
        return cached

    threat_types = None
    provider_ttl = None
    failure = None
    for attempt in range(MAX_PROVIDER_ATTEMPTS):
        try:
            threat_types, provider_ttl = adapter.lookup(provider_url, api_key, timeout)
            break
        except ProviderFailure as error:
            failure = error
            # A reputation lookup is read-only, so one brief retry is safe for
            # transient provider 5xx errors. Timeouts and 429s are returned as-is.
            if error.code != "provider_unavailable" or attempt + 1 >= MAX_PROVIDER_ATTEMPTS:
                break
            time.sleep(RETRY_BACKOFF_SECONDS * (2 ** attempt))

    if failure is not None:
        result = _base_result(
            url,
            provider=provider,
            reason="The reputation provider could not complete this check.",
            error=failure.code,
        )
        _store_cached(key, result, UNKNOWN_CACHE_TTL_SECONDS)
        return result

    if threat_types:
        reason = "Google Safe Browsing identified a potential threat: " + ", ".join(threat_types) + "."
        result = _base_result(
            url, provider=provider, risk_level="MALICIOUS", status="checked",
            reason=reason,
        )
        if provider_ttl:
            _store_cached(key, result, provider_ttl)
        return result

    structural = analyze_urls(provider_url).get("urls", [])
    suspicious_codes = {
        "ip_address_host", "userinfo", "punycode_host", "excessive_subdomains",
        "unusual_port", "known_shortener", "lookalike_brand_host",
    }
    indicators = structural[0].get("indicators", []) if structural else []
    suspicious = [item.get("reason") for item in indicators if item.get("code") in suspicious_codes]
    if suspicious:
        result = _base_result(
            url, provider=provider, risk_level="SUSPICIOUS", status="checked",
            reason="No known threat matched; URL structure has warning signs: " + " ".join(suspicious),
        )
        _store_cached(key, result, SAFE_CACHE_TTL_SECONDS)
        return result

    result = _base_result(
        url, provider=provider, risk_level="SAFE", status="checked",
        reason="No known threat matched in the provider lookup; this is not a guarantee of safety.",
    )
    _store_cached(key, result, SAFE_CACHE_TTL_SECONDS)
    return result
