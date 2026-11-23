"""Offline QR decoding and privacy-conscious presentation helpers."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import zxingcpp

from url_analyzer import analyze_urls


SENSITIVE_QUERY_KEYS = frozenset({
    "pa", "pn", "account", "account_number", "acct", "phone", "mobile",
    "email", "am", "amount", "token", "otp", "ref", "reference",
})
MAX_QR_CONTENT_LENGTH = 2048
MAX_QR_RESULTS = 5
MAX_QR_REPUTATION_LOOKUPS = 5


def _redact_content(value):
    value = "".join(char for char in value if char in "\n\t" or ord(char) >= 32)
    value = value[:MAX_QR_CONTENT_LENGTH]
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.query:
            query = [
                (key, "[redacted]" if key.casefold() in SENSITIVE_QUERY_KEYS else item)
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            ]
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, safe="[]"), ""))
    except ValueError:
        pass
    # Also mask sensitive key/value pairs in non-URL QR payloads.
    sensitive = "|".join(re.escape(key) for key in sorted(SENSITIVE_QUERY_KEYS, key=len, reverse=True))
    return re.sub(
        rf"(?i)\b({sensitive})\s*[:=]\s*([^&;,\s]+)",
        r"\1=[redacted]",
        value,
    )


def analyze_qr_payload(value, *, reputation_checker=None, reputation_provider=None,
                       lookup_count=0):
    """Assess decoded text without exposing payment values or opening links."""
    if not isinstance(value, str) or not value.strip():
        return {
            "content": "",
            "urls": [],
            "risk_level": "UNKNOWN",
            "reputation_status": "not_checked",
            "identified_indicators": [],
            "detection_reason": "No readable QR payload was available.",
            "recommended_action": "Treat the QR content as UNKNOWN until it can be reviewed.",
            "safety_recommendations": [
                "Do not rely on an unreadable QR code as a safety confirmation."
            ],
            "analysis_limitations": ["No QR payload was available to analyze."],
        }

    url_report = analyze_urls(value)
    safe_urls = []
    next_lookup = max(0, int(lookup_count or 0))
    for item in url_report["urls"]:
        safe_urls.append(
            _safe_url_result(item, reputation_checker, next_lookup, reputation_provider)
        )
        if reputation_checker is not None and next_lookup < MAX_QR_REPUTATION_LOOKUPS:
            next_lookup += 1

    indicators = []
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    scheme = parsed.scheme.casefold() if parsed is not None else ""
    if scheme == "upi" and parsed.netloc.casefold() == "pay":
        indicators.append({
            "code": "upi_payment_request",
            "category": "UPI payment payload",
            "reason": "This QR opens a UPI payment request; verify the recipient and amount in your payment app.",
        })
    elif scheme and scheme not in {"http", "https"}:
        indicators.append({
            "code": "non_web_action_uri",
            "category": "Non-web QR action",
            "reason": "This QR contains a non-web action URI; review the action before opening it.",
        })

    structural = [
        indicator for item in safe_urls
        for indicator in item.get("identified_indicators", [])
    ]
    identified = indicators + structural
    checked_levels = [item.get("risk_level") for item in safe_urls]
    if "MALICIOUS" in checked_levels:
        risk_level = "MALICIOUS"
        detection_reason = "A configured reputation provider reported a QR URL as a known threat."
    elif "SUSPICIOUS" in checked_levels or identified and not indicators:
        risk_level = "SUSPICIOUS"
        detection_reason = " ".join(
            item.get("reason", "Suspicious QR indicator observed.") for item in identified
        )
    elif safe_urls and all(item.get("risk_level") == "SAFE" for item in safe_urls):
        risk_level = "SAFE"
        detection_reason = "No known threat matched in the checked URL; this does not guarantee safety."
    else:
        risk_level = "UNKNOWN"
        detection_reason = (
            "QR content was decoded, but its recipient, action, or URL reputation could not be confirmed."
        )

    if indicators and indicators[0]["code"] == "upi_payment_request":
        recommendation = (
            "Check the payee name and amount in your payment app. Enter a UPI PIN only if you intend to send money."
        )
    elif risk_level in {"SUSPICIOUS", "MALICIOUS"}:
        recommendation = "Do not open this QR destination until you verify it through a trusted source."
    else:
        recommendation = "Review the destination and verify it independently before opening or paying."

    statuses = [item.get("reputation_status") for item in safe_urls]
    if safe_urls and statuses and all(status == "checked" for status in statuses):
        reputation_status = "checked"
    elif any(status == "checked" for status in statuses):
        reputation_status = "partial"
    elif any(status in {"error", "invalid"} for status in statuses):
        reputation_status = "unavailable"
    else:
        reputation_status = "not_checked"

    return {
        "content": _redact_content(value),
        "urls": safe_urls,
        "risk_level": risk_level,
        "reputation_status": reputation_status,
        "identified_indicators": identified,
        "detection_reason": detection_reason,
        "recommended_action": recommendation,
        "safety_recommendations": [recommendation],
        "analysis_limitations": [
            "QR analysis does not verify who controls a recipient, whether a payment is intended, or what a linked page contains.",
            "No URL is opened and no payment is sent by this analysis.",
        ],
    }


def analyze_qr(image, *, reputation_checker=None, reputation_provider=None):
    """Decode QR content locally; never dereference URLs or perform payments."""
    codes = zxingcpp.read_barcodes(
        image,
        formats=zxingcpp.BarcodeFormat.QRCode,
        try_rotate=True,
        try_downscale=True,
        try_invert=True,
    )
    results = []
    lookup_count = 0
    for code in codes[:MAX_QR_RESULTS]:
        raw = code.text or ""
        result = analyze_qr_payload(
            raw,
            reputation_checker=reputation_checker,
            reputation_provider=reputation_provider,
            lookup_count=lookup_count,
        )
        if reputation_checker is not None:
            lookup_count += min(
                len(result["urls"]),
                max(0, MAX_QR_REPUTATION_LOOKUPS - lookup_count),
            )
        result.update({
            "content_type": str(code.content_type),
            "reputation_checked": any(item.get("reputation_checked") for item in result["urls"]),
            "warning": "Decoding a QR code does not establish that its content, recipient, or payment request is safe.",
        })
        results.append(result)
    levels = [item["risk_level"] for item in results]
    if "MALICIOUS" in levels:
        risk_level = "MALICIOUS"
    elif "SUSPICIOUS" in levels:
        risk_level = "SUSPICIOUS"
    elif levels and all(level == "SAFE" for level in levels):
        risk_level = "SAFE"
    else:
        risk_level = "UNKNOWN"
    indicators = [
        indicator for item in results
        for indicator in item["identified_indicators"]
    ]
    recommendation = (
        results[0]["recommended_action"] if results
        else "Do not rely on an unreadable QR code as a safety confirmation."
    )
    return {
        "decoded": bool(results),
        "codes": results,
        "risk_level": risk_level,
        "identified_indicators": indicators,
        "detection_reason": (
            " ".join(item["detection_reason"] for item in results)
            if results else "No readable QR code was detected."
        ),
        "recommended_action": recommendation,
        "safety_recommendations": list(dict.fromkeys(
            item["recommended_action"] for item in results
        )) if results else [recommendation],
        "analysis_limitations": list(dict.fromkeys(
            note for item in results for note in item["analysis_limitations"]
        )) if results else ["No QR content was decoded; the image was not verified safe."],
        "reputation_checked": any(item["reputation_checked"] for item in results),
        "reputation_status": (
            "checked" if results and all(item["reputation_status"] == "checked" for item in results)
            else "partial" if any(item["reputation_status"] in {"checked", "partial"} for item in results)
            else "unavailable" if any(item["reputation_status"] == "unavailable" for item in results)
            else "not_checked"
        ),
        "message": (
            "QR content decoded locally. Review it carefully; no URL was opened and no payment was made."
            if results else "No readable QR code was detected. This says nothing about the image's safety."
        ),
    }


def _safe_url_result(item, reputation_checker, lookup_count, reputation_provider):
    """Keep raw QR URLs out of the response while adding reputation metadata."""
    result = {
        "host": item.get("host"),
        "indicators": item.get("indicators", []),
        "identified_indicators": item.get("indicators", []),
        "reputation_checked": False,
        "reputation_status": "not_checked",
        "risk_level": item.get("risk_level", "UNKNOWN"),
        "detection_reason": item.get("detection_reason", "URL reputation was not checked."),
        "recommended_action": item.get("recommended_action"),
        "analysis_limitations": item.get("analysis_limitations", []),
        "provider": None,
        "checked_timestamp": None,
        "error_status": None,
    }
    if reputation_checker is None:
        return result
    if lookup_count >= MAX_QR_REPUTATION_LOOKUPS:
        result.update({
            "reputation_status": "not_checked",
            "detection_reason": "This QR URL was not sent to a reputation provider.",
            "provider": reputation_provider,
            "checked_timestamp": None,
            "error_status": "scan_limit_exceeded",
        })
        return result
    try:
        checked = reputation_checker(item.get("url"))
        for field in (
            "risk_level", "reputation_status", "detection_reason", "provider",
            "checked_timestamp", "error_status",
        ):
            result[field] = checked.get(field)
        if checked.get("risk_level") == "UNKNOWN" and item.get("indicators"):
            result["risk_level"] = "SUSPICIOUS"
        result["recommended_action"] = checked.get(
            "recommended_action", result.get("recommended_action")
        )
        result["analysis_limitations"] = checked.get(
            "analysis_limitations", result.get("analysis_limitations", [])
        )
        result["reputation_checked"] = checked.get("reputation_status") == "checked"
    except Exception:
        result.update({
            "reputation_status": "error",
            "risk_level": "UNKNOWN",
            "detection_reason": "The reputation provider could not complete this check.",
            "provider": "configured_provider",
            "error_status": "provider_unavailable",
        })
    return result
