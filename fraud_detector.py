"""Transparent, offline heuristic rules for SMS and payment-scam screening."""

from dataclasses import dataclass
import re
import unicodedata

from url_analyzer import analyze_urls


@dataclass(frozen=True)
class Rule:
    category: str
    weight: int
    pattern: re.Pattern
    reason: str


def _rule(category, weight, pattern, reason):
    return Rule(category, weight, re.compile(pattern, re.IGNORECASE), reason)


# Each category contributes at most once. A category's multiple phrases are
# alternatives in one regex, so repeated or overlapping words cannot stack.
_CREDENTIAL_ACTION = (
    r"(?:\b(?:share|send|tell|confirm|enter|provide|give|reveal|disclose|read out|type|"
    r"batao|bataye|batana|bhejo|bhejna)\b|"
    r"(?<!\w)(?:\u092c\u0924\u093e\u090f\u0902|\u092c\u0924\u093e\u0913|"
    r"\u092d\u0947\u091c\u0947\u0902|\u092d\u0947\u091c\u094b|\u0926\u0947\u0902|"
    r"\u0926\u0947\u0928\u093e|\u092c\u0924\u093e\u0928\u093e)(?!\w))"
)
_CREDENTIAL_TERM = (
    r"(?:\b(?:otp|one[ -]?time password|upi pin|pin|cvv|password|verification code|security code)\b|"
    r"(?<!\w)(?:\u092a\u093e\u0938\u0935\u0930\u094d\u0921|\u0913\u091f\u0940\u092a\u0940)(?!\w))"
)

RULES = (
    _rule("Banking impersonation", 22,
          r"\b(?:bank account (?:blocked|suspended|locked)|account (?:blocked|suspended|locked)|"
          r"(?:bank|बैंक) (?:से|se) (?:बोल|bol|calling)|verify (?:your )?account|"
          r"account verification|debit card (?:blocked|expired))\b",
          "Bank-account access or verification claim detected."),
    _rule("KYC scam", 27,
          r"\b(?:kyc|केवाईसी)\b.{0,55}\b(?:update|complete|expire[sd]?|suspend(?:ed)?|"
          r"block(?:ed)?|verify|अद्यतन|पूरा|बंद|अपडेट|करें|करो|नहीं तो|वरना)\b|"
          r"\b(?:update|complete|expire[sd]?|suspend(?:ed)?|block(?:ed)?)\b.{0,40}\bkyc\b|"
          r"\b(?:kyc pending|kyc expired|kyc update|kyc karo|केवाईसी अपडेट)\b",
          "KYC update or account restriction language detected."),
    _rule("OTP or credential theft", 35,
          _CREDENTIAL_ACTION + r".{0,45}" + _CREDENTIAL_TERM + "|"
          + _CREDENTIAL_TERM + r".{0,45}" + _CREDENTIAL_ACTION,
          "A message asks for an OTP or another authentication credential."),
    _rule("UPI payment manipulation", 30,
          r"\b(?:upi collect|collect request|payment request.{0,35}(?:receive|get) money|"
          r"approve (?:the )?(?:payment|request).{0,35}(?:receive|get) money|"
          r"receive money.{0,30}(?:pin|approve)|money receive karne|paisa (?:receive|lene)|"
          r"paise (?:lene|receive)|"
          r"\u092a\u0948\u0938\u0947 (?:\u092a\u093e\u0928\u0947|\u092a\u094d\u0930\u093e\u092a\u094d\u0924 \u0915\u0930\u0928\u0947).{0,30}(?:\u092a\u093f\u0928|\u0905\u0928\u0941\u092e\u0924\u093f)|"
          r"request approve karo|payment approve karo)\b",
          "Payment approval or UPI collect-request language detected."),
    _rule("Fake reward or prize", 24,
          r"\b(?:lottery.{0,35}(?:winner|prize|claim|fee)|winner.{0,35}(?:won|prize|claim)|"
          r"won (?:a )?prize|claim (?:your )?(?:cashback |reward points |reward |prize |gift )?(?:reward|prize|cashback|gift)|"
          r"cashback.{0,35}(?:claim|click|link|verify|fee|share)|"
          r"reward points.{0,35}(?:claim|click|link|expire|redeem)|"
          r"free gift.{0,35}(?:claim|click|link|fee)|"
          r"\u0907\u0928\u093e\u092e.{0,35}(?:\u092e\u093f\u0932\u0947|\u092a\u094d\u0930\u093e\u092a\u094d\u0924|\u0926\u093e\u0935\u093e)|"
          r"\u0932\u0949\u091f\u0930\u0940.{0,35}(?:\u091c\u0940\u0924|\u0926\u093e\u0935\u093e|\u092b\u0940\u0938)|"
          r"\u092a\u0941\u0930\u0938\u094d\u0915\u093e\u0930.{0,35}(?:\u092a\u094d\u0930\u093e\u092a\u094d\u0924|\u0926\u093e\u0935\u093e)|"
          r"\u092c\u0927\u093e\u0908.{0,30}\u091c\u0940\u0924\u0947|"
          r"gift voucher.{0,30}(?:claim|click|link|fee)|"
          r"lucky draw.{0,30}(?:claim|won|prize|fee|click|link))\b",
          "Unexpected prize or reward language is paired with a request or claim action."),
    _rule("Job or task scam", 27,
          r"\b(?:task job|earn (?:up to )?(?:daily|\$|\u20b9)?|daily income|telegram task|"
          r"like and earn|review and earn|registration fee.{0,30}job|"
          r"(?:part[ -]?time job|work from home).{0,60}(?:earn|registration fee|telegram|task|deposit|investment)|"
          r"(?:earn|registration fee|telegram|task|deposit|investment).{0,60}(?:part[ -]?time job|work from home)|"
          r"\u0918\u0930 \u092c\u0948\u0920\u0947 \u0915\u092e\u093e\u090f\u0902|"
          r"\u092a\u093e\u0930\u094d\u091f.?\u091f\u093e\u0907\u092e \u0928\u094c\u0915\u0930\u0940|"
          r"\u0930\u094b\u091c\u093c\u093e\u0928\u093e \u0915\u092e\u093e\u0908|"
          r"\u0915\u093e\u092e \u0915\u0930\u0915\u0947 \u0915\u092e\u093e\u090f\u0902|task complete karo)\b",
          "Unsolicited job, task, or easy-income offer detected."),
    _rule("Refund scam", 26,
          r"\b(?:refund (?:pending|approved|initiated|failed).{0,35}(?:claim|click|link|verify|share|otp|pin|fee)|"
          r"claim (?:your )?refund|refund ke liye|refund lene|"
          r"\u0930\u093f\u092b\u0902\u0921.{0,25}(?:\u092a\u093e\u0928\u0947|\u0932\u0947\u0928\u0947|\u0932\u093f\u0902\u0915)|"
          r"reversal.{0,20}(?:click|link|verify)|money back.{0,20}(?:click|link))\b",
          "Refund or payment-reversal language is paired with an action or suspicious link."),
    _rule("Utility-payment scam", 24,
          r"\b(?:electricity|power|water|gas) bill.{0,50}(?:disconnect|cut off|"
          r"pay now|suspend)|(?:bill|connection).{0,35}(?:disconnect|cut off|suspend)|"
          r"bijli bill|bijli connection|बिजली बिल|बिजली कनेक्शन|मीटर.{0,25}(?:कट|बंद)|"
          r"गैस कनेक्शन.{0,20}(?:बंद|कट)\b",
          "Utility bill or imminent disconnection claim detected."),
    _rule("Remote-access scam", 35,
          r"\b(?:anydesk|teamviewer|quick.?support|rustdesk|screen.?sharing|"
          r"remote access|install (?:this )?app.{0,25}(?:bank|payment|refund)|"
          r"install apk|download apk|apk install karo|ऐप इंस्टॉल|स्क्रीन शेयर)\b",
          "Remote-access software, screen sharing, or APK installation request detected."),
    _rule("Urgency or threat", 12,
          r"\b(?:urgent|immediately|within \d+ hours?|account will be (?:blocked|closed)|"
          r"last warning|act now|आज ही|तुरंत|अभी नहीं तो|वरना खाता|खाता बंद|अंतिम चेतावनी)\b",
          "Urgency or account-threat wording detected."),
)

URL_WEIGHTS = {
    "ip_address_host": 24,
    "userinfo": 20,
    "punycode_host": 15,
    "lookalike_brand_host": 24,
    "known_shortener": 12,
    "unusual_port": 10,
    "excessive_subdomains": 8,
    "malformed_url": 8,
}


def normalize_text(value):
    """Normalize Unicode and remove invisible direction/format controls."""
    value = unicodedata.normalize("NFKC", value).casefold()
    return "".join(
        char for char in value
        if unicodedata.category(char) not in {"Cf", "Cc"} or char in "\n\t"
    )



_CREDENTIAL_ACTION_PATTERNS = (
    re.compile(
        r"(?P<action>" + _CREDENTIAL_ACTION + r").{0,45}" + _CREDENTIAL_TERM,
        re.IGNORECASE,
    ),
    re.compile(
        _CREDENTIAL_TERM + r".{0,45}(?P<action>" + _CREDENTIAL_ACTION + r")",
        re.IGNORECASE,
    ),
)
_CREDENTIAL_NEGATION = re.compile(
    r"\b(?:do not|don't|dont|never|not|avoid|should not|shouldn't|must not|mustn't|"
    r"cannot|can't|mat|nahi|nahin)\b|"
    r"(?<!\w)(?:\u0928\u0939\u0940\u0902|\u092e\u0924|\u0928)(?=\s|$)",
    re.IGNORECASE,
)
_CLAUSE_BOUNDARIES = ".!?;,\n"


def _requests_credentials(text):
    """Match requests to disclose a credential while ignoring clear warnings."""
    for pattern in _CREDENTIAL_ACTION_PATTERNS:
        for match in pattern.finditer(text):
            action_start = match.start("action")
            clause_start = max(
                (text.rfind(boundary, 0, action_start) for boundary in _CLAUSE_BOUNDARIES),
                default=-1,
            ) + 1
            clause_end = min(
                (position for boundary in _CLAUSE_BOUNDARIES
                 if (position := text.find(boundary, action_start)) >= 0),
                default=len(text),
            )
            if (_CREDENTIAL_NEGATION.search(text[clause_start:action_start])
                    or _CREDENTIAL_NEGATION.search(text[action_start:clause_end])):
                continue
            return True
    return False


def _risk_level(status):
    return {"FRAUD": "HIGH", "SUSPICIOUS": "MEDIUM", "SAFE": "LOW"}.get(status, "UNKNOWN")


def _safety_recommendations(status, categories):
    lowered = {str(category).casefold() for category in categories}
    recommendations = []
    if status in {"FRAUD", "SUSPICIOUS"}:
        recommendations.append(
            "Pause before acting. Verify the sender using the bank or service's official app or a number you already trust."
        )
    if any("otp" in category or "credential" in category for category in lowered):
        recommendations.append(
            "Never disclose an OTP, UPI PIN, CVV, or password to another person or through a link in a message."
        )
    if any("upi" in category for category in lowered):
        recommendations.append(
            "A UPI PIN authorizes a payment; you do not enter it to receive money. Decline unexpected collect requests."
        )
    if status == "UNKNOWN":
        recommendations.append("Provide readable text before relying on a message assessment.")
    if not recommendations:
        recommendations.append(
            "No major patterns matched. Verify unexpected payment or account requests independently before acting."
        )
    return recommendations

def analyze_sms(message, *, rules=RULES, url_weights=URL_WEIGHTS,
                suspicious_threshold=20, fraud_threshold=70):
    """Return a bounded heuristic assessment; this is not a probability."""
    if not isinstance(message, str) or not message.strip():
        return {
            "status": "UNKNOWN", "risk_level": "UNKNOWN", "risk_score": 0,
            "confidence_label": "Insufficient text to assess",
            "confidence": "Insufficient text to assess",
            "category": "General analysis", "all_categories": [],
            "reasons": ["Enter a non-empty text message to analyze."],
            "detection_reason": "There is no readable message text to assess.",
            "observed_indicators": [], "identified_indicators": [],
            "safety_recommendations": ["Provide readable text before relying on a message assessment."],
            "recommended_action": "Provide readable text before relying on a message assessment.",
            "analysis_limitations": ["No message text was available for analysis."],
            "evidence_status": "insufficient_text",
            "analysis_method": "offline_rule_based_heuristic",
            "scoring": {
                "raw_points": 0, "score_cap": 100, "cap_applied": False,
                "note": "No score can be assessed without readable text.",
            },
            "urls": [], "url_analysis": {"reputation_checked": False,
                                         "reputation_status": "not_checked"},
        }

    text = normalize_text(message)
    matched = []
    seen_categories = set()
    for rule in rules:
        has_match = (
            _requests_credentials(text)
            if rule.category == "OTP or credential theft"
            else bool(rule.pattern.search(text))
        )
        if has_match and rule.category not in seen_categories:
            matched.append(rule)
            seen_categories.add(rule.category)

    url_report = analyze_urls(message)
    categories = [rule.category for rule in matched]
    observed_indicators = [
        {
            "source": "message_pattern",
            "code": rule.category,
            "category": rule.category,
            "reason": rule.reason,
            "points": max(0, int(rule.weight)),
        }
        for rule in matched
    ]
    raw_points = sum(item["points"] for item in observed_indicators)

    # Count each URL structure indicator type once across the message.
    seen_url_indicators = set()
    for item in url_report["urls"]:
        for indicator in item["indicators"]:
            code = indicator["code"]
            if code not in seen_url_indicators:
                seen_url_indicators.add(code)
                points = max(0, int(url_weights.get(code, 0)))
                observed_indicators.append({
                    "source": "url_structure",
                    "code": code,
                    "category": "Suspicious URL structure",
                    "host": item.get("host"),
                    "reason": indicator["reason"],
                    "points": points,
                })
                raw_points += points
    if url_report["urls"] and not seen_url_indicators:
        observed_indicators.append({
            "source": "url_observation",
            "code": "url_present",
            "category": "URL present",
            "reason": "A URL was found, but no structural warning was flagged and its reputation was not checked.",
            "points": 0,
        })
    if seen_url_indicators:
        categories.append("Suspicious URL structure")

    score = max(0, min(100, int(raw_points)))
    reasons = list(dict.fromkeys(item["reason"] for item in observed_indicators))
    if not reasons:
        reasons = ["No major scam patterns matched these heuristic rules. This is not proof that the message is safe."]

    status = (
        "FRAUD" if score >= fraud_threshold
        else "SUSPICIOUS" if score >= suspicious_threshold
        else "SAFE"
    )
    if score >= fraud_threshold:
        uncertainty = "Several high-weight heuristic indicators matched; verify independently"
    elif score >= suspicious_threshold:
        uncertainty = "Some heuristic indicators matched; verify independently"
    else:
        uncertainty = "Few or no indicators matched; this does not establish safety"
    if not categories:
        categories = ["General analysis"]
    safety_recommendations = _safety_recommendations(status, categories)
    limitations = [
        "Message and URL-structure matches are offline heuristics; wording and context can cause missed scams or false alarms.",
        "A low score or no match does not prove that a sender, message, or payment request is safe.",
        "Risk points are rule weights, not a calibrated probability or a real-world accuracy estimate.",
    ]
    if url_report["urls"]:
        limitations.append(
            "URL reputation is not confirmed unless a configured provider returns a current result; unchecked URLs remain UNKNOWN."
        )

    return {
        "status": status,
        "risk_level": _risk_level(status),
        "risk_score": score,
        "confidence_label": uncertainty,
        "confidence": uncertainty,  # compatibility for the existing frontend/API clients
        "category": categories[0],
        "all_categories": list(dict.fromkeys(categories)),
        "reasons": reasons,
        "detection_reason": " ".join(reasons),
        "observed_indicators": observed_indicators,
        "identified_indicators": observed_indicators,
        "safety_recommendations": safety_recommendations,
        "recommended_action": safety_recommendations[0],
        "analysis_limitations": limitations,
        "evidence_status": "indicators_observed" if observed_indicators else "no_patterns_matched",
        "analysis_method": "offline_rule_based_heuristic",
        "scoring": {
            "raw_points": int(raw_points),
            "score_cap": 100,
            "cap_applied": raw_points > 100,
            "note": "Each message category and each URL-structure indicator type contributes at most once. Points are heuristic weights, not a probability.",
        },
        "urls": url_report["urls"],
        "url_analysis": {
            "reputation_checked": False,
            "reputation_status": "not_checked",
            "note": "Only URL structure was inspected; no URL was visited and no reputation service was queried.",
        },
    }
