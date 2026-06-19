import re

def analyze_sms(message):

    original_message = message
    message = message.lower()

    risk_score = 0
    reasons = []
    categories = []

    # Fraud Keywords
    fraud_keywords = {

        "bank": 10,
        "account blocked": 25,
        "account suspended": 25,
        "verify": 15,

        "kyc": 20,
        "update kyc": 25,
        "kyc expired": 30,

        "otp": 20,
        "share otp": 35,

        "upi": 15,
        "payment request": 25,
        "collect request": 30,

        "lottery": 25,
        "winner": 20,
        "reward": 20,
        "free gift": 25,

        "part time job": 30,
        "work from home": 25,
        "earn money": 25,

        "refund": 15,

        "urgent": 15,
        "immediately": 15,
        "final warning": 25,

        ".apk": 40,
        "install app": 30,
        "download app": 20,

        "बैंक": 15,
        "खाता": 15,
        "केवाईसी": 20,
        "लॉटरी": 25,
        "इनाम": 20,
        "बिजली बिल": 20
    }

    # Keyword Scan
    for keyword, score in fraud_keywords.items():

        if keyword in message:

            risk_score += score
            reasons.append(
                f"Detected keyword: {keyword}"
            )

    # Category Detection

    if "kyc" in message:
        categories.append("KYC Scam")

    if "otp" in message:
        categories.append("OTP Scam")

    if "upi" in message:
        categories.append("UPI Scam")

    if "lottery" in message:
        categories.append("Lottery Scam")

    if "part time job" in message:
        categories.append("Job Scam")

    # URL Detection

    found_url = False

    url_patterns = [
        "http://",
        "https://",
        "www.",
        ".com",
        ".in",
        ".net"
    ]

    for pattern in url_patterns:

        if pattern in message:

            found_url = True
            risk_score += 20

            reasons.append(
                "Link detected"
            )

            break

    # Short Link Detection

    short_links = [
        "bit.ly",
        "tinyurl",
        "cutt.ly",
        "rb.gy",
        "t.ly"
    ]

    for link in short_links:

        if link in message:

            risk_score += 35

            reasons.append(
                f"Suspicious short link: {link}"
            )

    # Remote Access Fraud

    remote_apps = [
        "anydesk",
        "teamviewer",
        "quicksupport"
    ]

    for app in remote_apps:

        if app in message:

            risk_score += 40

            reasons.append(
                f"Remote access app detected: {app}"
            )

    # Phone Number Detection

    phone_numbers = re.findall(
        r'\d{10}',
        message
    )

    if len(phone_numbers) > 0:

        risk_score += 10

        reasons.append(
            "Phone number detected"
        )

    # Scam Combinations

    if "otp" in message and found_url:

        risk_score += 40

        reasons.append(
            "OTP + Link Scam Pattern"
        )

    if "kyc" in message and "urgent" in message:

        risk_score += 35

        reasons.append(
            "Fake KYC Scam Pattern"
        )

    if (
        "part time job" in message
        and "earn money" in message
    ):

        risk_score += 35

        reasons.append(
            "Job Scam Pattern"
        )

    if (
        "lottery" in message
        and found_url
    ):

        risk_score += 40

        reasons.append(
            "Lottery Scam Pattern"
        )

    # ALL CAPS

    if (
        len(original_message) > 20
        and original_message.isupper()
    ):

        risk_score += 15

        reasons.append(
            "Message written in ALL CAPS"
        )

    # Excessive Symbols

    symbol_count = (
        message.count("!")
        + message.count("₹")
        + message.count("$")
    )

    if symbol_count >= 5:

        risk_score += 10

        reasons.append(
            "Too many promotional symbols"
        )

    # Multiple URLs

    urls_found = re.findall(
        r'https?://\S+|www\.\S+',
        message
    )

    if len(urls_found) >= 2:

        risk_score += 20

        reasons.append(
            "Multiple links detected"
        )

    # Limit Score

    risk_score = min(risk_score, 100)

    # Confidence

    if risk_score >= 80:
        confidence = "Very High"

    elif risk_score >= 60:
        confidence = "High"

    elif risk_score >= 40:
        confidence = "Medium"

    else:
        confidence = "Low"

    # Status

    if risk_score >= 70:

        status = "FRAUD"

    elif risk_score >= 35:

        status = "SUSPICIOUS"

    else:

        status = "SAFE"

    # Default Values

    if len(categories) == 0:

        categories.append(
            "General Analysis"
        )

    if len(reasons) == 0:

        reasons.append(
            "No major scam indicators detected"
        )




    return {

        "status": status,
        "risk_score": risk_score,
        "confidence": confidence,
        "category": categories[0],
        "all_categories": categories,
        "reasons": reasons
    }