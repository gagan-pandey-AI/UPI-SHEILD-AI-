"""Flask application routes for UPI Shield AI."""

import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from io import BytesIO
from PIL import Image, UnidentifiedImageError

from flask import Flask, abort, flash, g, jsonify, make_response, redirect, render_template, request, send_file, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import connection
from email_service import send_password_reset_email as _deliver_password_reset_email
from fraud_detector import analyze_sms
from pdf_reports import create_scan_report
from qr_analyzer import analyze_qr
from simulator import SCENARIOS, get_scenario
from ocr_service import OCRUnavailableError, extract_text, get_ocr_status
from url_reputation import check_url, unchecked_result


app = Flask(__name__)
app.config.from_object(Config)
Config.validate()

trusted_proxy_hops = app.config["TRUSTED_PROXY_HOPS"]
if trusted_proxy_hops:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=trusted_proxy_hops,
        x_proto=trusted_proxy_hops,
    )

Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=app.config["RATELIMIT_STORAGE_URI"],
)

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
JSON_SCAN_PATHS = {
    "/check", "/scan-image", "/extract-image", "/analyze-extracted-image",
}
ALLOWED_PHOTO_TYPES = {
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
}
_SERVICE_HEALTH_LOCK = threading.Lock()
_SERVICE_HEALTH = {
    "url_reputation": {"status": "unknown"},
    "smtp": {"status": "unknown"},
}
#=====================================================================================
def validate_profile_image(content, expected_format, max_pixels=20_000_000):
    """Validate that uploaded bytes contain a genuine PNG or JPEG image."""
    try:
        with Image.open(BytesIO(content)) as image:
            if image.format != expected_format:
                return False
            if image.width * image.height > max_pixels:
                return False

            image.verify()

        # Reopen the image and force decoding to detect corrupt image data.
        with Image.open(BytesIO(content)) as image:
            if image.format != expected_format:
                return False

            image.load()

        return True

    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError):
        return False

#=======================================================================================
def _error(message, status):
    return jsonify({"error": message}), status


def _valid_login_fields(email, password):
    return bool(
        isinstance(email, str)
        and len(email) <= 254
        and EMAIL_PATTERN.fullmatch(email.strip())
        and isinstance(password, str)
        and 0 < len(password) <= 128
    )


def _valid_registration_fields(name, email, password):
    return bool(
        isinstance(name, str)
        and 1 <= len(name.strip()) <= 80
        and _valid_login_fields(email, password)
        and len(password) >= 8
    )


def _mail_configuration_ready():
    tls_enabled = bool(app.config.get("MAIL_USE_TLS"))
    ssl_enabled = bool(app.config.get("MAIL_USE_SSL"))
    return bool(
        app.config.get("MAIL_HOST")
        and app.config.get("MAIL_FROM")
        and app.config.get("MAIL_PORT")
        and (tls_enabled != ssl_enabled)
        and (bool(app.config.get("MAIL_USERNAME")) == bool(app.config.get("MAIL_PASSWORD")))
    )


def _record_service_health(service, status):
    if service not in _SERVICE_HEALTH or status not in {
        "unknown", "available", "unavailable", "not_configured",
    }:
        return
    with _SERVICE_HEALTH_LOCK:
        _SERVICE_HEALTH[service] = {"status": status}


def _public_service_health():
    with _SERVICE_HEALTH_LOCK:
        current = {name: value["status"] for name, value in _SERVICE_HEALTH.items()}
    if not (
        app.config.get("URL_REPUTATION_PROVIDER") == "google_safe_browsing"
        and app.config.get("GOOGLE_SAFE_BROWSING_API_KEY")
    ):
        current["url_reputation"] = "not_configured"
    if not _mail_configuration_ready():
        current["smtp"] = "not_configured"
    return current


def _log_external_failure(service, provider, error_code):
    """Log fixed integration metadata as JSON; omit URLs, credentials, and OTPs."""
    app.logger.warning(
        "external_service_failure %s",
        json.dumps({
            "service": service,
            "provider": provider,
            "error_status": error_code,
        }, separators=(",", ":"), sort_keys=True),
    )


def send_password_reset_email(recipient, otp):
    """Deliver a password reset code without logging the recipient or code."""
    return _deliver_password_reset_email(app.config, recipient, otp)


def _check_url_reputation(url):
    result = check_url(url, settings=app.config)
    if result.get("reputation_status") == "checked":
        _record_service_health("url_reputation", "available")
    elif result.get("error_status") == "missing_credentials":
        _record_service_health("url_reputation", "not_configured")
    elif result.get("error_status") not in {
        None, "invalid_url", "scan_limit_exceeded",
    }:
        _record_service_health("url_reputation", "unavailable")
    if result.get("error_status") not in {
        None, "invalid_url", "missing_credentials", "scan_limit_exceeded",
    }:
        _log_external_failure(
            "url_reputation", result.get("provider"), result.get("error_status")
        )
    return result


def _enrich_url_reputation(analysis):
    """Attach bounded provider results while keeping failed and skipped URLs UNKNOWN."""
    urls = analysis.get("urls", [])
    if not isinstance(urls, list):
        return analysis
    try:
        limit = int(app.config.get("URL_REPUTATION_MAX_URLS_PER_SCAN", 5))
    except (TypeError, ValueError):
        limit = 5
    limit = max(1, min(limit, 20))

    checked = 0
    successful = 0
    failure_count = 0
    for index, item in enumerate(urls):
        if not isinstance(item, dict):
            continue
        structural_indicators = list(item.get("indicators") or [])
        if index < limit and isinstance(item.get("url"), str):
            result = _check_url_reputation(item["url"])
        else:
            result = unchecked_result(
                item.get("url", ""), settings=app.config, error="scan_limit_exceeded"
            )
        item.update(result)
        item["identified_indicators"] = structural_indicators
        if result["reputation_status"] == "checked":
            checked += 1
            successful += 1
        elif result["reputation_status"] in {"error", "invalid"}:
            failure_count += 1

    if urls:
        if successful == len(urls):
            aggregate = "checked"
        elif successful:
            aggregate = "partial"
        elif failure_count:
            aggregate = "unavailable"
        else:
            aggregate = "not_checked"
    else:
        aggregate = "not_checked"
    analysis["url_analysis"] = {
        **(analysis.get("url_analysis") or {}),
        "reputation_checked": checked > 0,
        "reputation_status": aggregate,
        "checked_url_count": checked,
        "note": (
            "Reputation lookups use the configured provider. A no-match result is not a guarantee of safety."
            if checked else "URL reputation was not confirmed; unchecked URLs remain UNKNOWN."
        ),
    }
    malicious_count = sum(item.get("risk_level") == "MALICIOUS" for item in urls if isinstance(item, dict))
    analysis["url_reputation_alert"] = (
        {
            "risk_level": "MALICIOUS",
            "count": malicious_count,
            "message": (
                f"A reputation provider reported a potential threat for {malicious_count} URL(s). "
                "Avoid opening them until you verify the destinations independently."
            ),
        }
        if malicious_count else None
    )
    suspicious_count = sum(
        item.get("risk_level") == "SUSPICIOUS"
        for item in urls if isinstance(item, dict)
    )
    if malicious_count:
        analysis["status"] = "FRAUD"
        analysis["risk_level"] = "HIGH"
        analysis["external_reputation_risk_level"] = "MALICIOUS"
        analysis["confidence_label"] = (
            "A configured reputation provider reported a potential threat; verify independently."
        )
        analysis["confidence"] = analysis["confidence_label"]
        analysis["all_categories"] = list(dict.fromkeys(
            [*(analysis.get("all_categories") or []), "Known malicious URL"]
        ))
        analysis["detection_reason"] = " ".join(filter(None, (
            analysis.get("detection_reason"),
            "A configured reputation provider reported a potential threat for a URL.",
        )))
        action = "Do not open the reported URL or enter information there. Verify the sender independently."
        analysis["safety_recommendations"] = list(dict.fromkeys(
            [*(analysis.get("safety_recommendations") or []), action]
        ))
        analysis["recommended_action"] = action
    elif suspicious_count and analysis.get("status") == "SAFE":
        analysis["status"] = "SUSPICIOUS"
        analysis["risk_level"] = "MEDIUM"
        analysis["external_reputation_risk_level"] = "SUSPICIOUS"
        action = "Avoid opening the suspicious URL until you verify its destination independently."
        analysis["safety_recommendations"] = list(dict.fromkeys(
            [*(analysis.get("safety_recommendations") or []), action]
        ))
        analysis["recommended_action"] = action
    else:
        analysis["external_reputation_risk_level"] = (
            "SAFE"
            if urls and all(
                isinstance(item, dict) and item.get("risk_level") == "SAFE"
                for item in urls
            )
            else "UNKNOWN"
        )
    limitations = list(analysis.get("analysis_limitations") or [])
    if urls:
        limitations.append(
            "Reputation lookup results may miss new threats or misclassify safe URLs; no URL was visited."
        )
    analysis["analysis_limitations"] = list(dict.fromkeys(limitations))
    return analysis


def _otp_hash(otp):
    key = app.config["SECRET_KEY"]
    if not isinstance(key, bytes):
        key = str(key).encode("utf-8")
    return hmac.digest(key, otp.encode("ascii"), "sha256").hex()


def _otp_length():
    return int(app.config["PASSWORD_RESET_CODE_DIGITS"])


def _ocr_diagnostics():
    return get_ocr_status(
        executable=app.config.get("TESSERACT_CMD"),
        configured_languages=app.config.get("OCR_LANGUAGES", "eng+hin"),
    )


def _image_ocr(content, status=None):
    """Run local Tesseract OCR over in-memory bytes; no image is written to disk."""
    text, _ = extract_text(
        content,
        executable=app.config.get("TESSERACT_CMD"),
        configured_languages=app.config.get("OCR_LANGUAGES", "eng+hin"),
        timeout=app.config.get("OCR_TIMEOUT_SECONDS", 15),
        status=status,
    )
    return text


def _image_safety_recommendations(result):
    categories = {str(value).casefold() for value in result.get("all_categories", [])}
    recommendations = []
    if any("kyc" in item or "banking" in item for item in categories):
        recommendations.append(
            "Verify account or KYC requests using your bank's official app or a phone number you already trust."
        )
    if any("otp" in item or "credential" in item for item in categories):
        recommendations.append("Never share an OTP, UPI PIN, CVV, or password with a caller or message sender.")
    if any("upi" in item or "payment" in item for item in categories):
        recommendations.append("You do not need to enter a UPI PIN to receive money; decline unexpected collect requests.")
    if any("job" in item for item in categories):
        recommendations.append("Check job offers through the employer's official careers site and do not pay a fee to get work.")
    if any("reward" in item or "refund" in item or "utility" in item for item in categories):
        recommendations.append("Check rewards, refunds, and bill alerts in the official service app; avoid links in unsolicited messages.")
    if any("remote-access" in item for item in categories):
        recommendations.append("Do not install remote-control apps or share your screen at the request of an unknown caller.")
    if not recommendations:
        recommendations.append("No major text patterns matched. Verify unexpected requests independently before acting.")
    return recommendations


@app.before_request
def _start_request_diagnostics():
    g.request_id = uuid.uuid4().hex
    g.request_started = time.perf_counter()
    if (
        app.config["APP_ENV"] == "production"
        and app.config["FORCE_HTTPS"]
        and request.path not in {"/health/live", "/health/ready"}
        and not request.is_secure
    ):
        return redirect(request.url.replace("http://", "https://", 1), code=308)


@app.after_request
def _secure_response(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data: blob: https://images.unsplash.com; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; "
        "connect-src 'self'"
    )
    if request.endpoint != "static":
        response.headers.setdefault("Cache-Control", "no-store")
    if (
        app.config["APP_ENV"] == "production"
        and app.config["ENABLE_HSTS"]
        and app.config["HTTPS_VERIFIED"]
        and request.is_secure
    ):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    request_id = getattr(g, "request_id", None)
    if request_id:
        response.headers["X-Request-ID"] = request_id
        started = getattr(g, "request_started", time.perf_counter())
        event = {
            "event": "http_request",
            "request_id": request_id,
            "method": request.method,
            "endpoint": request.endpoint or "unmatched",
            "status": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        level = app.logger.warning if response.status_code >= 500 else app.logger.info
        level("%s", json.dumps(event, sort_keys=True, separators=(",", ":")))
    return response


@app.route("/")
def home():
    return render_template("welcome.html")


@app.get("/health/live")
def health_live():
    """Liveness probe; it does not touch the database or integrations."""
    return jsonify({"status": "alive"}), 200


@app.get("/health/ready")
def health_ready():
    """Readiness probe with a minimal SQLite query and safe integration states."""
    database_path = Path(app.config["DATABASE_PATH"])
    if not database_path.is_file():
        return jsonify({"status": "not_ready"}), 503
    try:
        with connection(database_path) as conn:
            conn.execute("SELECT 1").fetchone()
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not {"users", "scan_history", "password_reset_tokens"}.issubset(tables):
                return jsonify({"status": "not_ready"}), 503
    except (OSError, sqlite3.Error):
        return jsonify({"status": "not_ready"}), 503
    return jsonify({
        "status": "ready",
        "database": "available",
        "external_services": _public_service_health(),
    }), 200


@app.get("/profile-photo/<filename>")
def profile_photo(filename):
    """Serve a profile photo only to the signed-in account that owns it."""
    user_id = session.get("user_id")
    if user_id is None:
        abort(404)
    with connection(app.config["DATABASE_PATH"]) as conn:
        user = conn.execute(
            "SELECT photo FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if (
        user is None
        or not filename
        or Path(filename).name != filename
        or filename in {".", "..", "default.png"}
        or user["photo"] != filename
    ):
        abort(404)
    response = make_response(send_from_directory(
        app.config["UPLOAD_FOLDER"], filename, conditional=True
    ))
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.get("/static/uploads/<path:filename>")
def deny_public_profile_upload(filename):
    """Prevent old static upload URLs from bypassing photo ownership checks."""
    abort(404)


@app.route("/check", methods=["POST"])
@limiter.limit("20 per minute")
def check():
    if "user_id" not in session:
        return _error("Please log in to scan a message.", 401)
    if not request.is_json:
        return _error("Send the scan as a JSON object.", 415)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("The request body must be a JSON object.", 400)
    sms = data.get("message")
    if not isinstance(sms, str):
        return _error("Message must be text.", 400)
    if not sms.strip():
        return _error("Enter a message to scan.", 400)
    if len(sms) > app.config["MAX_MESSAGE_LENGTH"]:
        return _error(
            f"Message must be {app.config['MAX_MESSAGE_LENGTH']} characters or fewer.",
            413,
        )

    result = _enrich_url_reputation(analyze_sms(sms))
    try:
        with connection(app.config["DATABASE_PATH"]) as conn:
            conn.execute(
                """INSERT INTO scan_history
                   (user_id, message, status, risk_score)
                   VALUES (?, ?, ?, ?)""",
                (session["user_id"], sms, result["status"], result["risk_score"]),
            )
    except sqlite3.IntegrityError:
        session.clear()
        return _error("Your session has expired. Please log in again.", 401)
    return jsonify(result), 200


@app.route("/scan-image", methods=["POST"])
@app.route("/extract-image", methods=["POST"])
@limiter.limit("8 per hour", scope="image_scan")
def scan_image():
    if "user_id" not in session:
        return _error("Please log in to scan an image.", 401)

    upload = request.files.get("image")
    if upload is None or not upload.filename:
        return _error("Choose a PNG or JPEG image to scan.", 400)
    extension = Path(upload.filename).suffix.lower()
    expected = ALLOWED_PHOTO_TYPES.get(extension)
    if expected is None or upload.mimetype != expected[0]:
        return _error("Only PNG and JPEG images are supported.", 415)

    content = upload.stream.read(app.config["MAX_IMAGE_SCAN_SIZE"] + 1)
    if len(content) > app.config["MAX_IMAGE_SCAN_SIZE"]:
        return _error("The image must be 4 MB or smaller.", 413)
    expected_format = "JPEG" if extension in {".jpg", ".jpeg"} else "PNG"
    if not content.startswith(expected[1]):
        return _error("The uploaded file is not a valid PNG or JPEG image.", 400)
    try:
        with Image.open(BytesIO(content)) as image:
            if image.width * image.height > app.config["MAX_IMAGE_SCAN_PIXELS"]:
                return _error("The image dimensions are too large to scan safely.", 413)
            if image.format != expected_format:
                return _error("The image contents do not match the selected file type.", 415)
        if not validate_profile_image(content, expected_format):
            return _error("The image is corrupt or unreadable.", 400)
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError):
        return _error("The image is corrupt or unreadable.", 400)

    ocr_status = _ocr_diagnostics()
    if not ocr_status["languages_used"]:
        return _error(ocr_status["message"], 503)
    try:
        extracted = _image_ocr(content, status=ocr_status)
    except OCRUnavailableError as error:
        return _error(error.public_message, 503)
    except TimeoutError:
        return _error("OCR took too long to process this image. Try a smaller or clearer image.", 504)
    except ImportError:
        return _error("OCR support is not installed. Install the requirements from requirements.txt.", 503)
    except Exception as error:
        # TesseractNotFoundError and missing traineddata are setup failures.
        from pytesseract import TesseractError, TesseractNotFoundError
        if isinstance(error, TesseractNotFoundError):
            return _error(
                "Local OCR is unavailable. Install Tesseract and the configured language data, then retry.",
                503,
            )
        if isinstance(error, TesseractError):
            app.logger.warning("Local OCR engine failed without retaining image content.")
            return _error("The OCR engine could not process this image. Check its installation and language data.", 503)
        if isinstance(error, RuntimeError) and "timeout" in str(error).lower():
            return _error("OCR took too long to process this image. Try a smaller or clearer image.", 504)
        app.logger.warning("Image OCR failed without retaining the uploaded content.")
        return _error("OCR could not read this image. Try a clearer PNG or JPEG.", 422)

    extracted = extracted.strip() if isinstance(extracted, str) else ""
    if len(extracted) > app.config["MAX_MESSAGE_LENGTH"]:
        return _error("The extracted text is too long to scan safely.", 413)
    try:
        with Image.open(BytesIO(content)) as image:
            image.load()
            qr_analysis = analyze_qr(
                image.copy(),
                reputation_checker=_check_url_reputation,
                reputation_provider=app.config.get("URL_REPUTATION_PROVIDER"),
            )
    except Exception:
        app.logger.warning("QR decoding failed without retaining uploaded content.")
        qr_analysis = {
            "decoded": False,
            "codes": [],
            "message": "QR analysis could not be completed for this image.",
        }

    if request.path == "/extract-image":
        return jsonify({
            "extracted_text": extracted,
            "qr_analysis": qr_analysis,
            "scan_source": "image_ocr",
            "analysis_pending_review": True,
        }), 200

    if not extracted:
        result = analyze_sms("")
        result.update({
            "status": "NO_TEXT_DETECTED",
            "risk_level": "UNKNOWN",
            "confidence_label": "OCR found no readable text",
            "confidence": "OCR found no readable text",
            "category": "No suspicious text detected",
            "evidence_status": "insufficient_ocr_text",
            "reasons": [
                "OCR found no readable text to assess. This does not mean the image is verified safe."
            ],
            "detection_reason": "OCR found no readable text to assess.",
        })
    else:
        result = _enrich_url_reputation(analyze_sms(extracted))
    qr_level = qr_analysis.get("risk_level", "UNKNOWN")
    if qr_level == "MALICIOUS":
        result["status"] = "FRAUD"
        result["risk_level"] = "HIGH"
        result["category"] = "Known malicious QR URL"
        result["all_categories"] = list(dict.fromkeys(
            [*(result.get("all_categories") or []), "Known malicious QR URL"]
        ))
        result["detection_reason"] = " ".join(filter(None, (
            result.get("detection_reason"), qr_analysis.get("detection_reason")
        )))
        result["recommended_action"] = qr_analysis.get("recommended_action")
    elif qr_level == "SUSPICIOUS" and result.get("status") in {"SAFE", "NO_TEXT_DETECTED"}:
        result["status"] = "SUSPICIOUS"
        result["risk_level"] = "MEDIUM"
        result["category"] = "Suspicious QR content"
        result["all_categories"] = list(dict.fromkeys(
            [*(result.get("all_categories") or []), "Suspicious QR content"]
        ))
        result["detection_reason"] = " ".join(filter(None, (
            result.get("detection_reason"), qr_analysis.get("detection_reason")
        )))
        result["recommended_action"] = qr_analysis.get("recommended_action")
    result.update({
        "extracted_text": extracted,
        "image_authenticity_verified": False,
        "scan_source": "image_ocr",
        "qr_analysis": qr_analysis,
        "safety_recommendations": _image_safety_recommendations(result),
        "analysis_limitations": list(dict.fromkeys(
            [*(result.get("analysis_limitations") or []),
             *(qr_analysis.get("analysis_limitations") or [])]
        )),
    })
    if qr_level in {"MALICIOUS", "SUSPICIOUS"}:
        result["safety_recommendations"] = list(dict.fromkeys(
            [*(result["safety_recommendations"] or []), qr_analysis.get("recommended_action")]
        ))
    return jsonify(result), 200


@app.route("/analyze-extracted-image", methods=["POST"])
@limiter.limit("20 per hour", scope="image_scan_analysis")
def analyze_extracted_image():
    if "user_id" not in session:
        return _error("Please log in to scan extracted text.", 401)
    if not request.is_json:
        return _error("Send the extracted text as a JSON object.", 415)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("The request body must be a JSON object.", 400)
    extracted = data.get("text")
    if not isinstance(extracted, str):
        return _error("Extracted text must be text.", 400)
    if not extracted.strip():
        return _error("OCR found no text to analyze. The image is not verified safe.", 422)
    if len(extracted) > app.config["MAX_MESSAGE_LENGTH"]:
        return _error(
            f"Extracted text must be {app.config['MAX_MESSAGE_LENGTH']} characters or fewer.",
            413,
        )
    result = _enrich_url_reputation(analyze_sms(extracted))
    result.update({
        "extracted_text": extracted,
        "image_authenticity_verified": False,
        "scan_source": "image_ocr_reviewed",
        "safety_recommendations": _image_safety_recommendations(result),
    })
    return jsonify(result), 200


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    name = request.form.get("name", "")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not _valid_registration_fields(name, email, password):
        return render_template(
            "register.html",
            error="Enter a name (up to 80 characters), a valid email, and a password of 8–128 characters.",
        ), 400

    try:
        with connection(app.config["DATABASE_PATH"]) as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
            if existing:
                return render_template(
                    "register.html", error="That email is already registered. Try logging in."
                ), 409
            conn.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name.strip(), email, generate_password_hash(password)),
            )
    except sqlite3.IntegrityError:
        return render_template(
            "register.html", error="That email is already registered. Try logging in."
        ), 409
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    if not _valid_login_fields(email, password):
        return render_template(
            "login.html", error="Enter a valid email and password."
        ), 400

    with connection(app.config["DATABASE_PATH"]) as conn:
        user = conn.execute(
            "SELECT id, name, email, password FROM users WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if user is None:
            return render_template(
                "login.html", error="Invalid email or password."
            ), 401

        stored_password = user["password"]
        try:
            valid_password = check_password_hash(stored_password, password)
        except (TypeError, ValueError):
            valid_password = False

        if not valid_password and hmac.compare_digest(stored_password, password):
            # Migrate only this account after its legacy password is proven.
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(password), user["id"]),
            )
            valid_password = True

        if not valid_password:
            return render_template(
                "login.html", error="Invalid email or password."
            ), 401

        user_id, name, normalized_email = user["id"], user["name"], user["email"]

    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["user_name"] = name
    session["user_email"] = normalized_email
    return redirect("/dashboard")


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per hour", methods=["POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()
    if not isinstance(email, str) or not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return render_template(
            "forgot_password.html", error="Enter a valid registered email address."
        ), 400
    if not _mail_configuration_ready():
        return render_template(
            "forgot_password.html",
            error=("Password reset email is not configured. Set MAIL_HOST, MAIL_PORT, "
                   "MAIL_FROM, and provider TLS settings in the application environment."),
        ), 503

    now = int(time.time())
    otp = None
    user_id = None
    with connection(app.config["DATABASE_PATH"]) as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
        if user is not None:
            user_id = user["id"]
            existing = conn.execute(
                "SELECT sent_at FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            ).fetchone()
            if existing is None or now - existing["sent_at"] >= app.config["PASSWORD_RESET_RESEND_SECONDS"]:
                otp = f"{secrets.randbelow(10 ** _otp_length()):0{_otp_length()}d}"
                conn.execute(
                    """INSERT INTO password_reset_tokens
                       (user_id, otp_hash, expires_at, attempts, sent_at)
                       VALUES (?, ?, ?, 0, ?)
                       ON CONFLICT(user_id) DO UPDATE SET
                           otp_hash=excluded.otp_hash,
                           expires_at=excluded.expires_at,
                           attempts=0,
                           sent_at=excluded.sent_at""",
                    (user_id, _otp_hash(otp), now + app.config["PASSWORD_RESET_TTL_SECONDS"], now),
                )

    if otp is not None:
        try:
            send_password_reset_email(email, otp)
            _record_service_health("smtp", "available")
        except Exception:
            _record_service_health("smtp", "unavailable")
            # Do not log recipient, OTP, or provider error text; remove unusable token.
            _log_external_failure("password_reset_email", "smtp", "delivery_failed")
            with connection(app.config["DATABASE_PATH"]) as conn:
                conn.execute(
                    "DELETE FROM password_reset_tokens WHERE user_id = ? AND otp_hash = ?",
                    (user_id, _otp_hash(otp)),
                )

    return render_template(
        "forgot_password.html",
        notice=("If an account matches that address, a verification code may be sent "
                "when email delivery is available. Check your inbox or spam folder."),
    ), 200


@app.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def reset_password():
    if request.method == "GET":
        return render_template("reset_password.html", otp_length=_otp_length())

    email = request.form.get("email", "").strip().lower()
    otp = request.form.get("otp", "").strip()
    password = request.form.get("password", "")
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return render_template(
            "reset_password.html", otp_length=_otp_length(),
            error="Enter a valid email address.",
        ), 400
    if not re.fullmatch(rf"\d{{{_otp_length()}}}", otp):
        return render_template(
            "reset_password.html", otp_length=_otp_length(),
            error=f"Enter the { _otp_length() }-digit code and a new password.",
        ), 400
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return render_template(
            "reset_password.html", otp_length=_otp_length(),
            error="Choose a password between 8 and 128 characters.",
        ), 400

    now = int(time.time())
    valid = False
    with connection(app.config["DATABASE_PATH"]) as conn:
        record = conn.execute(
            """SELECT t.user_id, t.otp_hash, t.expires_at, t.attempts
               FROM password_reset_tokens AS t
               JOIN users AS u ON u.id = t.user_id
               WHERE u.email = ? COLLATE NOCASE""",
            (email,),
        ).fetchone()
        if record is not None and record["attempts"] < app.config["PASSWORD_RESET_MAX_ATTEMPTS"]:
            if record["expires_at"] > now:
                if hmac.compare_digest(record["otp_hash"], _otp_hash(otp)):
                    conn.execute(
                        "UPDATE users SET password = ? WHERE id = ?",
                        (generate_password_hash(password), record["user_id"]),
                    )
                    conn.execute(
                        "DELETE FROM password_reset_tokens WHERE user_id = ?",
                        (record["user_id"],),
                    )
                    valid = True
                else:
                    conn.execute(
                        "UPDATE password_reset_tokens SET attempts = attempts + 1 WHERE user_id = ?",
                        (record["user_id"],),
                    )
    if not valid:
        return render_template(
            "reset_password.html", otp_length=_otp_length(),
            error="The verification code is invalid, expired, or locked. Request a new code and try again.",
        ), 400

    session.clear()
    flash("Password changed. Please sign in with your new password.", "success")
    return redirect("/login")


@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect("/login")
    with connection(app.config["DATABASE_PATH"]) as conn:
        history_data = conn.execute(
            """SELECT id, status, risk_score, scan_date
               FROM scan_history WHERE user_id = ? ORDER BY id DESC""",
            (session["user_id"],),
        ).fetchall()
    return render_template("history.html", history=history_data)


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
@limiter.limit("30 per hour")
def delete_scan(scan_id):
    if "user_id" not in session:
        return redirect("/login")
    with connection(app.config["DATABASE_PATH"]) as conn:
        result = conn.execute(
            "DELETE FROM scan_history WHERE id = ? AND user_id = ?",
            (scan_id, session["user_id"]),
        )
    if result.rowcount == 1:
        flash("Your scan-history record was deleted.", "success")
    else:
        # Same response for missing and another user's record.
        flash("No matching scan-history record was found.", "error")
    return redirect("/history")


@app.route("/history/<int:scan_id>/report.pdf")
@limiter.limit("30 per hour")
def download_scan_report(scan_id):
    if "user_id" not in session:
        return redirect("/login")
    with connection(app.config["DATABASE_PATH"]) as conn:
        record = conn.execute(
            """SELECT id, message, status, risk_score, scan_date
               FROM scan_history WHERE id = ? AND user_id = ?""",
            (scan_id, session["user_id"]),
        ).fetchone()
    if record is None:
        abort(404)
    # The original message is used only in memory for analysis and is never
    # placed in the report or logged.
    analysis = analyze_sms(record["message"])
    payload = create_scan_report(record, analysis)
    response = make_response(send_file(
        BytesIO(payload),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"upi-shield-scan-{scan_id}.pdf",
    ))
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/simulator", methods=["GET", "POST"])
@limiter.limit("30 per hour", methods=["POST"])
def simulator():
    if "user_id" not in session:
        return redirect("/login")
    revealed = None
    selected_answer = None
    is_correct = None
    error = None
    if request.method == "POST":
        revealed = get_scenario(request.form.get("scenario_id", ""))
        selected_answer = request.form.get("answer", "")
        if revealed is None or selected_answer not in {"scam", "unsure", "likely_legitimate"}:
            revealed = None
            error = "Choose a valid educational scenario and assessment."
        else:
            is_correct = selected_answer == "scam"
    return render_template(
        "simulator.html",
        scenarios=SCENARIOS,
        revealed=revealed,
        selected_answer=selected_answer,
        is_correct=is_correct,
        error=error,
    ), (400 if error else 200)


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    with connection(app.config["DATABASE_PATH"]) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if user is None:
            session.clear()
            return redirect("/login")
        stats = conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status = 'FRAUD' THEN 1 ELSE 0 END) AS fraud,
                      SUM(CASE WHEN status = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                      SUM(CASE WHEN status = 'SAFE' THEN 1 ELSE 0 END) AS safe
               FROM scan_history WHERE user_id = ?""",
            (session["user_id"],),
        ).fetchone()
    fraud_count = stats["fraud"] or 0
    return render_template(
        "profile.html",
        user=user,
        total_scans=stats["total"],
        fraud_count=fraud_count,
        suspicious_count=stats["suspicious"] or 0,
        safe_count=stats["safe"] or 0,
        security_score=max(0, 100 - (fraud_count * 10)),
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    recent_analysis_limit = 250
    today = date.today()
    trend_start = today - timedelta(days=today.weekday(), weeks=7)
    with connection(app.config["DATABASE_PATH"]) as conn:
        summary = conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status = 'FRAUD' THEN 1 ELSE 0 END) AS fraud,
                      SUM(CASE WHEN status = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                      SUM(CASE WHEN status = 'SAFE' THEN 1 ELSE 0 END) AS safe
               FROM scan_history WHERE user_id = ?""",
            (session["user_id"],),
        ).fetchone()
        scans = conn.execute(
            """SELECT id, message, status, risk_score, scan_date FROM scan_history
               WHERE user_id = ? ORDER BY id DESC LIMIT ?""",
            (session["user_id"], recent_analysis_limit),
        ).fetchall()
        risk_rows = conn.execute(
            """SELECT CASE
                      WHEN risk_score BETWEEN 0 AND 19 THEN 0
                      WHEN risk_score BETWEEN 20 AND 39 THEN 1
                      WHEN risk_score BETWEEN 40 AND 59 THEN 2
                      WHEN risk_score BETWEEN 60 AND 79 THEN 3
                      ELSE 4 END AS bucket,
                      COUNT(*) AS total
               FROM scan_history WHERE user_id = ? GROUP BY bucket""",
            (session["user_id"],),
        ).fetchall()
        weekly_rows = conn.execute(
            """SELECT strftime('%Y-%W', scan_date) AS week_key, COUNT(*) AS total
               FROM scan_history
               WHERE user_id = ? AND date(scan_date) >= ?
               GROUP BY week_key""",
            (
                session["user_id"],
                trend_start.isoformat(),
            ),
        ).fetchall()

    total_scans = summary["total"] or 0
    fraud_count = summary["fraud"] or 0
    category_counts = Counter()
    risk_buckets = [
        (0, 19, "0–19"), (20, 39, "20–39"), (40, 59, "40–59"),
        (60, 79, "60–79"), (80, 100, "80–100"),
    ]
    risk_counts = Counter({label: 0 for _, _, label in risk_buckets})
    for row in risk_rows:
        risk_counts[risk_buckets[row["bucket"]][2]] = row["total"]
    for scan in scans:
        assessment = analyze_sms(scan["message"])
        category_counts[assessment.get("category") or "General analysis"] += 1

    week_map = {row["week_key"]: row["total"] for row in weekly_rows if row["week_key"]}
    monday = today - timedelta(days=today.weekday())
    weekly_trends = []
    for weeks_ago in reversed(range(8)):
        week_start = monday - timedelta(weeks=weeks_ago)
        week_key = week_start.strftime("%Y-%W")
        weekly_trends.append({
            "label": week_start.strftime("%b %d"),
            "count": week_map.get(week_key, 0),
        })
    max_weekly = max((item["count"] for item in weekly_trends), default=0)
    for item in weekly_trends:
        item["width"] = int(100 * item["count"] / max_weekly) if max_weekly else 0
    max_risk = max(risk_counts.values(), default=0)
    risk_distribution = [
        {"label": label, "count": risk_counts[label],
         "width": int(100 * risk_counts[label] / max_risk) if max_risk else 0}
        for _, _, label in risk_buckets
    ]
    category_breakdown = [
        {"category": category, "count": count}
        for category, count in category_counts.most_common()
    ]
    recent_scans = [dict(scan) for scan in scans[:10]]
    return render_template(
        "dashboard.html",
        user_name=session.get("user_name", "Member"),
        total_scans=total_scans,
        fraud_count=fraud_count,
        suspicious_count=summary["suspicious"] or 0,
        safe_count=summary["safe"] or 0,
        security_score=max(0, 100 - (fraud_count * 10)),
        recent_analysis_limit=recent_analysis_limit,
        category_sample_count=len(scans),
        recent_scans=recent_scans,
        category_breakdown=category_breakdown,
        risk_distribution=risk_distribution,
        weekly_trends=weekly_trends,
    )


@app.route("/checker")
def checker():
    return render_template("checker.html", ocr_status=_ocr_diagnostics())


@app.route("/upload_photo", methods=["POST"])
def upload_photo():
    if "user_id" not in session:
        return redirect("/login")
    photo = request.files.get("photo")
    if photo is None or not photo.filename:
        flash("Choose a PNG or JPEG profile photo.", "error")
        return redirect("/profile")

    extension = Path(photo.filename).suffix.lower()
    expected = ALLOWED_PHOTO_TYPES.get(extension)
    if expected is None or photo.mimetype != expected[0]:
        flash("Only PNG and JPEG profile photos are supported.", "error")
        return redirect("/profile")

    content = photo.stream.read(app.config["MAX_PROFILE_PHOTO_SIZE"] + 1)
    if len(content) > app.config["MAX_PROFILE_PHOTO_SIZE"]:
        flash("The profile photo must be 4 MB or smaller.", "error")
        return redirect("/profile")
    #=============================================================================================
    # if not content.startswith(expected[1]):
    #     flash("The uploaded file is not a valid PNG or JPEG image.", "error")
    #     return redirect("/profile")
    expected_format = "JPEG" if extension in {".jpg", ".jpeg"} else "PNG"

    if (
        not content.startswith(expected[1])
        or not validate_profile_image(
            content,
            expected_format,
            max_pixels=app.config["MAX_PROFILE_PHOTO_PIXELS"],
        )
    ):
        flash("The uploaded file is not a valid PNG or JPEG image.", "error")
        return redirect("/profile")

#==============================================================================================
    safe_extension = ".jpg" if extension == ".jpeg" else extension
    filename = f"{uuid.uuid4().hex}{safe_extension}"
    upload_path = Path(app.config["UPLOAD_FOLDER"]) / filename
    try:
        upload_path.write_bytes(content)
        with connection(app.config["DATABASE_PATH"]) as conn:
            result = conn.execute(
                "UPDATE users SET photo = ? WHERE id = ?",
                (filename, session["user_id"]),
            )
            if result.rowcount != 1:
                raise sqlite3.IntegrityError("Authenticated user no longer exists")
    except (OSError, sqlite3.Error):
        upload_path.unlink(missing_ok=True)
        app.logger.warning("profile_photo_update_failed")
        flash("The profile photo could not be saved. Please try again.", "error")
        return redirect("/profile")
    flash("Profile photo updated.", "success")
    return redirect("/profile")


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    message = "The form has expired or is invalid. Reload the page and try again."
    if request.path in JSON_SCAN_PATHS and "user_id" not in session:
        return _error("Please log in to scan.", 401)
    if request.path in JSON_SCAN_PATHS or request.is_json:
        return _error(message, 400)
    return message, 400


@app.errorhandler(413)
def handle_too_large(exception):
    message = "The uploaded request is too large."
    if request.path in JSON_SCAN_PATHS or request.is_json:
        return _error(message, 413)
    flash(message, "error")
    return redirect("/profile")


@app.errorhandler(429)
def handle_rate_limit(exception):
    message = "Too many requests. Please wait a little and try again."
    if request.path in JSON_SCAN_PATHS or request.is_json:
        return _error(message, 429)
    return message, 429


@app.errorhandler(Exception)
def handle_unexpected_error(exception):
    if isinstance(exception, HTTPException):
        return exception
    request_id = getattr(g, "request_id", "unavailable")
    app.logger.error(
        "%s",
        json.dumps({
            "event": "request_failed",
            "request_id": request_id,
            "error_type": type(exception).__name__,
        }, sort_keys=True, separators=(",", ":")),
    )
    message = "The request could not be completed. Please retry or contact support with the request ID."
    if request.is_json:
        return jsonify({"error": message, "request_id": request_id}), 500
    return (
        "The request could not be completed. Please retry or contact support with the request ID "
        f"{request_id}.",
        500,
    )


app.logger.info(
    "%s",
    json.dumps({
        "event": "application_startup",
        "environment": app.config["APP_ENV"],
        "debug": bool(app.config["DEBUG"]),
        "trusted_proxy_hops": trusted_proxy_hops,
        "secure_cookies": bool(app.config["SESSION_COOKIE_SECURE"]),
        "https_enforced": bool(app.config["FORCE_HTTPS"]),
        "hsts_enabled": bool(app.config["ENABLE_HSTS"] and app.config["HTTPS_VERIFIED"]),
        "url_reputation_configured": bool(
            app.config.get("URL_REPUTATION_PROVIDER") == "google_safe_browsing"
            and app.config.get("GOOGLE_SAFE_BROWSING_API_KEY")
        ),
        "smtp_configured": _mail_configuration_ready(),
        "scheduled_backups": bool(app.config["ENABLE_SCHEDULED_BACKUPS"]),
        "rate_limit_shared_backend": app.config["RATELIMIT_STORAGE_URI"] != "memory://",
    }, sort_keys=True, separators=(",", ":")),
)


if __name__ == "__main__":
    if app.config["APP_ENV"] == "production":
        raise RuntimeError("The Flask development server is disabled in production; use Gunicorn.")
    app.run(host="127.0.0.1", debug=app.config["DEBUG"])
