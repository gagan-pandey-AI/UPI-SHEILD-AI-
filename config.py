"""Environment-based settings for UPI Shield AI."""

import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

# Local .env files are convenient in development. Production uses deployment
# environment variables and never reads a file from the application directory.
if os.getenv("APP_ENV", "development").strip().lower() != "production":
    load_dotenv(BASE_DIR / ".env", override=False)

IS_PRODUCTION = os.getenv("APP_ENV", "development").strip().lower() == "production"


def _csv_values(name, default=()):
    value = os.getenv(name)
    values = default if value is None else value.split(",")
    return tuple(dict.fromkeys(
        part.strip().lower().rstrip(".") for part in values if part.strip()
    ))


def _env_bool(name, default=False):
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default, minimum, maximum):
    value = int(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _env_float(name, default, minimum, maximum):
    value = float(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


class Config:
    APP_ENV = "production" if IS_PRODUCTION else "development"
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or (
        None if IS_PRODUCTION else secrets.token_hex(32)
    )
    DEBUG = _env_bool("FLASK_DEBUG", False) and not IS_PRODUCTION
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database.db"))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "static" / "uploads"))
    BACKUP_DIRECTORY = os.getenv(
        "BACKUP_DIRECTORY", str(BASE_DIR / "backups" / "database")
    )

    _render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
    APP_ALLOWED_HOSTS = _csv_values(
        "APP_ALLOWED_HOSTS", (_render_hostname,) if _render_hostname else ()
    )
    TRUSTED_HOSTS = list(APP_ALLOWED_HOSTS) if IS_PRODUCTION else None
    TRUSTED_PROXY_HOPS = _env_int("TRUSTED_PROXY_HOPS", 0, 0, 3)
    FORCE_HTTPS = _env_bool("FORCE_HTTPS", IS_PRODUCTION)
    ENABLE_HSTS = _env_bool("ENABLE_HSTS", False) and IS_PRODUCTION
    HTTPS_VERIFIED = _env_bool("HTTPS_VERIFIED", False)

    ENABLE_SCHEDULED_BACKUPS = _env_bool("ENABLE_SCHEDULED_BACKUPS", False)
    BACKUP_HOUR_UTC = _env_int("BACKUP_HOUR_UTC", 2, 0, 23)
    BACKUP_MINUTE_UTC = _env_int("BACKUP_MINUTE_UTC", 15, 0, 59)
    BACKUP_RETENTION_COUNT = _env_int("BACKUP_RETENTION_COUNT", 30, 2, 1000)
    BACKUP_RETENTION_DAYS = _env_int("BACKUP_RETENTION_DAYS", 30, 1, 3650)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAX_MESSAGE_LENGTH = 10_000
    MAX_PROFILE_PHOTO_SIZE = 4 * 1024 * 1024
    MAX_PROFILE_PHOTO_PIXELS = 20_000_000
    MAX_IMAGE_SCAN_SIZE = 4 * 1024 * 1024
    MAX_IMAGE_SCAN_PIXELS = 20_000_000
    OCR_LANGUAGES = os.getenv("OCR_LANGUAGES", "eng+hin")
    TESSERACT_CMD = os.getenv("TESSERACT_CMD")

    URL_REPUTATION_PROVIDER = os.getenv(
        "URL_REPUTATION_PROVIDER", "google_safe_browsing"
    ).strip().lower()
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    URL_REPUTATION_TIMEOUT_SECONDS = _env_float(
        "URL_REPUTATION_TIMEOUT_SECONDS", 4, 0.1, 30
    )
    URL_REPUTATION_MAX_URLS_PER_SCAN = _env_int(
        "URL_REPUTATION_MAX_URLS_PER_SCAN", 5, 1, 20
    )

    PASSWORD_RESET_TTL_SECONDS = _env_int("PASSWORD_RESET_TTL_SECONDS", 600, 60, 3600)
    PASSWORD_RESET_RESEND_SECONDS = _env_int("PASSWORD_RESET_RESEND_SECONDS", 60, 30, 3600)
    PASSWORD_RESET_MAX_ATTEMPTS = _env_int("PASSWORD_RESET_MAX_ATTEMPTS", 5, 1, 20)
    PASSWORD_RESET_CODE_DIGITS = _env_int("PASSWORD_RESET_CODE_DIGITS", 8, 6, 10)
    MAIL_HOST = os.getenv("MAIL_HOST")
    MAIL_PORT = _env_int("MAIL_PORT", 587, 1, 65535)
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_FROM = os.getenv("MAIL_FROM")
    MAIL_USE_TLS = _env_bool("MAIL_USE_TLS", True)
    MAIL_USE_SSL = _env_bool("MAIL_USE_SSL", False)
    MAIL_TIMEOUT_SECONDS = _env_float("MAIL_TIMEOUT_SECONDS", 10, 0.1, 30)
    OCR_TIMEOUT_SECONDS = 15

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 60 * 60

    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    @classmethod
    def validate(cls):
        """Reject production settings that would make the app unsafe to serve."""
        if not IS_PRODUCTION:
            return

        secret = cls.SECRET_KEY
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
        if not isinstance(secret_bytes, bytes) or len(secret_bytes) < 32:
            raise RuntimeError(
                "Production requires FLASK_SECRET_KEY containing at least 32 bytes of random data."
            )
        if not cls.APP_ALLOWED_HOSTS:
            raise RuntimeError(
                "Production requires APP_ALLOWED_HOSTS or the hosting platform's trusted hostname."
            )
        for hostname in cls.APP_ALLOWED_HOSTS:
            if len(hostname) > 253 or not re.fullmatch(r"[a-z0-9.-]+", hostname):
                raise RuntimeError("APP_ALLOWED_HOSTS contains an invalid hostname.")
        if "TRUSTED_PROXY_HOPS" not in os.environ:
            raise RuntimeError(
                "Production requires an explicit TRUSTED_PROXY_HOPS value for its network topology."
            )
        if not cls.FORCE_HTTPS:
            raise RuntimeError("Production requires FORCE_HTTPS=true.")
        if cls.ENABLE_HSTS and not cls.HTTPS_VERIFIED:
            raise RuntimeError(
                "Set HTTPS_VERIFIED=true only after confirming the production domain serves HTTPS before enabling HSTS."
            )
