import io
import re
import sqlite3
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash

from app import app
from database import connection, initialize_database, initialize_phase4_schema


class Phase4Tests(unittest.TestCase):
    _client_counter = 40

    def setUp(self):
        type(self)._client_counter += 1
        self.temp = tempfile.TemporaryDirectory(prefix="upi-shield-phase4-test-")
        root = Path(self.temp.name)
        self.database_path = root / "test.db"
        self.upload_path = root / "uploads"
        self.upload_path.mkdir()
        initialize_database(self.database_path)
        initialize_phase4_schema(self.database_path)
        with connection(self.database_path) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Test User", "user@example.test", generate_password_hash("old-password-123")),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                ("synthetic retained message", "SAFE", 0),
            )
        app.config.update(
            TESTING=True,
            PROPAGATE_EXCEPTIONS=True,
            WTF_CSRF_ENABLED=True,
            RATELIMIT_ENABLED=False,
            DATABASE_PATH=str(self.database_path),
            UPLOAD_FOLDER=str(self.upload_path),
            MAX_CONTENT_LENGTH=5 * 1024 * 1024,
            MAX_IMAGE_SCAN_SIZE=4 * 1024 * 1024,
            MAX_IMAGE_SCAN_PIXELS=20_000_000,
            MAX_MESSAGE_LENGTH=10_000,
            PASSWORD_RESET_TTL_SECONDS=600,
            PASSWORD_RESET_RESEND_SECONDS=60,
            PASSWORD_RESET_MAX_ATTEMPTS=5,
            PASSWORD_RESET_CODE_DIGITS=8,
            MAIL_HOST="smtp.example.test",
            MAIL_PORT=587,
            MAIL_USERNAME="",
            MAIL_PASSWORD="",
            MAIL_FROM="noreply@example.test",
            MAIL_USE_TLS=True,
            MAIL_USE_SSL=False,
        )
        self.client = app.test_client()
        self.client.environ_base["REMOTE_ADDR"] = f"198.51.100.{type(self)._client_counter}"
        self.sent_codes = []

    def tearDown(self):
        self.temp.cleanup()

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', response.data)
        if match is None:
            match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def request_code(self, email="user@example.test"):
        token = self.csrf_token("/forgot-password")
        with patch("app.send_password_reset_email", side_effect=self.capture_code):
            return self.client.post(
                "/forgot-password", data={"csrf_token": token, "email": email}
            )

    def capture_code(self, email, code):
        self.sent_codes.append((email, code))

    def post_reset(self, code, password="new-password-456"):
        token = self.csrf_token("/reset-password")
        return self.client.post(
            "/reset-password",
            data={
                "csrf_token": token,
                "email": "user@example.test",
                "otp": code,
                "password": password,
            },
        )

    def authenticated(self):
        with self.client.session_transaction() as current:
            current["user_id"] = 1
            current["user_name"] = "Test User"
            current["user_email"] = "user@example.test"

    def test_login_shows_visible_password_reset_link_and_reset_pages_render(self):
        login = self.client.get("/login")
        self.assertEqual(login.status_code, 200)
        self.assertIn(b'class="password-reset-link"', login.data)
        self.assertIn(b'Forgot Password?', login.data)
        self.assertIn(b'href="/forgot-password"', login.data)
        self.assertLess(
            login.data.index(b'Login'),
            login.data.index(b'class="password-reset-link"'),
        )

        for path in ("/forgot-password", "/reset-password"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'name="csrf_token"', response.data)

    @staticmethod
    def png_bytes():
        out = io.BytesIO()
        Image.new("RGB", (32, 32), "white").save(out, format="PNG")
        return out.getvalue()

    def image_post(self, data, filename="capture.png", mime="image/png"):
        token = self.csrf_token("/checker")
        return self.client.post(
            "/scan-image",
            data={"image": (io.BytesIO(data), filename, mime), "csrf_token": token},
            headers={"X-CSRFToken": token},
            content_type="multipart/form-data",
        )

    def test_reset_request_is_generic_and_only_stores_keyed_hash(self):
        registered = self.request_code()
        code = self.sent_codes[-1][1]
        unknown = self.request_code("missing@example.test")
        self.assertEqual(registered.status_code, 200)
        self.assertEqual(unknown.status_code, 200)
        self.assertIn(b"If an account matches that address", registered.data)
        self.assertIn(b"If an account matches that address", unknown.data)
        self.assertNotIn(b"user@example.test", registered.data)
        with connection(self.database_path) as conn:
            stored = conn.execute(
                "SELECT otp_hash, expires_at FROM password_reset_tokens WHERE user_id=1"
            ).fetchone()
        self.assertNotEqual(stored["otp_hash"], code)
        self.assertEqual(len(stored["otp_hash"]), 64)
        self.assertGreater(stored["expires_at"], int(time.time()))

    def test_unconfigured_email_delivery_fails_with_setup_message(self):
        app.config["MAIL_HOST"] = None
        token = self.csrf_token("/forgot-password")
        response = self.client.post(
            "/forgot-password",
            data={"csrf_token": token, "email": "user@example.test"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"MAIL_HOST", response.data)
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM password_reset_tokens").fetchone()[0], 0)

    def test_configured_delivery_failure_is_generic_and_invalidates_token(self):
        token = self.csrf_token("/forgot-password")
        with patch("app.send_password_reset_email", side_effect=OSError("private provider diagnostic")):
            response = self.client.post(
                "/forgot-password",
                data={"csrf_token": token, "email": "user@example.test"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"If an account matches that address", response.data)
        self.assertNotIn(b"private provider diagnostic", response.data)
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM password_reset_tokens").fetchone()[0], 0)

    def test_password_reset_requests_are_rate_limited(self):
        app.config["RATELIMIT_ENABLED"] = True
        token = self.csrf_token("/forgot-password")
        responses = [
            self.client.post(
                "/forgot-password",
                data={"csrf_token": token, "email": "missing@example.test"},
            )
            for _ in range(4)
        ]
        self.assertEqual([response.status_code for response in responses], [200, 200, 200, 429])

    def test_resend_cooldown_does_not_send_or_replace_code(self):
        self.request_code()
        first = self.sent_codes[-1][1]
        with connection(self.database_path) as conn:
            before = tuple(conn.execute("SELECT otp_hash, sent_at FROM password_reset_tokens").fetchone())
        self.request_code()
        with connection(self.database_path) as conn:
            after = tuple(conn.execute("SELECT otp_hash, sent_at FROM password_reset_tokens").fetchone())
        self.assertEqual(len(self.sent_codes), 1)
        self.assertEqual(before, after)
        self.assertEqual(len(first), 8)

    def test_incorrect_code_attempts_are_limited(self):
        self.request_code()
        for _ in range(app.config["PASSWORD_RESET_MAX_ATTEMPTS"]):
            response = self.post_reset("00000000")
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"invalid, expired, or locked", response.data)
        with connection(self.database_path) as conn:
            attempts = conn.execute("SELECT attempts FROM password_reset_tokens WHERE user_id=1").fetchone()[0]
        self.assertEqual(attempts, app.config["PASSWORD_RESET_MAX_ATTEMPTS"])

    def test_expired_code_is_rejected(self):
        self.request_code()
        with connection(self.database_path) as conn:
            conn.execute(
                "UPDATE password_reset_tokens SET expires_at=? WHERE user_id=1",
                (int(time.time()) - 1,),
            )
        response = self.post_reset(self.sent_codes[-1][1])
        self.assertEqual(response.status_code, 400)
        with connection(self.database_path) as conn:
            password = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
        self.assertTrue(check_password_hash(password, "old-password-123"))

    def test_reset_code_cannot_be_reused(self):
        self.request_code()
        code = self.sent_codes[-1][1]
        accepted = self.post_reset(code)
        reused = self.post_reset(code)
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(reused.status_code, 400)
        self.assertIn(b"invalid, expired, or locked", reused.data)
        with connection(self.database_path) as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM password_reset_tokens WHERE user_id=1"
            ).fetchone())
            password = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
        self.assertTrue(check_password_hash(password, "new-password-456"))

    def test_password_reset_verification_route_is_rate_limited(self):
        app.config["RATELIMIT_ENABLED"] = True
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.199"
        token = self.csrf_token("/reset-password")
        responses = [
            self.client.post(
                "/reset-password",
                data={
                    "csrf_token": token,
                    "email": "missing@example.test",
                    "otp": "00000000",
                    "password": "valid-password-123",
                },
            )
            for _ in range(11)
        ]
        self.assertEqual([response.status_code for response in responses[:10]], [400] * 10)
        self.assertEqual(responses[10].status_code, 429)

    def test_valid_reset_changes_hash_invalidates_code_and_allows_login(self):
        self.request_code()
        code = self.sent_codes[-1][1]
        response = self.post_reset(code)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login")
        with connection(self.database_path) as conn:
            password = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM password_reset_tokens WHERE user_id=1"
            ).fetchone())
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], 1)
        self.assertTrue(check_password_hash(password, "new-password-456"))
        token = self.csrf_token("/login")
        login = self.client.post(
            "/login",
            data={"csrf_token": token, "email": "user@example.test", "password": "new-password-456"},
        )
        self.assertEqual(login.status_code, 302)
        self.assertEqual(login.location, "/dashboard")

    def test_image_scan_runs_detector_without_persisting_image_or_text(self):
        self.authenticated()
        before = self.database_path.read_bytes()
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), patch("app._image_ocr", return_value="Share your OTP now at https://192.0.2.3/login"):
            response = self.image_post(self.png_bytes())
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["scan_source"], "image_ocr")
        self.assertIn("OTP", result["category"])
        self.assertEqual(result["urls"][0]["host"], "192.0.2.3")
        self.assertFalse(result["image_authenticity_verified"])
        self.assertFalse(result["url_analysis"]["reputation_checked"])
        self.assertEqual(list(self.upload_path.iterdir()), [])
        self.assertEqual(self.database_path.read_bytes(), before)

    def test_image_scan_rejects_unsupported_corrupt_and_oversized_files(self):
        self.authenticated()
        unsupported = self.image_post(b"<svg/>", "image.svg", "image/svg+xml")
        self.assertEqual(unsupported.status_code, 415)
        corrupt = self.image_post(b"\x89PNG\r\n\x1a\nnot a png")
        self.assertEqual(corrupt.status_code, 400)
        app.config["MAX_IMAGE_SCAN_SIZE"] = 40
        oversized = self.image_post(self.png_bytes())
        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(list(self.upload_path.iterdir()), [])

    def test_blank_ocr_is_not_reported_as_safe_and_ocr_failure_is_clear(self):
        self.authenticated()
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), patch("app._image_ocr", return_value=" \n "):
            blank = self.image_post(self.png_bytes())
        self.assertEqual(blank.status_code, 200)
        self.assertEqual(blank.get_json()["status"], "NO_TEXT_DETECTED")
        self.assertIn("not mean the image is verified safe", blank.get_json()["reasons"][0])
        self.assertEqual(blank.get_json()["evidence_status"], "insufficient_ocr_text")
        self.assertEqual(blank.get_json()["observed_indicators"], [])
        self.assertIn("scoring", blank.get_json())

        from pytesseract import TesseractNotFoundError
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), patch("app._image_ocr", side_effect=TesseractNotFoundError()):
            missing_engine = self.image_post(self.png_bytes())
        self.assertEqual(missing_engine.status_code, 503)
        self.assertIn(b"Install Tesseract", missing_engine.data)

    def test_host_without_tesseract_does_not_claim_ocr_succeeded(self):
        from app import _ocr_diagnostics
        if _ocr_diagnostics()["engine_available"]:
            self.skipTest("Native Tesseract is installed; OCR setup failure is not applicable.")
        self.authenticated()
        response = self.image_post(self.png_bytes())
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Local OCR is unavailable", response.get_json()["error"].encode())

    def test_image_scan_requires_authentication_and_never_adds_history(self):
        token = self.csrf_token("/checker")
        response = self.client.post(
            "/scan-image",
            data={"csrf_token": token},
            headers={"X-CSRFToken": token},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 401)
        self.authenticated()
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), patch("app._image_ocr", return_value="A normal message"):
            self.image_post(self.png_bytes())
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], 1)
        self.assertEqual(list(self.upload_path.iterdir()), [])

    def test_image_scan_is_rate_limited(self):
        app.config["RATELIMIT_ENABLED"] = True
        self.authenticated()
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), patch("app._image_ocr", return_value=""):
            responses = [self.image_post(self.png_bytes()) for _ in range(9)]
        self.assertEqual([response.status_code for response in responses[-2:]], [200, 429])

    def test_backup_first_migration_preserves_users_and_history(self):
        migration_database = Path(self.temp.name) / "pre-migration.db"
        initialize_database(migration_database)
        with connection(migration_database) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Migration User", "migration@example.test", "hash-placeholder"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                ("private marker should not be printed", "SAFE", 0),
            )
        env = os.environ.copy()
        env["DATABASE_PATH"] = str(migration_database)
        result = subprocess.run(
            [sys.executable, "migrate_phase4.py"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        backup_line = next(
            line for line in result.stdout.splitlines() if line.startswith("Recovery backup: ")
        )
        backup = Path(backup_line.split(": ", 1)[1])
        self.assertTrue(backup.is_file())
        self.assertNotIn("private marker", result.stdout)
        with closing(sqlite3.connect(backup)) as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='password_reset_tokens'"
            ).fetchone())
        with connection(migration_database) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='password_reset_tokens'"
            ).fetchone())


if __name__ == "__main__":
    unittest.main()
