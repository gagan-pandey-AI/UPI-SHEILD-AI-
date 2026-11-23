import io
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app import app
from database import connection, initialize_database, migrate_legacy_passwords
from werkzeug.security import check_password_hash


class SecurityWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="upi-shield-test-")
        root = Path(self.temp_dir.name)
        self.database_path = root / "test.db"
        self.upload_path = root / "uploads"
        self.upload_path.mkdir()
        initialize_database(self.database_path)
        with connection(self.database_path) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Test Account", "test@example.test", "legacy-test-password"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                ("synthetic preserved message", "SAFE", 0),
            )

        app.config.update(
            TESTING=True,
            PROPAGATE_EXCEPTIONS=True,
            WTF_CSRF_ENABLED=True,
            RATELIMIT_ENABLED=False,
            DATABASE_PATH=str(self.database_path),
            UPLOAD_FOLDER=str(self.upload_path),
            MAX_CONTENT_LENGTH=5 * 1024 * 1024,
            MAX_PROFILE_PHOTO_SIZE=4 * 1024 * 1024,
            MAX_MESSAGE_LENGTH=10_000,
        )
        self.client = app.test_client()
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.10"

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', response.data)
        if match is None:
            match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', response.data)
        self.assertIsNotNone(match, "The form should include a CSRF token.")
        return match.group(1).decode()

    def login_legacy_user(self):
        token = self.csrf_token()
        return self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": "test@example.test",
                "password": "legacy-test-password",
            },
        )

    def authenticated(self):
        with self.client.session_transaction() as current_session:
            current_session["user_id"] = 1
            current_session["user_name"] = "Test Account"
            current_session["user_email"] = "test@example.test"

    def test_legacy_password_upgrades_after_valid_login_and_preserves_scans(self):
        before = self.client.get("/")
        self.assertEqual(before.status_code, 200)
        with connection(self.database_path) as conn:
            before_scan = tuple(conn.execute("SELECT * FROM scan_history").fetchone())

        response = self.login_legacy_user()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/dashboard")
        with connection(self.database_path) as conn:
            stored = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
            after_scan = tuple(conn.execute("SELECT * FROM scan_history").fetchone())
        self.assertTrue(check_password_hash(stored, "legacy-test-password"))
        self.assertNotEqual(stored, "legacy-test-password")
        self.assertEqual(after_scan, before_scan)

    def test_initialize_database_preserves_existing_tables_and_records(self):
        with connection(self.database_path) as conn:
            before_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            before_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        initialize_database(self.database_path)
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], before_users)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], before_scans)

    def test_bulk_password_migration_is_idempotent_and_preserves_history(self):
        with connection(self.database_path) as conn:
            before_scan = tuple(conn.execute("SELECT * FROM scan_history").fetchone())
        self.assertEqual(migrate_legacy_passwords(self.database_path), 1)
        self.assertEqual(migrate_legacy_passwords(self.database_path), 0)
        with connection(self.database_path) as conn:
            stored = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
            after_scan = tuple(conn.execute("SELECT * FROM scan_history").fetchone())
        self.assertTrue(check_password_hash(stored, "legacy-test-password"))
        self.assertEqual(after_scan, before_scan)

    def test_migration_command_makes_recovery_copy_and_reports_no_private_values(self):
        env = os.environ.copy()
        env["DATABASE_PATH"] = str(self.database_path)
        result = subprocess.run(
            [sys.executable, "migrate_passwords.py"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        backup_line = next(
            line for line in result.stdout.splitlines() if line.startswith("Recovery backup: ")
        )
        backup_path = Path(backup_line.split(": ", 1)[1])
        self.assertTrue(backup_path.is_file())
        self.assertNotIn("legacy-test-password", result.stdout)
        self.assertNotIn("synthetic preserved message", result.stdout)

    def test_wrong_password_does_not_migrate_legacy_value(self):
        token = self.csrf_token()
        response = self.client.post(
            "/login",
            data={"csrf_token": token, "email": "test@example.test", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 401)
        with connection(self.database_path) as conn:
            stored = conn.execute("SELECT password FROM users WHERE id=1").fetchone()[0]
        self.assertEqual(stored, "legacy-test-password")

    def test_registration_hashes_password_and_rejects_invalid_input(self):
        token = self.csrf_token("/register")
        invalid = self.client.post(
            "/register",
            data={"csrf_token": token, "name": " ", "email": "bad", "password": "short"},
        )
        self.assertEqual(invalid.status_code, 400)
        created = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "name": "New Account",
                "email": "new@example.test",
                "password": "a-long-test-password",
            },
        )
        self.assertEqual(created.status_code, 302)
        with connection(self.database_path) as conn:
            password = conn.execute(
                "SELECT password FROM users WHERE email=?", ("new@example.test",)
            ).fetchone()[0]
        self.assertTrue(check_password_hash(password, "a-long-test-password"))

    def test_csrf_logout_and_authentication_guard(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.authenticated()
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/history").status_code, 200)
        self.assertEqual(self.client.get("/profile").status_code, 200)
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 400)

        token = self.csrf_token("/dashboard")
        response = self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").location, "/login")

    def test_check_validation_statuses_and_history_is_user_scoped(self):
        self.assertEqual(self.client.post("/check", json={"message": "test"}).status_code, 401)
        self.authenticated()
        token = self.csrf_token("/checker")
        headers = {"X-CSRFToken": token}
        self.assertEqual(self.client.post("/check", data="bad", headers=headers).status_code, 415)
        self.assertEqual(self.client.post("/check", json=[], headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/check", json={"message": 5}, headers=headers).status_code, 400)
        self.assertEqual(self.client.post("/check", json={"message": "  "}, headers=headers).status_code, 400)
        self.assertEqual(
            self.client.post("/check", json={"message": "x" * 10_001}, headers=headers).status_code,
            413,
        )

        scan = self.client.post(
            "/check", json={"message": "A routine synthetic message"}, headers=headers
        )
        self.assertEqual(scan.status_code, 200)
        scan_data = scan.get_json()
        self.assertTrue({"status", "risk_score", "confidence_label", "category",
                         "all_categories", "reasons", "urls", "url_analysis"}.issubset(scan_data))
        with connection(self.database_path) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Other Account", "other@example.test", "unused"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (2,?,?,?)",
                ("synthetic other-user marker", "FRAUD", 90),
            )
        history = self.client.get("/history")
        self.assertEqual(history.status_code, 200)
        self.assertNotIn(b"FRAUD", history.data)
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], 3)

    def test_checker_renders_heuristic_labels_and_explanation_script(self):
        self.authenticated()
        response = self.client.get("/checker")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Rule-based SMS, UPI, and phishing scam analysis", response.data)
        self.assertIn(b"Heuristic Risk Score", response.data)
        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Explainable Rule-Based Fraud Assessment", dashboard.data)
        self.assertNotIn(b"Artificial Intelligence", dashboard.data)
        script = self.client.get("/static/script.js")
        self.assertEqual(script.status_code, 200)
        self.assertIn(b"Why this assessment?", script.data)
        self.assertIn(b"not a probability", script.data)
        self.assertIn(b"Assessment unavailable", script.data)
        self.assertIn(b"Potentially unsafe URL reported", script.data)
        script.close()

    def test_upload_validation_unique_names_and_database_foreign_keys(self):
        self.authenticated()
        token = self.csrf_token("/profile")
        rejected = self.client.post(
            "/upload_photo",
            data={"csrf_token": token, "photo": (io.BytesIO(b"<svg/>"), "photo.svg", "image/svg+xml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(rejected.status_code, 302)
        self.assertEqual(list(self.upload_path.iterdir()), [])

        from PIL import Image
        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), color="green").save(image_buffer, format="PNG")
        image = image_buffer.getvalue()
        accepted = self.client.post(
            "/upload_photo",
            data={"csrf_token": token, "photo": (io.BytesIO(image), "../../profile.png", "image/png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(accepted.status_code, 302)
        saved = list(self.upload_path.iterdir())
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].suffix, ".png")
        self.assertNotIn("..", saved[0].name)

        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (999,?,?,?)",
                    ("synthetic", "SAFE", 0),
                )

    def test_upload_size_limit(self):
        self.authenticated()
        token = self.csrf_token("/profile")
        contents = b"\x89PNG\r\n\x1a\n" + b"x" * (4 * 1024 * 1024)
        response = self.client.post(
            "/upload_photo",
            data={"csrf_token": token, "photo": (io.BytesIO(contents), "large.png", "image/png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(list(self.upload_path.iterdir()), [])

    def test_login_rate_limit_returns_429(self):
        app.config["RATELIMIT_ENABLED"] = True
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.11"
        token = self.csrf_token()
        responses = [
            self.client.post(
                "/login",
                data={"csrf_token": token, "email": "test@example.test", "password": "wrong"},
            )
            for _ in range(6)
        ]
        self.assertEqual([response.status_code for response in responses[-2:]], [401, 429])

    def test_registration_rate_limit_returns_429(self):
        app.config["RATELIMIT_ENABLED"] = True
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.12"
        token = self.csrf_token("/register")
        responses = [
            self.client.post(
                "/register",
                data={"csrf_token": token, "name": "", "email": "bad", "password": "short"},
            )
            for _ in range(6)
        ]
        self.assertEqual([response.status_code for response in responses[-2:]], [400, 429])

    def test_scan_rate_limit_returns_429(self):
        app.config["RATELIMIT_ENABLED"] = True
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.13"
        self.authenticated()
        token = self.csrf_token("/checker")
        responses = [
            self.client.post(
                "/check",
                json={"message": "synthetic scan"},
                headers={"X-CSRFToken": token},
            )
            for _ in range(21)
        ]
        self.assertEqual([response.status_code for response in responses[-2:]], [200, 429])


if __name__ == "__main__":
    unittest.main()
