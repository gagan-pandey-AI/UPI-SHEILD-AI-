import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from app import app
from backup_database import backup_database, inspect_database
from backup_scheduler import next_backup_time
from database import connection, initialize_database, initialize_phase4_schema
from initialize_empty_database import initialize_if_missing
from provision_database import provision_database
from restore_database import restore_database


class Stage2AppSecurityTests(unittest.TestCase):
    def setUp(self):
        self.original_config = app.config.copy()
        app.config.update(
            APP_ENV="development",
            TESTING=False,
            PROPAGATE_EXCEPTIONS=False,
            FORCE_HTTPS=False,
            ENABLE_HSTS=False,
            HTTPS_VERIFIED=False,
            TRUSTED_HOSTS=None,
            WTF_CSRF_ENABLED=True,
            RATELIMIT_ENABLED=False,
        )

    def tearDown(self):
        app.config.update(self.original_config)

    def test_liveness_does_not_create_or_require_database(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-health-") as temporary:
            path = Path(temporary) / "missing.sqlite3"
            app.config["DATABASE_PATH"] = str(path)
            client = app.test_client()
            live = client.get("/health/live")
            ready = client.get("/health/ready")
            self.assertEqual(live.status_code, 200)
            self.assertEqual(live.get_json(), {"status": "alive"})
            self.assertEqual(ready.status_code, 503)
            self.assertNotIn(str(path), ready.get_data(as_text=True))
            self.assertFalse(path.exists())

    def test_readiness_checks_required_tables_and_returns_safe_service_states(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-health-") as temporary:
            path = Path(temporary) / "ready.sqlite3"
            app.config["DATABASE_PATH"] = str(path)
            initialize_database(path)
            self.assertEqual(app.test_client().get("/health/ready").status_code, 503)
            initialize_phase4_schema(path)
            response = app.test_client().get("/health/ready")
            self.assertEqual(response.status_code, 200)
            result = response.get_json()
            self.assertEqual(result["database"], "available")
            self.assertEqual(set(result["external_services"]), {"smtp", "url_reputation"})
            self.assertTrue(set(result["external_services"].values()).issubset({
                "unknown", "available", "unavailable", "not_configured",
            }))
            raw = response.get_data(as_text=True)
            self.assertNotIn(str(path), raw)
            self.assertNotIn("FLASK_SECRET_KEY", raw)

    def test_security_headers_and_private_response_caching(self):
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertTrue(response.headers.get("X-Request-ID"))

    def test_https_redirect_and_hsts_require_explicit_verification(self):
        app.config.update(APP_ENV="production", FORCE_HTTPS=True)
        client = app.test_client()
        redirected = client.get("http://localhost/?source=check")
        self.assertEqual(redirected.status_code, 308)
        self.assertEqual(redirected.location, "https://localhost/?source=check")
        self.assertNotIn("Strict-Transport-Security", redirected.headers)

        app.config.update(ENABLE_HSTS=True, HTTPS_VERIFIED=True)
        verified = client.get("https://localhost/")
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(
            verified.headers["Strict-Transport-Security"], "max-age=31536000"
        )

    def test_generic_error_response_and_logs_omit_exception_text(self):
        original_view = app.view_functions["home"]

        def fail_with_private_detail():
            raise RuntimeError("private-scan-content-marker")

        app.view_functions["home"] = fail_with_private_detail
        try:
            with self.assertLogs(app.logger, level="ERROR") as captured:
                response = app.test_client().get("/")
        finally:
            app.view_functions["home"] = original_view
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private-scan-content-marker", response.get_data(as_text=True))
        self.assertNotIn("private-scan-content-marker", "\n".join(captured.output))
        self.assertIn("request_failed", "\n".join(captured.output))

    def test_profile_photo_is_only_available_to_its_owner(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-photo-") as temporary:
            root = Path(temporary)
            database_path = root / "test.sqlite3"
            uploads = root / "uploads"
            uploads.mkdir()
            initialize_database(database_path)
            initialize_phase4_schema(database_path)
            with connection(database_path) as conn:
                conn.execute(
                    "INSERT INTO users (name,email,password,photo) VALUES (?,?,?,?)",
                    ("Test User", "owner@example.test", "unused", "owner.png"),
                )
            (uploads / "owner.png").write_bytes(b"synthetic image fixture")
            app.config.update(DATABASE_PATH=str(database_path), UPLOAD_FOLDER=str(uploads))
            client = app.test_client()
            self.assertEqual(client.get("/profile-photo/owner.png").status_code, 404)
            with client.session_transaction() as current:
                current["user_id"] = 1
            owned = client.get("/profile-photo/owner.png")
            self.assertEqual(owned.status_code, 200)
            self.assertEqual(owned.headers["Cache-Control"], "private, no-store")
            owned.close()
            self.assertEqual(client.get("/profile-photo/../owner.png").status_code, 404)
            self.assertEqual(client.get("/static/uploads/owner.png").status_code, 404)


class Stage2ProductionConfigTests(unittest.TestCase):
    def run_config_probe(self, extra_env=None, *, remove=()):
        environment = os.environ.copy()
        for name in remove:
            environment.pop(name, None)
        environment.update({
            "APP_ENV": "production",
            "FLASK_SECRET_KEY": "s" * 64,
            "APP_ALLOWED_HOSTS": "shield.example.test",
            "TRUSTED_PROXY_HOPS": "1",
            "FORCE_HTTPS": "true",
            "FLASK_DEBUG": "true",
        })
        environment.update(extra_env or {})
        return subprocess.run(
            [sys.executable, "-c", (
                "import json; from app import app; "
                "print(json.dumps({'debug': app.config['DEBUG'], "
                "'secure': app.config['SESSION_COOKIE_SECURE'], "
                "'httponly': app.config['SESSION_COOKIE_HTTPONLY'], "
                "'samesite': app.config['SESSION_COOKIE_SAMESITE'], "
                "'hosts': app.config['TRUSTED_HOSTS'], "
                "'proxy': type(app.wsgi_app).__name__}))"
            )],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
        )

    def test_production_config_disables_debug_and_sets_cookie_and_proxy_defaults(self):
        result = self.run_config_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(result.stdout.splitlines()[-1])
        self.assertFalse(values["debug"])
        self.assertTrue(values["secure"])
        self.assertTrue(values["httponly"])
        self.assertEqual(values["samesite"], "Lax")
        self.assertEqual(values["hosts"], ["shield.example.test"])
        self.assertEqual(values["proxy"], "ProxyFix")

    def test_production_requires_allowed_host_and_verified_https_before_hsts(self):
        missing_host = self.run_config_probe({"APP_ALLOWED_HOSTS": ""})
        self.assertNotEqual(missing_host.returncode, 0)
        self.assertIn("APP_ALLOWED_HOSTS", missing_host.stderr)

        unsafe_hsts = self.run_config_probe({"ENABLE_HSTS": "true", "HTTPS_VERIFIED": "false"})
        self.assertNotEqual(unsafe_hsts.returncode, 0)
        self.assertIn("HTTPS_VERIFIED", unsafe_hsts.stderr)

    def test_deployment_files_pin_dependencies_and_use_single_persistent_service(self):
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "requirements-production.txt").read_text(encoding="utf-8")
        self.assertIn("gunicorn==23.0.0", requirements)
        self.assertIn("Flask==3.1.3", requirements)
        self.assertNotIn(">=", requirements)
        render = (root / "render.yaml").read_text(encoding="utf-8")
        self.assertIn("plan: 1c-2g", render)
        self.assertIn("numInstances: 1", render)
        self.assertIn("mountPath: /var/data", render)
        self.assertIn("healthCheckPath: /health/ready", render)
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("tesseract-ocr-hin", dockerfile)
        self.assertIn("gosu app", (root / "docker-entrypoint.sh").read_text(encoding="utf-8"))
        self.assertTrue((root / "wsgi.py").is_file())
        self.assertTrue((root / "Procfile").is_file())


class Stage2SQLiteBackupTests(unittest.TestCase):
    def make_database(self, path, *, with_reset_table=True):
        initialize_database(path)
        if with_reset_table:
            initialize_phase4_schema(path)
        with connection(path) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Synthetic User", "synthetic@example.test", "hash-value"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (?,?,?,?)",
                (1, "synthetic private message", "SAFE", 0),
            )
            if with_reset_table:
                conn.execute(
                    "INSERT INTO password_reset_tokens (user_id,otp_hash,expires_at,attempts,sent_at) VALUES (?,?,?,?,?)",
                    (1, "a" * 64, 2_000_000_000, 0, 1_900_000_000),
                )

    def test_online_backup_and_restore_preserve_records_without_overwriting_active_db(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-backup-test-") as temporary:
            root = Path(temporary)
            active = root / "active.sqlite3"
            backup_dir = root / "backups"
            restored = root / "restored.sqlite3"
            self.make_database(active)
            result = backup_database(active, backup_dir)
            self.assertEqual(result["integrity"], "ok")
            self.assertEqual(result["row_counts"]["users"], 1)
            self.assertEqual(result["row_counts"]["scan_history"], 1)
            self.assertEqual(result["row_counts"]["password_reset_tokens"], 1)

            with connection(active) as conn:
                conn.execute(
                    "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                    ("Later User", "later@example.test", "hash-value"),
                )
            restored_summary = restore_database(
                result["path"], restored, active_database=active
            )
            self.assertEqual(restored_summary["integrity"], "ok")
            self.assertEqual(restored_summary["row_counts"]["users"], 1)
            self.assertEqual(restored_summary["row_counts"]["scan_history"], 1)
            self.assertEqual(restored_summary["row_counts"]["password_reset_tokens"], 1)
            self.assertEqual(inspect_database(active)["row_counts"]["users"], 2)
            with self.assertRaisesRegex(ValueError, "active database"):
                restore_database(result["path"], active, active_database=active)
            with self.assertRaises(FileExistsError):
                restore_database(result["path"], restored, active_database=active)

    def test_backup_retention_keeps_at_least_two_verified_copies(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-retention-test-") as temporary:
            root = Path(temporary)
            database = root / "source.sqlite3"
            backup_dir = root / "backups"
            self.make_database(database)
            for _ in range(4):
                backup_database(database, backup_dir, keep_count=2, keep_days=1)
            copies = list(backup_dir.glob("database-*.sqlite3"))
            self.assertEqual(len(copies), 2)
            self.assertTrue(all(inspect_database(path)["integrity"] == "ok" for path in copies))

    def test_provisioning_is_backup_first_and_preserves_existing_row_counts(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-provision-test-") as temporary:
            root = Path(temporary)
            database = root / "legacy.sqlite3"
            backup_dir = root / "backups"
            self.make_database(database, with_reset_table=False)
            result = provision_database(database, backup_dir)
            self.assertEqual(result["row_counts"]["users"], 1)
            self.assertEqual(result["row_counts"]["scan_history"], 1)
            self.assertEqual(result["row_counts"]["password_reset_tokens"], 0)
            self.assertTrue(result["backup"]["path"].is_file())
            with connection(database) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], 1)

    def test_empty_initializer_never_touches_an_existing_path(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-init-test-") as temporary:
            existing = Path(temporary) / "existing.sqlite3"
            existing.write_bytes(b"leave this file unchanged")
            before = existing.read_bytes()
            self.assertFalse(initialize_if_missing(existing))
            self.assertEqual(existing.read_bytes(), before)

    def test_empty_initializer_creates_only_the_fresh_application_schema(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-new-db-test-") as temporary:
            fresh = Path(temporary) / "new.sqlite3"
            self.assertTrue(initialize_if_missing(fresh))
            self.assertEqual(
                set(inspect_database(fresh)["row_counts"]),
                {"users", "scan_history", "password_reset_tokens"},
            )

    def test_scheduler_computes_a_future_utc_occurrence(self):
        before = datetime(2026, 11, 23, 2, 14, tzinfo=timezone.utc)
        at_time = datetime(2026, 11, 23, 2, 15, tzinfo=timezone.utc)
        self.assertEqual(
            next_backup_time(before, 2, 15),
            datetime(2026, 11, 23, 2, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(
            next_backup_time(at_time, 2, 15),
            datetime(2026, 11, 24, 2, 15, tzinfo=timezone.utc),
        )


if __name__ == "__main__":
    unittest.main()
