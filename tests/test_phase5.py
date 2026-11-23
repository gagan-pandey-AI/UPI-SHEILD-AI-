import re
import tempfile
import unittest
from pathlib import Path

from app import app
from database import connection, initialize_database


class Phase5FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="upi-shield-phase5-test-")
        self.database_path = Path(self.temp.name) / "test.db"
        self.upload_path = Path(self.temp.name) / "uploads"
        self.upload_path.mkdir()
        initialize_database(self.database_path)
        with connection(self.database_path) as conn:
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Primary Test", "primary@example.test", "test-only-hash"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                ("A routine appointment confirmation.", "SAFE", 0),
            )
            conn.execute(
                "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                ("Second Test", "second@example.test", "test-only-hash"),
            )
            conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (2,?,?,?)",
                ("Share your OTP at other-user-private-marker", "FRAUD", 95),
            )
        app.config.update(
            TESTING=True,
            PROPAGATE_EXCEPTIONS=True,
            WTF_CSRF_ENABLED=True,
            RATELIMIT_ENABLED=False,
            DATABASE_PATH=str(self.database_path),
            UPLOAD_FOLDER=str(self.upload_path),
        )
        self.client = app.test_client()
        self.client.environ_base["REMOTE_ADDR"] = "198.51.100.91"
        with self.client.session_transaction() as current:
            current["user_id"] = 1
            current["user_name"] = "Primary Test"
            current["user_email"] = "primary@example.test"

    def tearDown(self):
        self.temp.cleanup()

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', response.data)
        self.assertIsNotNone(match, f"Missing CSRF form token on {path}")
        return match.group(1).decode()

    def test_safety_centre_aggregates_only_current_users_scans(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Personal Scam Safety Centre", response.data)
        self.assertIn(b"Scam-category breakdown", response.data)
        self.assertIn(b"Risk-score distribution", response.data)
        self.assertIn(b"Weekly scans", response.data)
        self.assertIn(b"Your recent scans", response.data)
        self.assertNotIn(b"other-user-private-marker", response.data)
        fraud_card = re.search(
            rb'<article class="card fraud">.*?<div class="number">\s*(\d+)',
            response.data,
            re.S,
        )
        self.assertIsNotNone(fraud_card)
        self.assertEqual(fraud_card.group(1), b"0")

    def test_dashboard_category_reanalysis_is_bounded_to_recent_250_scans(self):
        with connection(self.database_path) as conn:
            conn.executemany(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                [(f"Routine notice {index}", "SAFE", 0) for index in range(260)],
            )
        from unittest.mock import patch
        from app import analyze_sms

        with patch("app.analyze_sms", wraps=analyze_sms) as detector:
            response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(detector.call_count, 250)

    def test_history_deletion_is_csrf_protected_and_owner_scoped(self):
        with connection(self.database_path) as conn:
            own_id = conn.execute("SELECT id FROM scan_history WHERE user_id=1").fetchone()[0]
            other_id = conn.execute("SELECT id FROM scan_history WHERE user_id=2").fetchone()[0]
        no_csrf = self.client.post(f"/history/{own_id}/delete")
        self.assertEqual(no_csrf.status_code, 400)
        token = self.csrf_token("/history")
        own = self.client.post(
            f"/history/{own_id}/delete", data={"csrf_token": token}
        )
        self.assertEqual(own.status_code, 302)
        other = self.client.post(
            f"/history/{other_id}/delete", data={"csrf_token": token}
        )
        self.assertEqual(other.status_code, 302)
        with connection(self.database_path) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM scan_history WHERE id=?", (own_id,)).fetchone())
            self.assertIsNotNone(conn.execute("SELECT 1 FROM scan_history WHERE id=?", (other_id,)).fetchone())

    def test_pdf_report_is_private_and_excludes_scan_text(self):
        message = "Share your OTP now at https://192.0.2.77/login?token=private-url-marker"
        with connection(self.database_path) as conn:
            cursor = conn.execute(
                "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                (message, "FRAUD", 91),
            )
            own_id = cursor.lastrowid
            other_id = conn.execute("SELECT id FROM scan_history WHERE user_id=2").fetchone()[0]
        response = self.client.get(f"/history/{own_id}/report.pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn(b"attachment", response.headers["Content-Disposition"].encode().lower())
        self.assertTrue(response.data.startswith(b"%PDF-1.4"))
        self.assertIn(b"Scan Assessment Report", response.data)
        self.assertIn(b"risk score: 91/100", response.data.lower())
        self.assertIn(b"192.0.2.77", response.data)
        self.assertIn(b"OTP", response.data)
        self.assertIn(b"safety recommendations", response.data.lower())
        self.assertNotIn(message.encode(), response.data)
        self.assertNotIn(b"private-url-marker", response.data)
        xref_offset = int(response.data.rsplit(b"startxref\n", 1)[1].splitlines()[0])
        self.assertTrue(response.data[xref_offset:].startswith(b"xref\n"))
        xref_lines = response.data[xref_offset:].splitlines()
        object_count = int(xref_lines[1].split()[1])
        for object_number, row in enumerate(xref_lines[3:3 + object_count - 1], start=1):
            object_offset = int(row[:10])
            self.assertTrue(response.data[object_offset:].startswith(f"{object_number} 0 obj".encode()))
        self.assertEqual(self.client.get(f"/history/{other_id}/report.pdf").status_code, 404)
        self.assertEqual(list(self.upload_path.iterdir()), [])

    def test_simulator_reveals_fictional_safety_learning_without_persistence(self):
        with connection(self.database_path) as conn:
            before = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        page = self.client.get("/simulator")
        self.assertEqual(page.status_code, 200)
        for title in (b"urgent KYC notice", b"easy-income job offer", b"unexpected reward",
                      b"urgent payment request", b"remote-access request"):
            self.assertIn(title, page.data)
        self.assertIn(b"fictional", page.data.lower())
        token = self.csrf_token("/simulator")
        response = self.client.post(
            "/simulator",
            data={"csrf_token": token, "scenario_id": "kyc", "answer": "unsure"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Learning note", response.data)
        self.assertIn(b"Warning signs", response.data)
        self.assertIn(b"official banking app", response.data)
        invalid = self.client.post(
            "/simulator",
            data={"csrf_token": token, "scenario_id": "unknown", "answer": "scam"},
        )
        self.assertEqual(invalid.status_code, 400)
        with connection(self.database_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0], before)

    def test_history_page_does_not_render_another_users_scan_or_message(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Download PDF", response.data)
        self.assertIn(b"Delete my record", response.data)
        self.assertNotIn(b"other-user-private-marker", response.data)


if __name__ == "__main__":
    unittest.main()
