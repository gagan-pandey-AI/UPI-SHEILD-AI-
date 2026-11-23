import tempfile
import unittest
from pathlib import Path

from database import connection, initialize_database


class DashboardQueryIndexTests(unittest.TestCase):
    def test_dashboard_listing_and_weekly_queries_use_user_date_indexes(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-index-test-") as directory:
            path = Path(directory) / "indexes.db"
            initialize_database(path)
            with connection(path) as conn:
                conn.execute(
                    "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                    ("Index Test", "index@example.test", "test-only-hash"),
                )
                conn.executemany(
                    "INSERT INTO scan_history (user_id,message,status,risk_score) VALUES (1,?,?,?)",
                    [(f"message {index}", "SAFE", 0) for index in range(300)],
                )
                listing = conn.execute(
                    "EXPLAIN QUERY PLAN SELECT id,message,status,risk_score,scan_date "
                    "FROM scan_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    (1, 250),
                ).fetchall()
                weekly = conn.execute(
                    "EXPLAIN QUERY PLAN SELECT strftime('%Y-%W',scan_date),COUNT(*) "
                    "FROM scan_history WHERE user_id=? AND date(scan_date)>=? "
                    "GROUP BY strftime('%Y-%W',scan_date)",
                    (1, "2026-01-01"),
                ).fetchall()

            listing_plan = " ".join(row["detail"] for row in listing)
            weekly_plan = " ".join(row["detail"] for row in weekly)
            self.assertIn("idx_scan_history_user_id_id", listing_plan)
            self.assertIn("idx_scan_history_user_date", weekly_plan)


if __name__ == "__main__":
    unittest.main()
