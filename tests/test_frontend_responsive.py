import re
import tempfile
import unittest
from pathlib import Path

from app import app
from database import connection, initialize_database, initialize_phase4_schema

ROOT = Path(__file__).resolve().parents[1]
MAIN_TEMPLATES = (
    "welcome.html",
    "login.html",
    "register.html",
    "forgot_password.html",
    "reset_password.html",
    "dashboard.html",
    "checker.html",
    "history.html",
    "profile.html",
    "simulator.html",
)


class ResponsiveMarkupTests(unittest.TestCase):
    def test_main_pages_declare_a_scaling_mobile_viewport(self):
        for filename in MAIN_TEMPLATES:
            with self.subTest(template=filename):
                markup = (ROOT / "templates" / filename).read_text(encoding="utf-8")
                self.assertRegex(
                    markup,
                    r'<meta\s+name="viewport"\s+content="width=device-width,\s*initial-scale=1(?:\.0)?"',
                )

    def test_main_pages_render_for_a_signed_in_user(self):
        with tempfile.TemporaryDirectory(prefix="upi-shield-responsive-pages-") as directory:
            path = Path(directory) / "pages.db"
            initialize_database(path)
            initialize_phase4_schema(path)
            with connection(path) as conn:
                conn.execute(
                    "INSERT INTO users (name,email,password) VALUES (?,?,?)",
                    ("Viewport Test", "viewport@example.test", "test-only-hash"),
                )
            previous = {name: app.config.get(name) for name in ("DATABASE_PATH", "TESTING", "WTF_CSRF_ENABLED")}
            app.config.update(DATABASE_PATH=str(path), TESTING=True, WTF_CSRF_ENABLED=True)
            self.addCleanup(app.config.update, previous)
            client = app.test_client()
            with client.session_transaction() as session:
                session.update(user_id=1, user_name="Viewport Test", user_email="viewport@example.test")

            for route in ("/", "/login", "/register", "/forgot-password", "/reset-password",
                          "/dashboard", "/checker", "/history", "/profile", "/simulator"):
                with self.subTest(route=route):
                    response = client.get(route)
                    self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                    self.assertIn(b"name=\"viewport\"", response.data)

    def test_styles_include_mobile_breakpoints_touch_controls_and_table_scrolling(self):
        css = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
        for width in (375, 600, 768, 900):
            with self.subTest(max_width=width):
                self.assertRegex(css, rf"@media\s*\(max-width:\s*{width}px\)")
        self.assertRegex(
            css,
            re.compile(r"button,\.button,\.nav-signout\s*\{[^}]*min-height:\s*44px", re.S),
        )
        self.assertIn(".history-table-wrap{width:100%;overflow-x:auto", css)
        self.assertRegex(
            css,
            re.compile(r"input,textarea,select\s*\{[^}]*max-width:\s*100%", re.S),
        )
        self.assertIn("overflow-wrap:anywhere", css)
        self.assertIn("prefers-reduced-motion:reduce", css)


if __name__ == "__main__":
    unittest.main()
