"""SQLite helpers and non-destructive schema initialization."""

import sqlite3
import re
import os
from contextlib import contextmanager
from pathlib import Path

from werkzeug.security import generate_password_hash


DEFAULT_DATABASE = Path(__file__).resolve().with_name("database.db")
PASSWORD_HASH_PATTERN = re.compile(
    r"^(?:scrypt:\d+:\d+:\d+|pbkdf2:sha(?:256|512):\d+)\$[A-Za-z0-9]+\$[0-9a-f]+$"
)


@contextmanager
def connection(database_path=None):
    """Yield a SQLite connection with referential integrity enabled."""
    path = str(database_path or DEFAULT_DATABASE)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            # SQLite file permissions are enforced by the host on Windows.
            pass
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database(database_path=None):
    """Create missing tables without dropping or replacing existing tables."""
    with connection(database_path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                photo TEXT DEFAULT 'default.png'
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_id_id "
            "ON scan_history(user_id, id DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_date "
            "ON scan_history(user_id, date(scan_date))"
        )


def migrate_legacy_passwords(database_path=None):
    """Hash legacy password values in one transaction; safe to rerun."""
    changed = 0
    with connection(database_path) as conn:
        users = conn.execute("SELECT id, password FROM users").fetchall()
        for user in users:
            stored = user["password"]
            if PASSWORD_HASH_PATTERN.fullmatch(stored or ""):
                continue
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(stored), user["id"]),
            )
            changed += 1

        remaining = conn.execute(
            "SELECT COUNT(*) FROM users WHERE password NOT LIKE 'scrypt:%' "
            "AND password NOT LIKE 'pbkdf2:%'"
        ).fetchone()[0]
        if remaining:
            raise RuntimeError("Password migration validation failed; transaction rolled back.")
    return changed


def initialize_phase4_schema(database_path=None):
    """Add the reset-token table without rebuilding or changing existing tables."""
    with connection(database_path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS password_reset_tokens (
                user_id INTEGER PRIMARY KEY,
                otp_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                sent_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"""
        )


if __name__ == "__main__":
    initialize_database()
    print("Database initialized without replacing existing tables.")
