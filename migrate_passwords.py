"""Back up the live database, then hash existing plaintext passwords in place."""

import hashlib
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from database import DEFAULT_DATABASE, connection, migrate_legacy_passwords


def _snapshot(database_path):
    """Capture a consistent SQLite backup through SQLite's backup API."""
    backup_dir = Path(tempfile.mkdtemp(prefix="upi-shield-ai-password-backup-"))
    backup_path = backup_dir / "database-before-password-migration.db"
    source_uri = database_path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(source_uri, uri=True) as source, sqlite3.connect(backup_path) as target:
        source.backup(target)
    return backup_path


def _fingerprint(conn, query):
    digest = hashlib.sha256()
    for row in conn.execute(query):
        digest.update(repr(tuple(row)).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _database_state(database_path):
    with connection(database_path) as conn:
        return {
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "scans": conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0],
            "user_data": _fingerprint(
                conn, "SELECT id,name,email,photo FROM users ORDER BY id"
            ),
            "scan_data": _fingerprint(conn, "SELECT * FROM scan_history ORDER BY id"),
            "integrity": conn.execute("PRAGMA integrity_check").fetchone()[0],
            "foreign_key_violations": len(
                conn.execute("PRAGMA foreign_key_check").fetchall()
            ),
        }


def _passwords_are_hashed(database_path):
    from database import PASSWORD_HASH_PATTERN

    with connection(database_path) as conn:
        return all(
            PASSWORD_HASH_PATTERN.fullmatch(row[0] or "")
            for row in conn.execute("SELECT password FROM users")
        )


def _restore(database_path, backup_path):
    restore_path = database_path.with_suffix(database_path.suffix + ".restore")
    shutil.copy2(backup_path, restore_path)
    os.replace(restore_path, database_path)


def main():
    database_path = Path(os.getenv("DATABASE_PATH", str(DEFAULT_DATABASE))).resolve()
    if not database_path.is_file():
        raise SystemExit("Database file not found; migration stopped without creating a database.")

    backup_path = _snapshot(database_path)
    before = _database_state(database_path)
    backup_state = _database_state(backup_path)
    if before != backup_state:
        raise SystemExit("Backup validation failed; the database was not changed.")

    committed = False
    try:
        migrated = migrate_legacy_passwords(database_path)
        committed = True
        after = _database_state(database_path)
        if (
            after["users"] != before["users"]
            or after["scans"] != before["scans"]
            or after["user_data"] != before["user_data"]
            or after["scan_data"] != before["scan_data"]
            or after["integrity"] != "ok"
            or after["foreign_key_violations"] != 0
            or not _passwords_are_hashed(database_path)
        ):
            raise RuntimeError("Post-migration validation failed.")
    except Exception:
        if committed:
            _restore(database_path, backup_path)
        raise

    print(f"Password migration complete. Updated accounts: {migrated}.")
    print(f"Preserved users: {after['users']}; preserved scans: {after['scans']}.")
    print("SQLite integrity: ok; foreign-key violations: 0.")
    print(f"Recovery backup: {backup_path}")


if __name__ == "__main__":
    main()
