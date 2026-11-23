"""Safely provision missing SQLite tables without replacing existing records."""

import os
from pathlib import Path
import sqlite3

from backup_database import backup_database
from config import Config
from database import DEFAULT_DATABASE, connection, initialize_database, initialize_phase4_schema


def _row_counts(path):
    if not Path(path).is_file():
        return {}
    with connection(path) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        return {
            table: conn.execute(
                f'SELECT COUNT(*) FROM "{table.replace(chr(34), chr(34) * 2)}"'
            ).fetchone()[0]
            for table in sorted(names)
        }


def provision_database(database_path=None, backup_directory=None):
    """Back up an existing database, then run only the existing additive schema setup."""
    path = Path(
        database_path or os.getenv("DATABASE_PATH", str(Config.DATABASE_PATH or DEFAULT_DATABASE))
    ).resolve()
    backups = backup_directory or os.getenv("BACKUP_DIRECTORY", Config.BACKUP_DIRECTORY)
    before = _row_counts(path)
    backup_result = None
    if path.is_file():
        backup_result = backup_database(path, backups)

    initialize_database(path)
    initialize_phase4_schema(path)
    after = _row_counts(path)
    for table, count in before.items():
        if after.get(table) != count:
            raise RuntimeError("Database provisioning changed existing row counts.")
    with connection(path) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Database provisioning failed its integrity check.")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("Database provisioning found a foreign-key violation.")
    if not {"users", "scan_history", "password_reset_tokens"}.issubset(after):
        raise RuntimeError("Database provisioning did not create the expected tables.")
    return {"database": path, "backup": backup_result, "row_counts": after}


def main():
    result = provision_database()
    counts = result["row_counts"]
    print(
        "Database provisioned additively; SQLite integrity=ok; "
        f"users={counts.get('users', 0)}; scans={counts.get('scan_history', 0)}; "
        f"reset_tokens={counts.get('password_reset_tokens', 0)}"
    )
    if result["backup"]:
        print(f"Pre-provisioning recovery backup: {result['backup']['path']}")


if __name__ == "__main__":
    main()
