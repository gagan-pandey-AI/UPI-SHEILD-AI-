"""Create a verified recovery snapshot, then add Phase 4 reset-token storage."""

import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from database import DEFAULT_DATABASE, initialize_phase4_schema


def main():
    database_path = Path(os.getenv("DATABASE_PATH", str(DEFAULT_DATABASE))).resolve()
    if not database_path.is_file():
        raise SystemExit("Configured database file does not exist; no migration was run.")

    backup_dir = Path(tempfile.mkdtemp(prefix="upi-shield-phase4-recovery-"))
    backup_path = backup_dir / "database-before-phase4-migration.sqlite"
    with closing(sqlite3.connect(database_path)) as source:
        with closing(sqlite3.connect(backup_path)) as backup:
            source.backup(backup)
            if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SystemExit("Recovery copy failed its integrity check; no migration was run.")
            before = {
                table: backup.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("users", "scan_history")
            }

    initialize_phase4_schema(database_path)
    with closing(sqlite3.connect(database_path)) as migrated:
        if migrated.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("Post-migration integrity check failed.")
        after = {
            table: migrated.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("users", "scan_history")
        }
        table_exists = migrated.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='password_reset_tokens'"
        ).fetchone()
    if before != after or table_exists is None:
        raise SystemExit("Migration validation failed; preserve the recovery copy for review.")
    print("Recovery backup:", backup_path)
    print("Additive Phase 4 schema migration complete; user and scan row counts preserved.")


if __name__ == "__main__":
    main()
