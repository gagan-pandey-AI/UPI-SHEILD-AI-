"""Initialize a brand-new deployment database without touching existing files."""

import os
from pathlib import Path
import sqlite3

from config import Config
from database import DEFAULT_DATABASE, connection, initialize_database, initialize_phase4_schema


def initialize_if_missing(database_path=None):
    path = Path(
        database_path or os.getenv("DATABASE_PATH", str(Config.DATABASE_PATH or DEFAULT_DATABASE))
    ).resolve()
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    initialize_database(path)
    initialize_phase4_schema(path)
    with connection(path) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("New database failed its integrity check.")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("New database failed its foreign-key check.")
    return True


def main():
    path = Path(
        os.getenv("DATABASE_PATH", str(Config.DATABASE_PATH or DEFAULT_DATABASE))
    ).resolve()
    created = initialize_if_missing(path)
    if created:
        print("Created a new empty SQLite schema; no existing database was changed.")
    else:
        print("Existing SQLite file found; it was left unchanged.")


if __name__ == "__main__":
    main()
