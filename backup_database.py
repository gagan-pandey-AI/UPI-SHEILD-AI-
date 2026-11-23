"""Create consistent, verified snapshots of a live SQLite database."""

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid

from config import Config
from database import DEFAULT_DATABASE


LOGGER = logging.getLogger("upi_shield.backups")
BACKUP_PATTERN = re.compile(r"^database-(\d{8}T\d{6}Z)-[0-9a-f]{8}\.sqlite3$")
CORE_TABLES = {"users", "scan_history"}


def _readonly_connection(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=10)


def _table_names(conn):
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def inspect_database(path):
    """Return a privacy-safe integrity summary or raise if the DB is not restorable."""
    with closing(_readonly_connection(path)) as conn:
        tables = _table_names(conn)
        missing = CORE_TABLES - tables
        if missing:
            raise ValueError("Database is missing required application tables.")
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise ValueError("SQLite integrity verification failed.")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("SQLite foreign-key verification failed.")
        counts = {
            name: conn.execute(
                f'SELECT COUNT(*) FROM "{name.replace(chr(34), chr(34) * 2)}"'
            ).fetchone()[0]
            for name in sorted(tables)
        }
    return {"integrity": "ok", "foreign_key_violations": 0, "row_counts": counts}


def _log(level, event, **fields):
    LOGGER.log(level, "%s", json.dumps({"event": event, **fields}, sort_keys=True))


def _apply_retention(directory, *, keep_count, keep_days, now):
    valid = []
    for candidate in directory.glob("database-*.sqlite3"):
        if not BACKUP_PATTERN.fullmatch(candidate.name):
            continue
        try:
            inspect_database(candidate)
            valid.append(candidate)
        except (OSError, sqlite3.Error, ValueError):
            continue
    valid.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    if len(valid) <= 2:
        return 0

    cutoff = now - timedelta(days=keep_days)
    preserved = set(valid[:2])
    removed = 0
    for index, candidate in enumerate(valid):
        if candidate in preserved:
            continue
        expired = datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc) < cutoff
        beyond_count = index >= keep_count
        if expired or beyond_count:
            try:
                candidate.unlink()
                removed += 1
            except OSError as error:
                _log(logging.WARNING, "backup_retention_failed", error_type=type(error).__name__)
    return removed


def backup_database(
    database_path=None,
    backup_directory=None,
    *,
    keep_count=30,
    keep_days=30,
    now=None,
):
    """Use SQLite's online backup API, verify the copy, then publish it atomically."""
    source_path = Path(
        database_path or os.getenv("DATABASE_PATH", str(Config.DATABASE_PATH or DEFAULT_DATABASE))
    ).resolve()
    destination_dir = Path(
        backup_directory
        or os.getenv("BACKUP_DIRECTORY", str(Config.BACKUP_DIRECTORY or source_path.parent / "backups"))
    ).resolve()
    if not source_path.is_file():
        raise FileNotFoundError("Configured SQLite database does not exist.")
    if keep_count < 2 or keep_days < 1:
        raise ValueError("Backup retention must keep at least two copies and one day.")

    destination_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(destination_dir, 0o700)
    except (OSError, NotImplementedError):
        pass

    current_time = now or datetime.now(timezone.utc)
    current_time = current_time.astimezone(timezone.utc)
    stamp = current_time.strftime("%Y%m%dT%H%M%SZ")
    final_path = destination_dir / f"database-{stamp}-{uuid.uuid4().hex[:8]}.sqlite3"
    fd, temporary_name = tempfile.mkstemp(prefix=".database-", suffix=".partial", dir=destination_dir)
    os.close(fd)
    temporary_path = Path(temporary_name)

    try:
        with closing(_readonly_connection(source_path)) as source, closing(sqlite3.connect(temporary_path)) as target:
            source.backup(target)
        try:
            os.chmod(temporary_path, 0o600)
        except (OSError, NotImplementedError):
            pass
        summary = inspect_database(temporary_path)
        os.replace(temporary_path, final_path)
        try:
            os.chmod(final_path, 0o600)
        except (OSError, NotImplementedError):
            pass
    except Exception as error:
        temporary_path.unlink(missing_ok=True)
        _log(logging.ERROR, "backup_failed", error_type=type(error).__name__)
        raise

    removed = _apply_retention(
        destination_dir,
        keep_count=keep_count,
        keep_days=keep_days,
        now=current_time,
    )
    _log(
        logging.INFO,
        "backup_created",
        backup=final_path.name,
        users=summary["row_counts"].get("users", 0),
        scans=summary["row_counts"].get("scan_history", 0),
        retention_removed=removed,
    )
    return {"path": final_path, **summary}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", default=os.getenv("DATABASE_PATH", str(Config.DATABASE_PATH or DEFAULT_DATABASE))
    )
    parser.add_argument(
        "--directory", default=os.getenv("BACKUP_DIRECTORY", Config.BACKUP_DIRECTORY)
    )
    parser.add_argument("--keep-count", type=int, default=int(os.getenv("BACKUP_RETENTION_COUNT", "30")))
    parser.add_argument("--keep-days", type=int, default=int(os.getenv("BACKUP_RETENTION_DAYS", "30")))
    args = parser.parse_args(argv)
    try:
        result = backup_database(
            args.database,
            args.directory,
            keep_count=args.keep_count,
            keep_days=args.keep_days,
        )
    except Exception as error:
        raise SystemExit(f"Database backup failed ({type(error).__name__}); see protected service logs.") from None
    print(
        f"Backup created: {result['path']} | integrity=ok | "
        f"users={result['row_counts'].get('users', 0)} | "
        f"scans={result['row_counts'].get('scan_history', 0)}"
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
