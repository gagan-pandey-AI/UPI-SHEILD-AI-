"""Restore a verified SQLite backup to a new, inactive database path."""

import argparse
from contextlib import closing
import json
import logging
import os
from pathlib import Path
import sqlite3
import tempfile

from backup_database import inspect_database
from config import Config


LOGGER = logging.getLogger("upi_shield.restore")


def restore_database(source_path, target_path, *, active_database=None):
    """Restore to a new path without replacing the active configured database."""
    source = Path(source_path).resolve()
    target = Path(target_path).resolve()
    active = Path(active_database or Config.DATABASE_PATH).resolve()
    if not source.is_file():
        raise FileNotFoundError("Backup source file does not exist.")
    if source == target:
        raise ValueError("Restore target must differ from the backup source.")
    if target == active:
        raise ValueError("Restore target matches the configured active database; refusing to overwrite it.")
    if os.path.lexists(target):
        raise FileExistsError("Restore target already exists; choose a new path.")

    source_summary = inspect_database(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".restore-", suffix=".partial", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        uri = source.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=10)) as backup, closing(sqlite3.connect(temporary)) as restored:
            backup.backup(restored)
        try:
            os.chmod(temporary, 0o600)
        except (OSError, NotImplementedError):
            pass
        restored_summary = inspect_database(temporary)
        if restored_summary != source_summary:
            raise ValueError("Restored database verification did not match the source backup.")
        # A hard link is atomic and fails if another process created the target.
        os.link(temporary, target)
        temporary.unlink()
        try:
            os.chmod(target, 0o600)
        except (OSError, NotImplementedError):
            pass
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    LOGGER.info(
        "%s",
        json.dumps({
            "event": "database_restored_to_new_path",
            "users": restored_summary["row_counts"].get("users", 0),
            "scans": restored_summary["row_counts"].get("scan_history", 0),
        }, sort_keys=True),
    )
    return {"path": target, **restored_summary}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Verified SQLite backup file")
    parser.add_argument("--target", required=True, help="New database path; existing paths are refused")
    args = parser.parse_args(argv)
    try:
        result = restore_database(args.source, args.target)
    except Exception as error:
        raise SystemExit(f"Restore failed ({type(error).__name__}); the active database was not replaced.") from None
    counts = result["row_counts"]
    print(
        f"Verified restore written to: {result['path']} | integrity=ok | "
        f"users={counts.get('users', 0)} | scans={counts.get('scan_history', 0)}"
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
