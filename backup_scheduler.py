"""Single-process UTC scheduler for daily SQLite backups."""

from datetime import datetime, time, timedelta, timezone
import json
import threading

from backup_database import backup_database


def next_backup_time(now, hour, minute):
    """Return the next UTC occurrence of the configured daily backup time."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    scheduled = datetime.combine(
        now.date(), time(hour=hour, minute=minute), tzinfo=timezone.utc
    )
    return scheduled if scheduled > now else scheduled + timedelta(days=1)


class DailyBackupScheduler:
    def __init__(self, flask_app):
        self.app = flask_app
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="upi-shield-daily-backup",
            daemon=True,
        )

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=60)

    def _run(self):
        app = self.app
        hour = app.config["BACKUP_HOUR_UTC"]
        minute = app.config["BACKUP_MINUTE_UTC"]
        app.logger.info(
            "%s",
            json.dumps({
                "event": "backup_scheduler_started",
                "hour_utc": hour,
                "minute_utc": minute,
            }, sort_keys=True),
        )
        while not self._stop.is_set():
            now = datetime.now(timezone.utc)
            run_at = next_backup_time(now, hour, minute)
            if self._stop.wait(max(0.0, (run_at - now).total_seconds())):
                return
            try:
                with app.app_context():
                    backup_database(
                        app.config["DATABASE_PATH"],
                        app.config["BACKUP_DIRECTORY"],
                        keep_count=app.config["BACKUP_RETENTION_COUNT"],
                        keep_days=app.config["BACKUP_RETENTION_DAYS"],
                    )
            except Exception as error:
                app.logger.error(
                    "%s",
                    json.dumps({
                        "event": "scheduled_backup_failed",
                        "error_type": type(error).__name__,
                    }, sort_keys=True),
                )
            else:
                app.logger.info('{"event":"scheduled_backup_completed"}')


def start_scheduler(flask_app):
    if not flask_app.config.get("ENABLE_SCHEDULED_BACKUPS"):
        return None
    return DailyBackupScheduler(flask_app).start()
