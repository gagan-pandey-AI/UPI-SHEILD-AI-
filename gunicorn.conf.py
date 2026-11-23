"""Gunicorn settings for the single-instance SQLite deployment."""

import os


bind = f"0.0.0.0:{int(os.getenv('PORT', '10000'))}"
workers = 1
worker_class = "gthread"
threads = 4
timeout = 90
graceful_timeout = 90
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
preload_app = False
accesslog = None  # Flask emits sanitized structured access events without URLs or IPs.
errorlog = "-"
capture_output = True
loglevel = "info"


def post_worker_init(worker):
    import atexit

    from backup_scheduler import start_scheduler

    worker.upi_shield_backup_scheduler = start_scheduler(worker.wsgi)
    if worker.upi_shield_backup_scheduler is not None:
        atexit.register(worker.upi_shield_backup_scheduler.stop)


def worker_exit(server, worker):
    scheduler = getattr(worker, "upi_shield_backup_scheduler", None)
    if scheduler is not None:
        scheduler.stop()
