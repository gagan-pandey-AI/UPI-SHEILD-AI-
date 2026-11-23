# UPI Shield AI v1.0.0 release checklist

Status is specific to this workspace on 2026-11-23. A checked item is implemented and verified by the named check; a pending item needs a real external account, configuration, or manual review. This file prepares a release candidate only. No tag, public release, push, or deployment has been created.

## Application and data

- [x] Local Flask startup succeeded with an isolated test database; `/health/live` returned `alive` and `/health/ready` returned `ready`.
- [x] The local database remained at 3 users and 4 scans; the pre-provision snapshot and active database both passed integrity and foreign-key checks. The snapshot restored to a new path with the same counts.
- [ ] Start the production container with the final deployment environment and verify `/health/live` and `/health/ready`.
- [ ] Configure and validate `FLASK_SECRET_KEY`, `APP_ALLOWED_HOSTS`, trusted proxy count, HTTPS, HSTS, database, upload, SMTP, OCR, provider, and rate-limit settings in the actual host.
- [ ] Confirm the SQLite database is on persistent storage and run the backup-first additive provisioning step for an imported database.
- [ ] Complete a production-shaped registration, login, SMS/UPI scan, URL lookup (if enabled), OCR/QR review, history, report, profile-photo access, and password-reset smoke test.

## Security and recovery

- [x] Existing password hashing, signed session cookies, CSRF, rate limits, upload bounds, user-scoped access, safe error handling, and security headers have regression coverage in the test suite.
- [x] The current local rate-limit backend is explicit (`memory://`); Redis URI support is documented and the optional client is in the production requirements. No live Redis connection has been tested.
- [ ] Provision shared Redis with TLS/authentication before running multiple workers or instances; verify limits across processes.
- [x] Local SQLite snapshot and restore helpers verify integrity and row counts against temporary databases in tests.
- [ ] Provision private off-site storage, versioning, public access block, SSE-KMS, least-privilege IAM, monitoring, and retention.
- [ ] Run an off-site database and upload restore drill. App-level local backups currently remain on the same volume and are not independently encrypted.
- [x] The cleanup preserves local `database.db` and uploaded images while removing them from the Git index. `.env`, caches, editor settings, and unrelated practice files are ignored.
- [ ] Review the final commit contents and scan the complete commit diff for credentials before publishing to a private repository.

## Detection and data quality

- [x] Offline, deterministic evaluation runs from `evaluation/run_evaluation.py`; synthetic and public corpus reports are separate and include confusion counts, FPR, and FNR.
- [x] UCI SMS collection: 5,574 rows, ham 4,827 / spam 747. Current rule set: accuracy 0.866703, precision 0.700000, recall 0.009371, F1 0.018494, FPR 0.000622, FNR 0.990629. The spam corpus is old and out of domain; these are not UPI fraud accuracy claims.
- [x] Synthetic fixtures: SMS n=48 (accuracy/precision/recall/F1 1.0); URLs n=16 (accuracy 0.937500, precision 1.0, recall 0.875000, F1 0.933333, FPR 0, FNR 0.125); QR payloads n=8 (all four binary metrics 1.0). These are rule-path tests only, not real-world estimates.
- [ ] Obtain a representative, licensed, independently labeled Indian scam corpus and evaluate on a held-out set before making an accuracy claim.
- [ ] Migrate the legacy Safe Browsing v4 adapter to Google Web Risk or a suitable commercial provider before commercial operation; complete privacy/terms review and provider integration tests.

## Frontend and performance

- [x] Main page templates have a mobile viewport declaration; CSS regression checks cover the 375/600/768/900 px breakpoints, 44 px navigation/button controls, wrapping inputs, reduced motion, and scrollable history table.
- [ ] Check all key screens in a real browser at 360, 375, 390, 430, 768, 1024, 1366, and 1920 CSS pixels; confirm no horizontal overflow and inspect forms, navigation, tables, and scan results.
- [ ] Rendered viewport checks were attempted with installed headless Chrome and Edge, but both failed to start a usable GPU/render context in this Windows workspace. The eight-width visual check remains unverified.
- [ ] Complete keyboard-only and screen-reader review, and verify on a physical iOS and Android device.
- [x] Dashboard history access is indexed and category reanalysis is capped at 250 recent rows; automated checks verify the cap and query plans.
- [ ] Capture a representative production-like latency and upload/OCR profile. No performance numbers are claimed without that workload.

## Build, tests, and release

- [x] Complete suite: `python -m unittest discover -s tests -v` ran 114 tests, 113 passed and 1 test for the missing-Tesseract case was skipped because Tesseract is installed on this host; the separate root detector script also exited successfully.
- [x] `node --check static/script.js`, template rendering regression checks, production configuration tests, and local startup/readiness checks passed. A production host startup was not performed.
- [x] `git diff --check` passed after fixing added trailing whitespace.
- [ ] Build the Docker image. A clean temporary context reached the Docker CLI, but the engine pipe is unavailable; no image build is claimed.
- [ ] Review all pending external configuration and rollback procedures with the deployment operator.
- [ ] Create the v1.0.0 tag/release only after the authorized repository owner approves; do not push or deploy as part of Stage 3.

## Final status

Do not mark v1.0.0 production-ready while external provider migration, off-site backup provisioning and restore drill, production environment validation, and the representative fraud dataset remain pending. The current result is a locally validated MVP candidate, not a verified production release.
