# Technical Architecture

This is a high-level guide to the repository, not a formal architecture assurance report.

## Windows desktop

- `luna_app.py` starts the desktop shell and scanner application.
- `dashboard.html`, `locales.json`, and `luna_dashboard.py` provide the interface and local API integration.
- `luna_guard.py` contains scanning, threat-data, file analysis, YARA, correlation, and system-check logic.
- `luna_quarantine.py` implements quarantine, integrity verification, restoration, recovery, and deletion operations.
- `luna_audit.py` writes an allowlisted local security audit trail.
- `luna_rules.yar` and `rules/` contain bundled rule material. User rules can also be loaded locally.

The desktop interface is served through a loopback HTTP server. The README documents Host/Origin checks, a per-run request token, JSON body limits, rate limits, and a Content Security Policy nonce. Review implementation details directly before relying on these controls.

## Detection and data flow

Scans combine local file/hash checks, optional YARA matches, file/PE metadata, bounded archive inspection, and selected system checks. Threat-feed refreshes contact MalwareBazaar, ThreatFox, and URLhaus and maintain a local indicator database with source and lifecycle fields. The documented design does not upload scanned files or scan history to those feed providers.

Signals are combined into a capped heuristic risk score with per-signal explanations. This score is not a probability or independently validated malware verdict.

## Quarantine flow

The documented implementation records metadata, copies the file, verifies SHA-256, then removes the source. Restore verifies the expected digest and metadata, rejects destination conflicts, and writes through a temporary file before placement. Interrupted operations are reconciled conservatively. See `luna_quarantine.py` and `SECURITY.md`.

## Companion app

The `mobile/` directory contains Flutter/Dart source. The user selects files or an accessible Android directory. Hashing, local checks, and history are handled on-device. It is not the desktop scanner port: it has no desktop YARA engine, archive-member inspection, process-memory scanning, whole-device access, or automatic quarantine.

## Build and release pipeline

GitHub Actions workflows are in `.github/workflows/`. Python dependencies are pinned in `requirements.txt` and `requirements-build.txt`. The mobile Flutter SDK version is pinned in CI, but `mobile/pubspec.lock` is absent, so transitive Dart dependencies are not fully locked. Tagged Android artifacts require configured signing secrets and are signed and verified by workflow; Windows executables are unsigned. See [Build and release](09_BUILD_AND_RELEASE.md).
