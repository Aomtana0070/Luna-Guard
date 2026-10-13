# Changelog

## v1.6.0 — 2026-10-13

- Correlate file hash reputation, YARA, heuristic, signature, and suspicious metadata into a capped risk score, with the contributing signals explained in the dashboard.
- Filter recent findings by file type and severity; filtering is applied before pagination.
- Keep threat indicators in `ACTIVE`, `STALE`, and `EXPIRED` lifecycle states, retaining stale indicators for up to 30 days after their expiry.
- Refuse quarantine restore when the recorded quarantine filename does not match its item ID; continue verifying SHA-256 before restoring.
- Add security regression coverage for archive limits and failure cases, quarantine integrity and recovery, API validation, and correlated detections.
- Update Android package version to `1.6.0+10`.
