# Security, privacy, and release notes

## Product limits

Luna Guard is an on-demand scanner and quarantine helper. It is not a replacement for Microsoft Defender or another maintained endpoint protection product, does not provide real-time protection, and cannot promise to detect every threat. A clean result covers only the paths and system components the scan could inspect. Permission failures, unsupported files, and resource limits are reported as an incomplete scan.

The mobile app checks only files the user selects. It does not inspect other apps' private data, extract archive members, or upload file contents.

First launch shows a short, dismissible onboarding that explains scan coverage, protection limits, and feed-update destinations. It does not request elevated access before the user starts an action that needs it.

## Local data

The desktop app binds its HTTP server to loopback, creates a new unpredictable token for each run, sends that token in a request header, and checks Host and Origin. The UI does not put the token in a URL. API bodies are JSON-only and size-limited; requests are rate-limited.

Threat-feed updates contact MalwareBazaar (including its recent detections feed), ThreatFox, and URLhaus. Scanned file contents and scan history are not sent to those providers. The optional abuse.ch Auth-Key is stored locally in `%LOCALAPPDATA%\LunaGuard\config.json`. Application activity logs are kept in process memory. Scan history is stored locally and may include file paths and detection reasons. PowerShell history results record a line number and rule reason, not the command text.

The security audit log at `%LOCALAPPDATA%\LunaGuard\audit.jsonl` contains allowlisted event names, timestamps, bounded result categories, scan IDs, and quarantine IDs. It is capped at 2 MiB with one rotated backup. It does not record file paths or API keys.

## Quarantine

Quarantine creates a random ID and durable metadata before copying, verifies SHA-256 before removing the source, and records each state change atomically. Restore checks the stored digest, refuses a conflicting destination, and writes to a temporary file before an atomic no-overwrite placement. Startup recovery reconciles safe interrupted operations and leaves ambiguous files in a recovery-required state. Permanent deletion requires an explicit confirmation in the UI and verifies the digest again.

## Archive resource limits

Archive inspection is capped at 10,000 members, 256 MiB per member, 512 MiB total expanded data, nesting depth 8, compression ratio 1,000:1, and 180 seconds per archive. Encrypted, corrupt, unsupported, or over-budget content may be skipped; those conditions must leave the scan marked incomplete. ZIP central-directory metadata still uses memory proportional to the capped member count.

## YARA rules and benchmark

Bundled rules identify themselves as first-party heuristics. Their metadata says when licensing or independent review is incomplete, and describes known false-positive patterns. The recursive loader does not fetch community rules automatically. PE signature presence is only a metadata-directory check; publisher/version strings are file resources and may be forged. Neither field proves a valid digital signature. Risk scores are heuristic evidence summaries, not calibrated probabilities. Run `python benchmarks/run_benchmark.py` for a deterministic synthetic smoke set. Its metrics are not a claim about real-world malware detection effectiveness.

## Build and signing

Python runtime and build dependencies are pinned in `requirements.txt` and `requirements-build.txt`. CI pins the Flutter SDK version, but `mobile/pubspec.lock` is not present yet, so Flutter package resolution is not fully locked and mobile rebuilds may select newer compatible transitive packages. CI records the source commit, tool versions, SHA-256 checksum, and an explicit unsigned status with each build. Desktop executables and the current Android APK are not production-signed because no signing certificate/key has been configured. Verify a downloaded file against its adjacent `SHA256SUMS.txt` or `.sha256` file; a checksum confirms file integrity relative to that checksum, not that the software is harmless.

## Reporting a security issue

Please report suspected vulnerabilities through the repository owner's GitHub security reporting channel when enabled, or open a private contact with the maintainer before publishing exploit details. Do not include API keys, personal file contents, or signing material in an issue.
