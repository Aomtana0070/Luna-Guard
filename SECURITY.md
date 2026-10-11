# Security, privacy, and release notes

## Product limits

Luna Guard is an on-demand scanner and quarantine helper. It is not a replacement for Microsoft Defender or another maintained endpoint protection product, does not provide real-time protection, and cannot promise to detect every threat. A clean result covers only the paths and system components the scan could inspect. Permission failures, unsupported files, and resource limits are reported as an incomplete scan.

The mobile app checks only files the user selects. It does not inspect other apps' private data, extract archive members, or upload file contents.

First launch shows a short, dismissible onboarding that explains scan coverage, protection limits, and feed-update destinations. It does not request elevated access before the user starts an action that needs it.

## Local data

The desktop app binds its HTTP server to loopback, creates a new unpredictable token for each run, sends that token in a request header, and checks Host and Origin. The UI does not put the token in a URL. API bodies are JSON-only and size-limited; requests are rate-limited. The request server caps concurrent workers at 32. The dashboard uses a per-response Content Security Policy nonce and contains no inline event handlers.

Threat-feed updates contact MalwareBazaar (including its recent detections feed), ThreatFox, and URLhaus. Scanned file contents and scan history are not sent to those providers. The optional abuse.ch Auth-Key is stored locally in `%LOCALAPPDATA%\LunaGuard\config.json`, protected with Windows DPAPI for the current Windows account. Legacy plaintext keys are migrated when read. This protects against offline disclosure of the config file, but not malware already running as the same Windows user. Application activity logs are kept in process memory. Scan history is stored locally and may include file paths and detection reasons. PowerShell history results record a line number and rule reason, not the command text.

The security audit log at `%LOCALAPPDATA%\LunaGuard\audit.jsonl` contains allowlisted event names, timestamps, bounded result categories, scan IDs, and quarantine IDs. It is capped at 2 MiB with one rotated backup. It does not record file paths or API keys.

## Quarantine

Quarantine creates a random ID and durable metadata before copying, verifies SHA-256 before removing the source, and records each state change atomically. Restore checks the stored digest, refuses a conflicting destination, and writes to a temporary file before an atomic no-overwrite placement. Startup recovery reconciles safe interrupted operations and leaves ambiguous files in a recovery-required state. Permanent deletion requires an explicit confirmation in the UI and verifies the digest again.

## Archive resource limits

Standard archive inspection is capped across an archive and its nested members at 10,000 members, 256 MiB per member, 512 MiB total expanded data, nesting depth 8, compression ratio 1,000:1, and 180 seconds. The optional Deep archive scan expands these budgets to 100,000 members, 1 GiB per member, 8 GiB total expanded data, nesting depth 32, and compression ratio 5,000:1, with no per-archive timer. Scan drive C: uses Deep mode and attempts all accessible directories without an overall file-count or time cap. It does not follow junctions/reparse points; each skipped point is reported as an incomplete scan to prevent loops or leaving the selected drive. Both archive modes retain finite count/size/depth/ratio bounds; Deep mode stops inspecting archives if the temporary drive cannot preserve a 1 GiB free-space reserve. Encrypted, corrupt, unsupported, low-disk, or over-budget content may be skipped; those conditions must leave the scan marked incomplete. ZIP central-directory metadata still uses memory proportional to the capped member count. Regular-file traversal and the overall drive scan remain separately stoppable by the user.

## YARA rules and benchmark

Bundled rules identify themselves as first-party heuristics. Their metadata says when licensing or independent review is incomplete, and describes known false-positive patterns. The recursive loader does not fetch community rules automatically. PE signature presence is only a metadata-directory check; publisher/version strings are file resources and may be forged. Neither field proves a valid digital signature. Risk scores are heuristic evidence summaries, not calibrated probabilities. Run `python benchmarks/run_benchmark.py` for a deterministic synthetic smoke set covering file classification, nested archive detection, timing, and incomplete results on archive budget limits. Its tiny generated fixtures and metrics are not a claim about real-world malware detection effectiveness. GitHub Actions uploads the JSON report with the Windows build artifact.

## Build and signing

Python runtime and build dependencies are pinned in `requirements.txt` and `requirements-build.txt`. CI pins the Flutter SDK version, but `mobile/pubspec.lock` is not present yet, so Flutter package resolution is not fully locked and mobile rebuilds may select newer compatible transitive packages. Ordinary branch artifacts are not production-signed. Tagged Release builds require the Android keystore secrets, sign and verify the APK, and record artifact checksums and build provenance before publication. The Windows EXE is unsigned because this project does not use a paid code-signing certificate; Windows may show an unknown publisher or SmartScreen warning. Missing Android signing secrets or failed APK verification stop the release job. The already published v1.5.1 files were not production-signed; Android APK did not use a persistent release key. Because Android updates require a matching signing identity, users may need to uninstall an earlier APK before installing the first release-key-signed build, which removes local app data. Verify a downloaded file against its adjacent checksum and provenance; a checksum confirms integrity relative to that checksum, not publisher identity or that software is harmless. Never share or commit signing private keys.

GitHub Actions are pinned to full commit SHAs. Dependabot checks Actions and Python/Dart dependencies weekly. In repository settings, require pull requests and status checks for `main`, block force pushes, and restrict creation/update of `v*` tags to trusted maintainers. Store release signing secrets in a protected `production-release` environment with required reviewer approval and a `v*` deployment branch/tag rule. Workflow YAML cannot enforce those repository-level controls; without them, a person able to push a tag may run release workflow code with repository secrets.

## Reporting a security issue

Please report suspected vulnerabilities through the repository owner's GitHub security reporting channel when enabled, or open a private contact with the maintainer before publishing exploit details. Do not include API keys, personal file contents, or signing material in an issue.
