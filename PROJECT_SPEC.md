# Luna Guard — Project Reference

This file describes the current repository. The product and security decisions are documented in [README.md](README.md), [SECURITY.md](SECURITY.md), and the separate `Luna_Guard_Security_Product_Specification.md` source document supplied to the project maintainer. Older project handoff notes have been replaced because they described unbounded archives and a numeric “security score,” neither of which reflects the current design.

## Product scope

Luna Guard is an on-demand Windows desktop scanner and quarantine helper, plus a separate limited offline Flutter file checker for Android/iOS. It is not real-time antivirus and must not claim complete protection. Microsoft Defender remains the primary real-time protection layer.

Desktop scans include focused file scans or system checks for enumerated processes/memory, startup persistence, network/DNS indicators, and PowerShell history. They are read-only unless the user explicitly starts remediation. Remediation automatically acts on HIGH only; MEDIUM/LOW findings require user review. Archive findings apply to members, but quarantine moves the whole archive container.

## Desktop components

| File | Responsibility |
|---|---|
| `luna_guard.py` | CLI, SQLite threat data, feed updates, file/YARA/heuristic scans, system checks, history, remediation. |
| `luna_quarantine.py` | Durable quarantine states, SHA-256 integrity, safe restore, permanent delete, startup recovery. |
| `luna_audit.py` | Size-bounded JSONL audit log with an allowlist of fields. |
| `luna_dashboard.py` | Loopback HTTP API, token/Host/Origin checks, rate/body limits, background jobs and state. |
| `luna_app.py` | pywebview desktop window wrapper. |
| `dashboard.html`, `locales.json` | Self-contained responsive UI with Thai, English and Simplified Chinese strings. |
| `luna_rules.yar`, `rules/` | First-party YARA heuristics with recursive rule discovery and metadata; external community rules require provenance/license review. |
| `malware_knowledge.json` | Local family descriptions and behavior notes shown with detections. |
| `test_luna.py`, `test_security.py` | Scanner and security regression suites. |
| `benchmarks/run_benchmark.py` | Small synthetic smoke benchmark; not a real-world efficacy evaluation. |

## Data and security

The desktop stores data under `%LOCALAPPDATA%\LunaGuard`: SQLite threat data, local configuration, scan history, quarantine files/index, audit logs, and optional user rules. The malware hash index stores SHA-256/SHA-1/MD5, family, threat name, severity, first/last seen, source confidence, and references; an associated source table retains independent feed provenance. SHA-256, SHA-1, and MD5 are calculated in one streaming pass and checked locally before YARA/PE analysis. ThreatFox and URLhaus indicators keep kind, source, confidence, timestamps, expiration, and active/stale/expired state; stale and expired indicators do not match. The existing `hashes`, `iocs`, and `ioc_lifecycle` tables are retained and migrated forward. YARA and PE/file metadata contribute to a risk score, which is a heuristic score and not a probability. PE signature presence is reported without validating the Authenticode chain.

The API binds to `127.0.0.1`, uses a random per-run token sent in a request header, checks Host and Origin, requires JSON POST bodies, enforces a 64 KiB body limit and per-IP request limits, and allows only GET/POST. The UI has no CDN and does not place the token in the URL.

Quarantine writes pending metadata before copying, verifies the copied file against the scanned SHA-256, and checks the source again before removal. Restore uses a verified temporary copy and a no-overwrite atomic placement. Startup recovery resolves only unambiguous operations; ambiguous files remain available for manual review. Permanent deletion is explicit and integrity-checked.

ZIP-based inspection limits work to 10,000 members, 256 MiB per member, 512 MiB total expanded bytes, depth 8, 1,000:1 compression ratio, and 180 seconds per archive. Any exceeded limit or read failure marks the scan incomplete. Scan status uses text/status symbols; the UI does not present a heuristic count as a probability of safety.

## Build and checks

Python runtime/build dependencies are pinned in `requirements.txt` and `requirements-build.txt`. The Windows workflow uses Python 3.14, runs both test modules, builds to `dist/release`, and records SHA-256 and build provenance. The mobile workflow pins Flutter 3.44.9 and builds Android/iOS CI artifacts. Current desktop and mobile release artifacts are not production-signed.

Run the desktop regression suite:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_luna test_security
```

Run the synthetic benchmark:

```powershell
.\.venv\Scripts\python.exe benchmarks\run_benchmark.py
```

## Known limitations

- No real XWorm binaries or malware corpus are included; synthetic benchmark scores are not evidence of real-world detection rates.
- Windows-specific process, registry, task, network and Defender integrations are mocked in the local test suite; they still need execution on representative Windows systems.
- Flutter/Android/iOS toolchains are not installed in every developer environment; mobile CI is the verification path until local toolchains are available.
- There is no production signing certificate, iOS provisioning profile, or mobile signing key configured.
- Flutter SDK is pinned in CI, but `mobile/pubspec.lock` is not checked in; compatible Flutter packages can still resolve to newer versions on later builds.
- Desktop scan history stores up to 30 runs and up to 100 finding details per run. Paths are local data; command text from PowerShell history is deliberately not copied into findings.
- Cloud reputation, remote administration, real-time monitoring, enterprise policy, and other P3 ideas from the product specification require separate threat models and are not part of the current implementation.
