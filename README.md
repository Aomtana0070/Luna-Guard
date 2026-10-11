# Luna Guard

Luna Guard is a Windows desktop helper for scanning and quarantining suspicious files. It is not real-time antivirus software and does not replace Microsoft Defender or another endpoint protection product.

## Features

- Desktop window powered by pywebview; the loopback API validates Host/Origin, uses a per-run header token, limits JSON bodies and request rates, and denies unsupported methods.
- Luna Guard logo is shown in the app and bundled with the Windows executable.
- The Windows executable uses the Luna Guard logo as its multi-size `.ico` app/taskbar icon.
- Scan findings with severity and reasons, plus up to 100 detailed findings per scan in local history.
- One-click, read-only Auto file scan for Downloads, Temp, AppData, and Startup; redundant nested roots are skipped. It also checks supported archives but does not inspect processes/memory, startup persistence, network/DNS, or PowerShell history. Use Quick scan for those additional checks.
- Streaming inspection of supported ZIP-based archives, including macro-enabled Office documents and APKs, with bounded member count, member/expanded bytes, compression ratio, nesting depth, disk use, and scan time. Limit or read errors mark a scan incomplete; a flagged member can quarantine its containing archive.
- Streaming analysis for regular files of any size, plus direct YARA scanning of every enumerated running process's memory (the scanner excludes its own process).
- Crash-aware quarantine with SHA-256 verification, atomic metadata, startup recovery checks, explicit destination conflict handling, and confirmed permanent deletion. HIGH findings are the only findings handled automatically by remediation; review MEDIUM and LOW yourself.
- Microsoft Defender status reporting and buttons to request Defender quick or full scans on Windows.
- Optional YARA scanning with the bundled Luna Guard rules and `yara-python`.
- Thai, English, and Simplified Chinese interface and in-app guide covering archive inspection and Microsoft Defender.
- Threat-data updates add MalwareBazaar recent detections to the local file-hash database, plus ThreatFox and URLhaus indicators (abuse.ch). The local database retains SHA-256/SHA-1/MD5, source provenance and IOC active/stale/expired state. Hashes are matched before YARA/PE analysis; findings include a heuristic risk score, not a probability.
- YARA rules load recursively from `rules/` and the local user-rules directory. PE analysis reports architecture, timestamp, signature presence, section entropy, imports and available version strings; signature authenticity is not validated.

## Run from source

Requires Windows and Python 3.10 or newer. The reproducible build uses Python 3.14.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe luna_app.py
```

To run the test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_luna test_security
```

## Build the Windows executable

With Python 3.14 installed, run `build.bat` from the project directory. Exact desktop/YARA/packaging dependency versions are pinned in `requirements-build.txt`. The executable and SHA-256/build provenance files are written to `dist\release\`; GitHub Actions runs the same tests and attaches build outputs to workflow artifacts and tagged releases.

Windows EXE files are unsigned because this project does not currently use a paid code-signing certificate. Windows may show an unknown publisher or SmartScreen warning; users should download only from this repository's Releases and verify the published SHA-256 checksum. Build provenance marks the Windows artifact as unsigned. Android tagged releases continue to use the persistent Android release keystore and are signed and verified before publication. Keep that keystore backed up securely: future Android updates must use the same signing identity. The already published v1.5.1 assets were not production-signed. Users installing the first APK signed with the persistent release key may need to uninstall an earlier APK first, which removes its local app data.

Before creating a new `v*` release tag, configure the GitHub environment named `production-release`, restrict it to `v*` tags, and require a reviewer. Add these environment secrets for Android signing: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD`. No Windows signing secrets are needed. Never commit signing files or paste private keys/passwords into issues or chat. If the protected environment or a required Android signing secret is missing, or APK signature verification fails, the release workflow stops without publishing assets.

## Mobile app (Android and iOS) — In development (1.5.1+6)


The Flutter source is in [mobile/](./mobile/). It scans only files the user selects, stores history and imported SHA-256 lists on-device, and does not upload file contents. The mobile scanner is a limited offline checker; it does not run the desktop YARA engine, inspect archive members or process memory, or scan other apps' private files.

Android APK builds and unsigned iOS compilation run with the pinned Flutter 3.44.9 toolchain in the Mobile app GitHub Actions workflow. CI attaches SHA-256 checksums and build provenance. Version tags sign and verify the Android APK; the Windows EXE is published unsigned with its checksum and provenance. To build iOS for installation or distribution, use macOS with Xcode and configure Apple signing and provisioning.

## Threat-data sources and privacy

Threat hashes and indicators are downloaded from [MalwareBazaar](https://bazaar.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), and [URLhaus](https://urlhaus.abuse.ch/). YARA rules shipped with the app are maintained in this repository. Update requests contact those services; the app does not upload scanned files or scan history. An abuse.ch Auth-Key is stored under `%LOCALAPPDATA%\LunaGuard` and protected with Windows DPAPI. Older plaintext settings are migrated to DPAPI the next time Luna Guard reads the key. DPAPI protects the key at rest for the current Windows account; software already running as that account can still use it.

Luna Guard scans on demand; Microsoft Defender provides real-time protection when enabled. The focused Auto file scan checks Downloads, Temp, AppData, and Startup without system checks; Quick scan adds process/memory, startup persistence, network/DNS, and PowerShell-history checks. Scan drive C: has no overall file-count or time cap and attempts all accessible directories, including Windows, caches, $Recycle.Bin, and System Volume Information; it automatically uses the Deep archive profile. It does not follow junctions/reparse points, to prevent loops and traversal outside C:, and reports them as incomplete. Deep archive inspection is still bounded: 100,000 members, 1 GiB per member, 8 GiB total expanded data, depth 32, compression ratio 5,000:1, and at least 1 GiB free on the temporary drive. Disk, permission, corrupt-file, encrypted-file, unsupported-compression, skipped reparse point, and budget-limit errors mark the scan incomplete. Windows may deny access to protected files or process memory. A "no threats found" result applies only to the scanned scope and does not guarantee the system is safe or that every malware family was detected. Review findings before taking action and retain Microsoft Defender or another maintained endpoint protection product.
