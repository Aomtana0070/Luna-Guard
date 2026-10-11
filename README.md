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

The executable is not signed. Windows SmartScreen may show an unfamiliar-app warning.

## Mobile app (Android and iOS) — In development (1.5.0+5)


The Flutter source is in [mobile/](./mobile/). It scans only files the user selects, stores history and imported SHA-256 lists on-device, and does not upload file contents. The mobile scanner is a limited offline checker; it does not run the desktop YARA engine, inspect archive members or process memory, or scan other apps' private files.

Android APK builds and unsigned iOS compilation run with the pinned Flutter 3.44.9 toolchain in the Mobile app GitHub Actions workflow. CI attaches SHA-256 checksums and build provenance. Version tags build and publish the Android APK and Windows executable together as GitHub Release assets; the current APK is not production-signed. To build iOS for installation or distribution, use macOS with Xcode and configure Apple signing and provisioning.

## Threat-data sources and privacy

Threat hashes and indicators are downloaded from [MalwareBazaar](https://bazaar.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), and [URLhaus](https://urlhaus.abuse.ch/). YARA rules shipped with the app are maintained in this repository. Update requests contact those services; the app does not upload scanned files or scan history. An abuse.ch Auth-Key, if configured, is stored locally under `%LOCALAPPDATA%\LunaGuard`.

Luna Guard scans on demand; Microsoft Defender provides real-time protection when enabled. The focused Auto file scan checks Downloads, Temp, AppData, and Startup without system checks; Quick scan adds process/memory, startup persistence, network/DNS, and PowerShell-history checks. Regular files are streamed. Archive inspection is bounded to 10,000 members, 256 MiB per member, 512 MiB expanded data, nesting depth 8, compression ratio 1,000:1, and 180 seconds per archive. ZIP metadata may still consume memory up to the member-count cap. Disk, permission, corrupt-file, encrypted-file, unsupported-compression, and budget-limit errors mark the scan incomplete. Windows may deny access to protected process memory; the app reports such scans as incomplete. A "no threats found" result applies only to the scanned scope and does not guarantee the system is safe or that every malware family was detected. Review findings before taking action and retain Microsoft Defender or another maintained endpoint protection product.
