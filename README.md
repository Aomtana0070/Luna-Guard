# Luna Guard

Luna Guard is a Windows desktop helper for scanning and quarantining suspicious files. It is not real-time antivirus software and does not replace Microsoft Defender or another endpoint protection product.

## Features

- Desktop window powered by pywebview; the local API binds only to `127.0.0.1` and checks a per-run token and Host header.
- Luna Guard logo is shown in the app and bundled with the Windows executable.
- The Windows executable uses the Luna Guard logo as its multi-size `.ico` app/taskbar icon.
- Scan findings with severity and reasons, plus up to 100 detailed findings per scan in local history.
- One-click, read-only Auto file scan for Downloads, Temp, AppData, and Startup; redundant nested roots are skipped. It also checks supported archives but does not inspect processes/memory, startup persistence, network/DNS, or PowerShell history. Use Quick scan for those additional checks.
- Streaming inspection of supported ZIP-based archives, including macro-enabled Office documents and APKs, with resource limits; a flagged member can quarantine its containing archive.
- Streaming analysis for regular files of any size, plus direct YARA scanning of every enumerated running process's memory (the scanner excludes its own process).
- Reversible quarantine; HIGH findings are the only findings handled automatically by remediation. Review MEDIUM and LOW findings yourself.
- Quarantine copies and verifies a file before removing the source; Restore verifies SHA-256, validates the destination, and refuses to overwrite an existing file.
- Microsoft Defender status reporting and buttons to request Defender quick or full scans on Windows.
- Optional YARA scanning with the bundled Luna Guard rules and `yara-python`.
- Thai, English, and Simplified Chinese interface and in-app guide covering archive inspection and Microsoft Defender.
- Threat-data updates from MalwareBazaar, ThreatFox, and URLhaus (abuse.ch). Feed availability and API limits are controlled by their providers.

## Run from source

Requires Windows and Python 3.10 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install pywebview yara-python
.\.venv\Scripts\python.exe luna_app.py
```

To run the test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_luna
```

## Build the Windows executable

With Python installed, run `build.bat` from the project directory. It installs the desktop/YARA/packaging dependencies and writes `dist\LunaGuard.exe`. GitHub Actions also builds a Windows executable and attaches it to tagged GitHub releases.

The executable is not signed. Windows SmartScreen may show an unfamiliar-app warning.

## Mobile app (Android and iOS) — v1.4.3


The Flutter source is in [mobile/](./mobile/). On Android, the user can select a folder through the system picker and rescan files and subfolders within that granted scope. On iOS, the user selects files. The app stores history and imported SHA-256 lists on-device and does not upload file contents. The mobile scanner is a limited offline checker; it does not run the desktop YARA engine, inspect archive members or process memory, or scan other apps' private files.

Android APK builds and unsigned iOS compilation run in the Mobile app GitHub Actions workflow. Version tags build and publish the Android APK and Windows executable together as GitHub Release assets. To build iOS for installation or distribution, use macOS with Xcode and configure Apple signing and provisioning.

## Threat-data sources and privacy

Threat hashes and indicators are downloaded from [MalwareBazaar](https://bazaar.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), and [URLhaus](https://urlhaus.abuse.ch/). YARA rules shipped with the app are maintained in this repository. Update requests contact those services; the app does not upload scanned files or scan history. An abuse.ch Auth-Key, if configured, is stored locally under `%LOCALAPPDATA%\LunaGuard`.

Luna Guard scans on demand; Microsoft Defender provides real-time protection when enabled. The focused Auto file scan checks Downloads, Temp, AppData, and Startup without system checks; Quick scan adds process/memory, startup persistence, network/DNS, and PowerShell-history checks. Regular files and supported archive members are analyzed in chunks. Desktop archive scanning is bounded to 10,000 entries across the archive tree, 256 MiB per member, 512 MiB total expanded data, 8 nested levels, and 180 seconds per top-level archive. Expanded member data uses temporary files; the total expanded-data budget also bounds temporary disk use. If a limit is reached, the affected content is skipped or scanning stops and the scan is marked incomplete, never clean. ZIP central-directory metadata still consumes memory proportional to the number of entries listed in an archive. Disk, permission, corrupt-file, encrypted-file, unsupported-compression, and resource-limit errors mark the scan incomplete. Windows may deny access to protected process memory; the app reports such scans as incomplete. A "no threats found" result applies only to the scanned scope and does not guarantee the system is safe or that every malware family was detected. Review findings before taking action and retain Microsoft Defender or another maintained endpoint protection product.

## Security product specification

The development direction, security requirements, UX guidance, release checklist, and roadmap are documented in [docs/SECURITY_PRODUCT_SPEC.md](./docs/SECURITY_PRODUCT_SPEC.md). It is a development specification, not a security certification or a claim that every recommendation is already implemented.
