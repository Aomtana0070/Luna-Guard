# Luna Guard

Luna Guard is a Windows desktop helper for scanning and quarantining suspicious files. It is not real-time antivirus software and does not replace Microsoft Defender or another endpoint protection product.

## Features

- Desktop window powered by pywebview; the local API binds only to `127.0.0.1` and checks a per-run token and Host header.
- Luna Guard logo is shown in the app and bundled with the Windows executable.
- The Windows executable uses the Luna Guard logo as its multi-size `.ico` app/taskbar icon.
- Scan findings with severity and reasons, plus up to 100 detailed findings per scan in local history.
- Streaming inspection of supported ZIP-based archives, including macro-enabled Office documents and APKs, without fixed member-count, expanded-size, or nesting-depth caps; a flagged member can quarantine its containing archive.
- Streaming analysis for regular files of any size, plus direct YARA scanning of every enumerated running process's memory (the scanner excludes its own process).
- Reversible quarantine; HIGH findings are the only findings handled automatically by remediation. Review MEDIUM and LOW findings yourself.
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

## Mobile app (Android and iOS)

The Flutter source is in [mobile/](./mobile/). It scans only files the user selects, stores history and imported SHA-256 lists on-device, and does not upload file contents. The mobile scanner is a limited offline checker; it does not run the desktop YARA engine, inspect archive members or process memory, or scan other apps' private files.

Android APK builds and unsigned iOS compilation run in the Mobile app GitHub Actions workflow. To build iOS for installation or distribution, use macOS with Xcode and configure Apple signing and provisioning.

## Threat-data sources and privacy

Threat hashes and indicators are downloaded from [MalwareBazaar](https://bazaar.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), and [URLhaus](https://urlhaus.abuse.ch/). YARA rules shipped with the app are maintained in this repository. Update requests contact those services; the app does not upload scanned files or scan history. An abuse.ch Auth-Key, if configured, is stored locally under `%LOCALAPPDATA%\LunaGuard`.

Luna Guard scans on demand; Microsoft Defender provides real-time protection when enabled. Regular files and supported archive members are analyzed in chunks, without fixed file-size, archive-member-count, expanded-data, or nesting-depth caps. Archive members are streamed through temporary files to bound expanded-content RAM use. Disk use and scan time can grow with archive contents, and ZIP central-directory metadata still consumes memory proportional to the number of members; disk, permission, corrupt-file, encrypted-file, or unsupported-compression errors mark the scan incomplete. Windows may deny access to protected process memory; the app reports such scans as incomplete. A "no threats found" result applies only to the scanned scope and does not guarantee the system is safe or that every malware family was detected. Review findings before taking action and retain Microsoft Defender or another maintained endpoint protection product.
