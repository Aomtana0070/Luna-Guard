# Luna Guard

Luna Guard is a Windows desktop helper for scanning and quarantining suspicious files. It is not real-time antivirus software and does not replace Microsoft Defender or another endpoint protection product.

## Features

- Desktop window powered by pywebview; the local API binds only to `127.0.0.1` and checks a per-run token and Host header.
- Scan findings with severity and reasons, plus up to 100 detailed findings per scan in local history.
- Reversible quarantine; HIGH findings are the only findings handled automatically by remediation. Review MEDIUM and LOW findings yourself.
- Optional YARA scanning with the bundled Luna Guard rules and `yara-python`.
- Thai, English, and Simplified Chinese interface and in-app guide.
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

## Threat-data sources and privacy

Threat hashes and indicators are downloaded from [MalwareBazaar](https://bazaar.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/), and [URLhaus](https://urlhaus.abuse.ch/). YARA rules shipped with the app are maintained in this repository. Update requests contact those services; the app does not upload scanned files or scan history. An abuse.ch Auth-Key, if configured, is stored locally under `%LOCALAPPDATA%\LunaGuard`.

Downloaded threat intelligence and detection rules can change over time. Neither a clean scan nor a successful update guarantees that a system is safe or that all malware will be detected. Review findings before taking action and retain Microsoft Defender or another maintained endpoint protection product.
