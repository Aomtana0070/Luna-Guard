# Feature Inventory

This inventory describes features in the repository documentation; verify behavior against a specific checkout and test environment.

## Windows desktop

- **Scan modes:** focused Auto scan of Downloads, Temp, AppData, and Startup; Quick scan adds process/memory, startup persistence, network/DNS, and PowerShell-history checks; C: scan attempts accessible paths on the selected drive.
- **File analysis:** streaming analysis, SHA-256/SHA-1/MD5, file type and size, selected PE architecture/timestamp/signature-presence/section-entropy/import/version metadata.
- **Detection:** optional YARA scanning; bundled rules; hash/IOC reputation; selected behavioral/system heuristics; signal correlation with an explained capped risk score.
- **Threat intelligence:** MalwareBazaar recent hashes, ThreatFox, and URLhaus; local indicator source/confidence/seen/expiry lifecycle metadata.
- **Archives:** bounded inspection of supported ZIP-based formats, including Office macro formats and APKs; errors and resource limits can make a scan incomplete.
- **Quarantine:** HIGH findings alone are handled automatically by remediation policy; MEDIUM and LOW remain for user review. Hash verification, recovery, restore-conflict handling, and confirmed deletion are documented.
- **Defender integration:** report Microsoft Defender status and request quick or full scans on Windows.
- **Interface:** pywebview dashboard, Thai/English/Simplified Chinese UI, local scan history, finding filters, and an in-app guide.

## Mobile companion

- User-selected files and Android directories accessible through the system picker.
- Local SHA-256 and optional imported hash-list comparison.
- Small offline XWorm and suspicious PowerShell string heuristics.
- On-device summaries/history; no automatic deletion or quarantine.
- No process-memory inspection, archive extraction, desktop YARA engine, or access to other apps' private files.

## Website and project material

The project also has a public website, documentation, release links, and branding/artwork. Ownership and rights are not presumed clear; see [Licensing and IP](06_LICENSE_AND_IP.md).

## Not claimed

No real-time protection, guaranteed detection, independently validated detection rate, calibrated probability, paid customer base, revenue, or active-user total is claimed.
