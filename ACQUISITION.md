# Luna Guard — Acquisition

**A Windows security project available for acquisition or a supported handover.**

Luna Guard is an on-demand Windows malware-scanning and quarantine application, with a limited Android/iOS companion checker and a public project website. The project is pre-revenue. Its creator, Tanapisit Onsroi, is looking to pass it to a team that can continue developing it and is willing to help with a transition and technical walkthrough.

**Price:** Open to serious offers. No asking price or valuation is represented here.

## At a glance

- **Latest tagged release:** [v1.6.1](https://github.com/Aomtana0070/Luna-Guard/releases/tag/v1.6.1)
- **Desktop:** Windows scanner, dashboard, YARA rules, threat-feed updates, file analysis, and integrity-checked quarantine.
- **Companion:** Flutter source for Android and iOS; selected-file, local checks with a deliberately smaller scope than desktop.
- **Website:** [Luna Guard](https://luna-guard-website.vercel.app/)
- **Source repository:** [github.com/Aomtana0070/Luna-Guard](https://github.com/Aomtana0070/Luna-Guard)
- **Business status:** Pre-revenue. Revenue, customer, and active-user figures are not claimed. See GitHub for live public repository and release activity; GitHub counters are not a measure of active users or customers.
- **Code license:** No project-wide `LICENSE` file is currently present. Publicly viewable source code should not be interpreted as permission to reuse or transfer every part. License and rights clearance is a diligence item.

## What the project does

The Windows application provides on-demand scans, YARA and hash/IOC checks, file and PE metadata analysis, bounded archive inspection, selected system checks, explainable heuristic risk scores, and a quarantine workflow that verifies SHA-256 before removal or restore. Threat-feed updates use MalwareBazaar, ThreatFox, and URLhaus. Scanned files and scan history are not uploaded to those feeds.

The companion app processes files selected by the user on-device. It does not inspect other apps' private files, scan device memory, extract archive members, or automatically quarantine files.

See the [project overview](data-room/01_PROJECT_OVERVIEW.md), [technical architecture](data-room/02_TECHNICAL_ARCHITECTURE.md), [security review and limitations](data-room/03_SECURITY_REVIEW.md), and [feature inventory](data-room/04_FEATURES.md) for detail.

## Potential handover scope

The exact assets and rights included in a transaction must be agreed and verified. The repository contains desktop and mobile source, documentation, build and release workflows, application assets, and project website material. Third-party libraries, threat feeds, and any assets or rules without confirmed transferable rights are subject to their own terms and are not represented as automatically transferable.

No signing key, API key, `.env` file, personal data, local scan history, quarantine contents, or other secrets are part of this public data room. Transfer of any signing identity or account requires a separate secure process and explicit agreement. The Android release key is especially sensitive because future Android updates depend on the same signing identity.

## Transition support

The creator is willing to provide a technical walkthrough and handover guidance. Scope, schedule, and duration can be agreed with the acquiring team. The project is not represented as a staffed, plug-and-play business; there is no claimed revenue, customer base, or service-level commitment.

## Important limitations

Luna Guard is an on-demand scanner, not real-time antivirus and not a replacement for Microsoft Defender or another maintained endpoint-protection product. Detection scores are heuristic evidence summaries, not calibrated probabilities. A clean result applies only to the components the scan could inspect and is not a guarantee that a device is safe. See [SECURITY.md](SECURITY.md) for scan coverage, archive limits, data handling, release signing, and known limitations.

The Windows executable is unsigned and may trigger an unknown-publisher or SmartScreen warning. Android tagged releases are signed through a protected release workflow; the signing identity is not included in the repository. iOS distribution needs Apple signing and provisioning.

## Diligence materials

The [free Data Room](data-room/README.md) provides project, technical, security, licensing, dependency, build, testing, and roadmap notes. The testing document describes how to run the existing checks; it does not claim a new independent audit or a test run for this offer. Product screenshots should be captured from a real current build before being used in a listing.

## Contact

For an acquisition conversation, contact the maintainer through the [GitHub profile](https://github.com/Aomtana0070) or repository. Share sensitive diligence information only through a mutually agreed private channel. Do not send secrets, signing material, or user data in public issues.

Any transaction is subject to diligence, rights verification, mutually agreed written terms, and appropriate legal review. If the creator is under 18, involve a parent or guardian and qualified legal counsel before signing or transferring rights.
