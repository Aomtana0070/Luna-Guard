# Security Review and Known Limitations

## Scope of this document

This is a repository-based self-review summary, not an independent penetration test, malware-efficacy evaluation, or certification. The project-maintained [SECURITY.md](../SECURITY.md) is the primary source for implementation details and should be read alongside the code.

## Documented safeguards

- Loopback desktop API with per-run token, Host/Origin validation, method restrictions, bounded JSON request bodies, rate limits, and worker limits.
- Local threat-feed data; scanned files and scan history are not sent to the feed providers.
- Optional abuse.ch Auth-Key protected at rest with Windows DPAPI for the current account; software already running as that account may still use it.
- Quarantine and restore verify SHA-256, handle interrupted operations, reject conflicting destinations, and require confirmation for permanent deletion.
- Archive scanning applies member, expanded-size, ratio, nesting, disk-space, and time/resource limits. Errors or skipped content should produce an incomplete result.
- CI workflows pin GitHub Actions by full commit SHA; Dependabot checks are configured.

## Material limitations and diligence items

- On-demand scanner only; it is not real-time protection and does not replace Microsoft Defender or another maintained endpoint-protection product.
- A clean result covers only accessible items and the selected scan scope. Permission failures, unsupported formats, and resource limits can leave content uninspected.
- The full C: scan has no overall file-count or time cap. Deep archive inspection has large but finite per-archive limits and may use substantial disk, memory, or time.
- PE signature reporting checks metadata presence; it does not validate the authenticity of a digital signature. Version strings can be forged.
- Risk scores are heuristic summaries, not calibrated probabilities. YARA rule matches can be false positives and rules have not been independently reviewed as a complete set.
- The Windows executable is unsigned. Users may see an unknown publisher or SmartScreen warning.
- Mobile scanning has a deliberately limited scope and is not equivalent to desktop detection.
- Flutter dependency resolution is not fully reproducible until a `pubspec.lock` is added and reviewed.
- Repository settings such as required reviewers, branch protection, and protected release environments require configuration outside workflow YAML; verify these settings during diligence.

## Evidence and next review

Review `SECURITY.md`, `test_security.py`, `test_luna.py`, `luna_quarantine.py`, the loopback API implementation, and `.github/workflows/`. Run the tests from a clean environment as part of diligence. No new test run or independent audit is claimed by this document.

Report suspected vulnerabilities using the repository's GitHub security reporting channel when enabled, or contact the maintainer privately before publishing exploit details. Never place keys, malware samples, personal data, or signing credentials in public issues.
