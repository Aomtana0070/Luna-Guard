# Indicative Roadmap

These are possible next steps for a future maintainer, not commitments or contracted deliverables.

## Near-term diligence and maintenance

- Add and review a Flutter `pubspec.lock` to improve reproducibility.
- Complete project-wide license and asset ownership review before any redistribution or sale.
- Review bundled YARA rule provenance, licenses, false-positive notes, and independent validation status rule by rule.
- Capture current, sanitized screenshots of the Windows app and mobile companion.
- Run the existing test suite and build workflows from a clean checkout; publish dated verification evidence.
- Re-check release environment protection, signing-secret custody, recovery procedures, and ownership transfer plan.

## Product opportunities

- Add independent security review and broader regression coverage for archive, API, quarantine, and update flows.
- Improve detection quality measurement using a controlled, lawful test corpus and clearly reported false-positive/false-negative methodology.
- Improve mobile dependency locking and clarify platform-specific coverage.
- Improve accessibility, onboarding, scan progress, and explanations for incomplete scans and risk scoring.
- Consider signed Windows builds and a documented key-custody/release process.
- Add operational support and privacy documentation if the project evolves into a commercial service.

Prioritize safety and evidence before broadening product claims. Do not treat this list as evidence that the work has already been implemented.
