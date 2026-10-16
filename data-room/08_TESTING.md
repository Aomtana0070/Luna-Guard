# Tests and Verification Guidance

The repository contains `test_luna.py`, `test_security.py`, and a Flutter test at `mobile/test/scanner_test.dart`. CI workflow definitions are in `.github/workflows/`. This document does not claim that tests were run for this acquisition brief, and passing tests would not demonstrate real-world malware detection efficacy.

## Windows desktop tests

From the repository root, using Python 3.14 and the pinned build environment:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m unittest -v test_luna test_security
```

## Mobile tests

Install the Flutter version used by CI (3.44.9), then from `mobile/` run:

```powershell
flutter pub get
flutter test
```

Because a `pubspec.lock` is not present, `flutter pub get` may resolve newer versions allowed by the constraints. Record the exact Flutter and package versions used when producing diligence results.

## Benchmark

The repository documents `python benchmarks/run_benchmark.py` as a deterministic synthetic smoke set. Its fixtures are not representative of live malware and its output must not be presented as a detection-rate claim.

## Recommended acquisition verification

- Start from a clean clone and verify the tag/commit being reviewed.
- Run unit tests and platform builds in isolated environments.
- Review archive limits, API validation, quarantine integrity/recovery, and release signing workflows.
- Capture command, tool versions, commit hash, timestamp, and output for each verification run.
- Use only lawful, isolated samples and test corpora; do not test malware on a production machine.
