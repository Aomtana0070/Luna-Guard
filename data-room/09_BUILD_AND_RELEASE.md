# Build and Release

## Windows desktop build

The documented build requires Windows and Python 3.14. From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.
build.bat
```

The batch file installs pinned build dependencies, invokes PyInstaller, and writes the executable and provenance/checksum material under `dist\release\`. Review the exact checked-in `build.bat` and workflow before running it.

The Windows executable is unsigned. A checksum can detect a mismatch against the published checksum; it does not prove publisher identity or that a program is harmless.

## Mobile build

Mobile source is in `mobile/`. The repository documentation describes Flutter builds for Android and no-code-sign iOS compilation on macOS with Xcode. The tagged Android release workflow requires configured signing secrets and verifies the APK. iOS distribution requires Apple signing/provisioning. See `mobile/README.md` and `.github/workflows/mobile.yml`.

## Release and secret custody

Release workflows depend on repository/environment configuration outside the source tree. Before a future release, verify environment protection, required reviewers, tag restrictions, and secret access. Do not copy signing credentials into the repository or this data room. Any signing-key transfer must be separately authorized and handled securely.

## Reproducibility caveats

Python desktop dependencies are pinned in the checked-in requirements files. Flutter is pinned in CI, but the absence of `mobile/pubspec.lock` means full Dart dependency resolution is not locked. Build output can also vary with operating system and toolchain. Record tool versions, commit, and artifact checksums for each build reviewed.
