# Luna Guard Mobile

Flutter source for the Android and iOS companion file checker.

## Build

Install Flutter 3.41 or newer and the platform tools. From the repository root:

```powershell
flutter create --platforms=android,ios --org com.lunaguard --project-name luna_guard_mobile mobile\platform_scaffold
Copy-Item mobile\platform_scaffold\android mobile\android -Recurse
Copy-Item mobile\platform_scaffold\ios mobile\ios -Recurse
Remove-Item mobile\platform_scaffold -Recurse -Force
Set-Location mobile
flutter pub get
flutter build apk --release
```

For iOS, run `flutter build ios --release --no-codesign` from the `mobile` directory on macOS with Xcode. An installable or App Store-distributable iOS build additionally needs Apple signing credentials and provisioning.

The GitHub Actions workflow builds and tests the Android APK on Linux and compiles the unsigned iOS app on macOS. Its generated native platform projects are intentionally ignored; the shared Flutter source and platform configuration are kept here.

## Scope and privacy

- Scans only files explicitly selected in the native file picker. File bytes are processed locally in chunks and are not uploaded.
- Computes SHA-256 and compares against an optional local text list imported by the user. Imported hashes are kept in device preferences.
- Applies a small offline set of XWorm and suspicious PowerShell string heuristics. This is not the desktop YARA engine and is not a replacement for mobile platform protections.
- Archive containers are marked incomplete; archive contents are not inspected.
- Stores scan summaries locally. Does not scan device memory, other apps' private files, or the entire phone. Does not automatically delete or quarantine files.
- A clean result means no bundled pattern matched; it is not proof that a file or device is safe.
