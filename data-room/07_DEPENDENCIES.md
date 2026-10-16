# Dependency Inventory and Review Notes

This is a manifest-level inventory, not a complete software bill of materials or license clearance. Versions below come from the checked-in manifests at the documented repository state. Confirm the exact release commit before relying on them.

## Desktop Python

`requirements.txt`:

| Package | Pinned version |
| --- | ---: |
| `pywebview` | 6.2.1 |
| `yara-python` | 4.5.4 |
| `pefile` | 2024.8.26 |

`requirements-build.txt` additionally pins packaging/runtime dependencies including `altgraph`, `bottle`, `cffi`, `clr_loader`, `packaging`, `proxy_tools`, `pycparser`, `pyinstaller`, `pyinstaller-hooks-contrib`, `pythonnet`, `pywin32-ctypes`, `setuptools`, and `typing_extensions`. See that file for exact versions.

## Flutter/Dart

`mobile/pubspec.yaml` declares `crypto`, `file_picker`, `saf`, `shared_preferences`, Flutter SDK, and `flutter_test`. Version constraints are present, but `mobile/pubspec.lock` is not checked in; resolved transitive package versions may change. CI pins Flutter 3.44.9.

## License review status

Package names and versions alone do not establish license compatibility. Before transfer or commercial redistribution, generate an SBOM from a clean, locked dependency resolution, identify direct and transitive licenses, review notices/attributions, and record any copyleft, source-offer, trademark, or redistribution obligations. This data room does not claim that dependency license review is complete.

## Other external inputs

- Threat data: MalwareBazaar, ThreatFox, and URLhaus, subject to provider terms and service availability.
- Build tools: Python 3.14 for the documented Windows build; Flutter 3.44.9 in CI; Windows SDK/packaging tooling; Android SDK; macOS/Xcode for iOS builds.
- Bundled YARA rules and logos/assets require separate provenance and rights review; see [Licensing and IP](06_LICENSE_AND_IP.md).
