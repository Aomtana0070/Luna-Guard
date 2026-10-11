# YARA rules

`core/` contains first-party heuristic rules. Other directories are reserved for
family-specific rules after sample review and provenance/license checks. The
`community/` directory is intentionally empty: external rules must not be added
without reviewing their license, source, metadata, and false-positive notes.

Rules are recursively loaded from this directory and `%LOCALAPPDATA%/LunaGuard/rules`.
Matches are indicators for investigation, not proof of malicious intent.
