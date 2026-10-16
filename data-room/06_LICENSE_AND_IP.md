# Licensing, Intellectual Property, and Transfer Scope

## Current known status

- The repository has **no top-level `LICENSE` file** at the reviewed commit. The code is publicly viewable, but the absence of a license does not establish that third parties may freely use, modify, redistribute, or acquire it.
- The repository's bundled YARA rules describe themselves as first-party heuristics, while rule metadata also records unspecified licensing or incomplete independent review where applicable. Provenance and rights should be checked rule by rule.
- Luna Guard name, logo, icon, screenshots, illustrations, website copy, and other artwork need an ownership and third-party-material inventory. This document does not make a legal finding that each item is transferable.
- Python and Flutter packages remain governed by their respective third-party licenses. Feed sources and APIs remain governed by their providers' current terms; access credentials and subscriptions do not automatically transfer.
- GitHub/Vercel accounts, domains, signing identities, and credentials are separate from source-code files and require explicit agreement and provider-compliant transfer steps.

## Suggested transfer schedule

Before closing, prepare a written schedule identifying each item as one of:

1. Owned by the creator and proposed for transfer, subject to proof and written assignment.
2. Third-party material that may be used only under its stated license or terms.
3. Excluded or not yet cleared.

Include source code, rules, visual assets, website code/content, documentation, build workflows, domains/accounts (if any), and signing keys as separate line items. Do not promise transfer of third-party rights, credentials, personal accounts, or data without authority and a secure plan.

## Credentials and sensitive data

The public repository intentionally excludes `.env`, signing key files, user settings, threat databases, scan history, and quarantine contents. Never add those items to this data room. Android release signing depends on custody of a persistent signing identity; arrange any handover through a private, secure channel and agree on a rotation/continuity plan. Do not share secrets in GitHub issues, commits, or this folder.

## Required follow-up

- Add a project license only after the rights holder selects and approves its scope.
- Generate a dependency and asset bill of materials with license and provenance evidence.
- Verify rights to the logo, icon, fonts, illustrations, screenshots, and website content.
- Review current provider terms for MalwareBazaar, ThreatFox, URLhaus, and any optional authenticated service.
- Use written assignment/asset-transfer terms reviewed by qualified legal counsel. If the creator is under 18, involve a parent or guardian and qualified counsel.

This is an operational checklist, not legal advice or a representation that any transfer is already authorized.
