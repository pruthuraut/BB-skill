---
name: ios-sandbox-audit
description: "Audit how an authorized iOS app uses its sandbox: container isolation, files outside the container, app group and iCloud containers, security-scoped bookmarks, path sanitization and symlinks, pasteboard and share-sheet exits. Kernel and platform sandbox escapes are recorded as not tested; no exploit work is done."
---

# iOS Sandbox Boundaries

Audit how an authorized iOS app uses its sandbox: container isolation, files outside the container, app group and iCloud containers, security-scoped bookmarks, path sanitization and symlinks, pasteboard and share-sheet exits. Kernel and platform sandbox escapes are recorded as not tested; no exploit work is done.

This skill is generated from the iOS checklist source (`.agents/skills/ios-app-audit/references/source/`). Edit the source and rerun `scripts/build_ios_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device and test accounts you own.
2. `passive` rows read the IPA only. `bounded` rows read from the test device, its backup, or in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are OS or platform behaviour. They are recorded, not tested.
4. Save evidence to `artifacts/<bundle>/`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the bundle: `python3 -I .agents/skills/ios-app-audit/scripts/ios_static.py --ipa APP.ipa --out artifacts/<bundle>/ios-static.json`.
2. Start tracking: `python3 -I .agents/skills/ios-app-audit/scripts/ios_checklist.py init --bundle <bundle>`, then `ingest` each report.
3. Work this skill's checklist: `references/checklist.md`. The Tool column names the script or hook for each row.
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand, then `ios_checklist.py set IOS-xxxx failed --note ...`.

## Notes

Container isolation is checked from the pulled container and `frida/file_protection.js` (paths outside the container are flagged). App groups and iCloud containers come from entitlements. Sandbox escape rows that need kernel, XPC or IOKit exploitation are not tested.

## Coverage

- passive: 8
- bounded: 28
- authorized-only: 5
- not-tested: 9
- total: 50
- sections: Sandbox Deep (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0276` to `IOS-0325`).
