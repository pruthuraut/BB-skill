---
name: android-enterprise-audit
description: "Audit work-profile isolation and enterprise behaviour in an authorized Android app: cross-profile data, clipboard, notifications, sharing, MDM and managed configuration, using manifest and static review. Device-platform bypass items are recorded as not tested."
---

# Android Work Profile and Enterprise

Audit work-profile isolation and enterprise behaviour in an authorized Android app: cross-profile data, clipboard, notifications, sharing, MDM and managed configuration, using manifest and static review. Device-platform bypass items are recorded as not tested.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-enterprise-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Most work-profile items need a managed device and an MDM. Record items you cannot set up as not tested rather than marking them passed. Device-platform bypass items are not tested by this skill.

## Coverage

- passive: 9
- bounded: 59
- authorized-only: 69
- not-tested: 8
- total: 145
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0577` to `AND-0721`).
