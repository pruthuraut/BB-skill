---
name: android-component-audit
description: "Audit Android components in an authorized app: exported activities, services, receivers and providers, permission enforcement, caller identity checks, provider query and path handling, task affinity and launch modes, using the manifest audit and static code checks."
---

# Android Components

Audit Android components in an authorized app: exported activities, services, receivers and providers, permission enforcement, caller identity checks, provider query and path handling, task affinity and launch modes, using the manifest audit and static code checks.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-component-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Manifest audit lists component exports, permissions and launch modes. Static rules check ContentProvider query and openFile code.

## Coverage

- passive: 12
- bounded: 23
- authorized-only: 15
- total: 50
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0527` to `AND-0576`).
