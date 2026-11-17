---
name: android-accessibility-audit
description: "Check an authorized Android app's defences against accessibility-service abuse: FLAG_SECURE on sensitive screens, password and card field flags, overlay and tapjacking protection, and secure-view handling. The skill does not build or run accessibility abuse tooling."
---

# Android Accessibility Defences

Check an authorized Android app's defences against accessibility-service abuse: FLAG_SECURE on sensitive screens, password and card field flags, overlay and tapjacking protection, and secure-view handling. The skill does not build or run accessibility abuse tooling.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-accessibility-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

This skill covers defences only. Static rules check FLAG_SECURE, password and card input types, filterTouchesWhenObscured, and accessibility declarations. Do not build or run accessibility abuse tooling; the authorized-only rows describe what the defence must withstand.

## Coverage

- bounded: 4
- authorized-only: 92
- not-tested: 2
- total: 98
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0822` to `AND-0919`).
