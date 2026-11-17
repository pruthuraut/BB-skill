---
name: android-logging-audit
description: "Audit logging in an authorized Android app: sensitive data in Log calls, release log stripping, logcat exposure, crash reports, HTTP header and token logging, using static logging rules and gated on-device logcat review."
---

# Android Logging

Audit logging in an authorized Android app: sensitive data in Log calls, release log stripping, logcat exposure, crash reports, HTTP header and token logging, using static logging rules and gated on-device logcat review.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-logging-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Static logging rules match Log.* and println calls against sensitive names (token, password, card, session). Release log stripping is checked in proguard-rules and the build.gradle release block. On-device logcat is read with `android_device.py --logcat PACKAGE`.

## Coverage

- passive: 7
- bounded: 37
- authorized-only: 6
- total: 50
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0477` to `AND-0526`).
