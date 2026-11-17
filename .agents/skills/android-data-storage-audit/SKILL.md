---
name: android-data-storage-audit
description: "Audit how an authorized Android app stores data: SharedPreferences and SQLite plaintext, file permissions, external and cache storage, backups, logcat leakage, content providers and Keystore use, using static rules and `android_device.py --storage` on a test device."
---

# Android Data Storage

Audit how an authorized Android app stores data: SharedPreferences and SQLite plaintext, file permissions, external and cache storage, backups, logcat leakage, content providers and Keystore use, using static rules and `android_device.py --storage` on a test device.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-data-storage-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Static rules flag plaintext storage and world-readable modes. `android_device.py --storage PACKAGE` reads permissions and listing of shared_prefs, databases and cache with `run-as` (debuggable builds) or with `adb shell ls -l` on the test device. Backup extraction needs `--backup-approved`.

## Coverage

- passive: 3
- bounded: 9
- authorized-only: 3
- total: 15
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0072` to `AND-0086`).
