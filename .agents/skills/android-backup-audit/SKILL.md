---
name: android-backup-audit
description: "Audit backup exposure in an authorized Android app: allowBackup, fullBackupContent rules, ADB backup extraction on a test device, backup agents, and secrets that reach backup, using manifest audit and gated `android_device.py --backup-approved`."
---

# Android Backup Security

Audit backup exposure in an authorized Android app: allowBackup, fullBackupContent rules, ADB backup extraction on a test device, backup agents, and secrets that reach backup, using manifest audit and gated `android_device.py --backup-approved`.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-backup-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Manifest audit reads allowBackup and fullBackupContent. ADB backup extraction is gated: `android_device.py --active-approved --backup-approved PKG` writes a scratch file under artifacts/, reports its header and encryption flag only, and you delete the file after reporting. Confirm the prompt on the device screen.

## Coverage

- passive: 9
- bounded: 33
- authorized-only: 8
- total: 50
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0427` to `AND-0476`).
