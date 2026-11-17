---
name: android-ipc-intent-audit
description: "Test Android inter-process communication for an authorized app: exported components, intent injection and redirection, PendingIntent misuse, broadcast abuse, content provider injection and traversal, task hijacking and service binding, using manifest audit plus gated adb and Drozer checks on a test device."
---

# Android IPC and Intents

Test Android inter-process communication for an authorized app: exported components, intent injection and redirection, PendingIntent misuse, broadcast abuse, content provider injection and traversal, task hijacking and service binding, using manifest audit plus gated adb and Drozer checks on a test device.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-ipc-intent-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Manifest audit lists every exported component and its intent filters. `android_device.py --intents PACKAGE` lists exported components on the device; `--active-approved` allows one explicit `am start` per activity. Drozer commands are printed, not run.

## Coverage

- passive: 2
- bounded: 8
- authorized-only: 20
- total: 30
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0132` to `AND-0161`).
