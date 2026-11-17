---
name: android-dynamic-audit
description: "Test a running Android app on a test device you own: Frida and Objection hooking, Burp interception, Drozer component testing, adb intent checks, file permissions, clipboard, screenshots and keyboard cache, using `android_device.py` and the bundled Frida scripts. Active checks need written approval."
---

# Android Dynamic Analysis

Test a running Android app on a test device you own: Frida and Objection hooking, Burp interception, Drozer component testing, adb intent checks, file permissions, clipboard, screenshots and keyboard cache, using `android_device.py` and the bundled Frida scripts. Active checks need written approval.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-dynamic-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Needs a rooted or emulator test device, Frida server, and `frida`/`objection` on the workstation. Bundled hooks live in `scripts/frida/`: `ssl_pinning_bypass.js`, `root_bypass.js`, `emulator_bypass.js`, `debug_check.js`. Run one hook at a time against your own build. `android_device.py --print-drozer PACKAGE` prints Drozer commands for the in-scope package. Nothing here is run automatically.

## Coverage

- passive: 3
- bounded: 4
- authorized-only: 23
- total: 30
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0042` to `AND-0071`).
