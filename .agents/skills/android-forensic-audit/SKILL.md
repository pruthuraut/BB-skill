---
name: android-forensic-audit
description: "Review data residue left by an authorized Android app on the owner's own test device: after uninstall, cache clearing, deletion, backup and log files, WebView storage and thumbnails. Only the app's own data is examined and only on test devices you own."
---

# Android Forensic Residue

Review data residue left by an authorized Android app on the owner's own test device: after uninstall, cache clearing, deletion, backup and log files, WebView storage and thumbnails. Only the app's own data is examined and only on test devices you own.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-forensic-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Run on your own test device only. `android_device.py --residue PACKAGE` lists the app's data directories and file sizes after uninstall or clearing, and reports residue locations. It never collects other apps' data.

## Coverage

- authorized-only: 91
- not-tested: 1
- total: 92
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0920` to `AND-1011`).
