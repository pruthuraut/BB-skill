---
name: android-firebase-audit
description: "Audit Firebase and cloud backends used by an authorized Android app: Realtime Database and Firestore rules, Storage access, Remote Config, Cloud Functions, google-services.json exposure and App Check, using `firebase_probe.py` read-only checks scoped to the program's listed project."
---

# Android Firebase and Cloud

Audit Firebase and cloud backends used by an authorized Android app: Realtime Database and Firestore rules, Storage access, Remote Config, Cloud Functions, google-services.json exposure and App Check, using `firebase_probe.py` read-only checks scoped to the program's listed project.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-firebase-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

`firebase_probe.py` reads `google-services.json` and tests only read access to the Realtime Database, Firestore, Storage and Remote Config endpoints for the project id listed in your scope file. Writes are never attempted. A Maps key check sends one request per API.

## Coverage

- passive: 1
- bounded: 10
- authorized-only: 4
- total: 15
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0262` to `AND-0276`).
