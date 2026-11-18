---
name: ios-privacy-permission-audit
description: "Audit privacy permissions in an authorized iOS app: usage descriptions for camera, microphone, location, contacts, photos, calendars, reminders, HealthKit, HomeKit, motion, Bluetooth, local network, tracking (ATT) and Focus, matched against entitlements, imported frameworks and prompt timing, using `ios_static.py` and a test device."
---

# iOS Privacy and Permissions

Audit privacy permissions in an authorized iOS app: usage descriptions for camera, microphone, location, contacts, photos, calendars, reminders, HealthKit, HomeKit, motion, Bluetooth, local network, tracking (ATT) and Focus, matched against entitlements, imported frameworks and prompt timing, using `ios_static.py` and a test device.

This skill is generated from the iOS checklist source (`.agents/skills/ios-app-audit/references/source/`). Edit the source and rerun `scripts/build_ios_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device and test accounts you own.
2. `passive` rows read the IPA only. `bounded` rows read from the test device, its backup, or in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are OS or platform behaviour. They are recorded, not tested.
4. Save evidence to `artifacts/<bundle>/`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the bundle: `python3 -I .agents/skills/ios-app-audit/scripts/ios_static.py --ipa APP.ipa --out artifacts/<bundle>/ios-static.json`.
2. Start tracking: `python3 -I .agents/skills/ios-app-audit/scripts/ios_checklist.py init --bundle <bundle>`, then `ingest` each report.
3. Work this skill's checklist: `references/checklist.md`. The Tool column names the script or hook for each row.
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand, then `ios_checklist.py set IOS-xxxx failed --note ...`.

## Notes

`ios_static.py` lists every NS*UsageDescription, flags empty or vague text, and compares them with entitlements (HealthKit, HomeKit, Siri, NFC) and imported frameworks. Check on the test device when each prompt appears and what the app does after a denial.

## Coverage

- bounded: 15
- total: 15
- sections: iOS Privacy & Permissions (15)

Checklist rows: `references/checklist.md` (IDs `IOS-0121` to `IOS-0135`).
