---
name: ios-notification-audit
description: "Audit notifications in an authorized iOS app: lock-screen and preview content, notification service and content extensions, action authentication options, critical alert and communication entitlements, silent pushes, attachments and device-token handling, using `ios_static.py`, `frida/notification_trace.js`, and lock-screen review on a test device."
---

# iOS Notification Security

Audit notifications in an authorized iOS app: lock-screen and preview content, notification service and content extensions, action authentication options, critical alert and communication entitlements, silent pushes, attachments and device-token handling, using `ios_static.py`, `frida/notification_trace.js`, and lock-screen review on a test device.

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

`ios_static.py` reads aps-environment, critical-alert and communication entitlements, notification extensions, and UNNotification symbols. `frida/notification_trace.js` logs categories and their action options (authenticationRequired, destructive, foreground), and incoming payload keys (values redacted). Review the lock screen with the device locked and previews set to Always.

## Coverage

- passive: 8
- bounded: 29
- authorized-only: 10
- not-tested: 3
- total: 50
- sections: Notification Security (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0226` to `IOS-0275`).
