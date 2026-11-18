---
name: ios-forensic-audit
description: "Review data residue left by an authorized iOS app on the owner's own test device: after logout, data clearing, uninstall and reinstall, in the container, keychain, backups, caches, logs, crash and MetricKit reports, using `ios_container_audit.py --diff` and marker search. System and other apps' data (Safari, Photos, Messages) is recorded as not tested."
---

# iOS Data Residue and Recovery

Review data residue left by an authorized iOS app on the owner's own test device: after logout, data clearing, uninstall and reinstall, in the container, keychain, backups, caches, logs, crash and MetricKit reports, using `ios_container_audit.py --diff` and marker search. System and other apps' data (Safari, Photos, Messages) is recorded as not tested.

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

Run on your own test device only. Snapshot the container before and after the action (`ios_device.py --pull-container`), then `ios_container_audit.py --diff BEFORE AFTER --marker M`. For uninstall rows, reinstall and check whether keychain items survive (`frida/keychain_dump.js`). System-wide stores and other apps' data are not tested.

## Coverage

- bounded: 51
- not-tested: 39
- total: 90
- sections: iOS Data Recovery (90)

Checklist rows: `references/checklist.md` (IDs `IOS-0866` to `IOS-0955`).
