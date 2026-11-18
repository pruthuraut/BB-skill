---
name: ios-data-storage-audit
description: "Audit how an authorized iOS app stores data: keychain, UserDefaults, plists, SQLite and CoreData, caches, tmp, snapshots, cookies, backups and iCloud, file protection classes and POSIX permissions, using `ios_container_audit.py` on a pulled container or backup and `frida/file_protection.js` on a test device."
---

# iOS Data Storage, Data Protection and File System

Audit how an authorized iOS app stores data: keychain, UserDefaults, plists, SQLite and CoreData, caches, tmp, snapshots, cookies, backups and iCloud, file protection classes and POSIX permissions, using `ios_container_audit.py` on a pulled container or backup and `frida/file_protection.js` on a test device.

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

Pull the container from the jailbroken test device with `ios_device.py --pull-container BUNDLE`, or make a backup with `ios_device.py --backup-approved`. Then run `ios_container_audit.py --container DIR` (or `--backup DIR --bundle ID`). It scans plists, UserDefaults, SQLite (with WAL), Cache.db, Cookies.binarycookies, Realm files, snapshots and tmp for secrets and for your own `--marker` value. File protection classes come from `frida/file_protection.js` output (`--protection-json`).

## Coverage

- passive: 15
- bounded: 51
- authorized-only: 4
- not-tested: 5
- total: 75
- sections: Data Storage (15); iOS Data Protection (10); File System Deep (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0051` to `IOS-0525`).
