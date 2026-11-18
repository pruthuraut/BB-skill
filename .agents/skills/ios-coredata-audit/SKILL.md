---
name: ios-coredata-audit
description: "Audit CoreData in an authorized iOS app: store file protection, WAL/SHM and journal files, predicate injection, transformable attributes and value transformers, CloudKit mirroring, Spotlight indexing, migrations and logout cleanup, using the static model scan, `ios_container_audit.py`, and `frida/sqlite_trace.js`."
---

# iOS CoreData Security

Audit CoreData in an authorized iOS app: store file protection, WAL/SHM and journal files, predicate injection, transformable attributes and value transformers, CloudKit mirroring, Spotlight indexing, migrations and logout cleanup, using the static model scan, `ios_container_audit.py`, and `frida/sqlite_trace.js`.

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

`ios_static.py` lists CoreData models (.momd/.mom) and flags sensitive attribute names and NSKeyedUnarchiveFromData transformers. `ios_container_audit.py` identifies CoreData stores (Z_METADATA), WAL/SHM files, freelist pages and protection classes. `frida/sqlite_trace.js` logs NSPredicate format strings and SQL so you can see whether user input reaches a format string.

## Coverage

- passive: 13
- bounded: 30
- authorized-only: 7
- total: 50
- sections: CoreData Security (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0376` to `IOS-0425`).
