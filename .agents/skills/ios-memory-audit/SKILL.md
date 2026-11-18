---
name: ios-memory-audit
description: "Audit memory handling in an authorized iOS app: binary mitigations (PIE, canary, ARC, PAC), unsafe C functions, and retention of credentials, tokens, keys and PII in process memory after login, logout and backgrounding, using the Mach-O checks in `ios_static.py` and `frida/memory_marker_scan.js` with a known test marker."
---

# iOS Memory Security

Audit memory handling in an authorized iOS app: binary mitigations (PIE, canary, ARC, PAC), unsafe C functions, and retention of credentials, tokens, keys and PII in process memory after login, logout and backgrounding, using the Mach-O checks in `ios_static.py` and `frida/memory_marker_scan.js` with a known test marker.

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

Mitigation rows are static: PIE, stack canary, ARC, PAC (arm64e), encryption and unsafe C imports from `ios_static.py`. Retention rows use a marker: log in with a test password that contains a unique marker, perform the action, then run `frida/memory_marker_scan.js` with that marker. A hit after logout or backgrounding is a finding.

## Coverage

- passive: 35
- bounded: 95
- authorized-only: 4
- not-tested: 9
- total: 143
- sections: Memory Security (50); iOS Memory Security (93)

Checklist rows: `references/checklist.md` (IDs `IOS-0426` to `IOS-0865`).
