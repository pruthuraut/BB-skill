---
name: ios-reverse-protection-audit
description: "Assess an authorized iOS app's anti-reversing controls: jailbreak detection (files, URL schemes, sandbox writes, dyld images), DYLD_INSERT_LIBRARIES and Frida detection, anti-debugging (ptrace, sysctl P_TRACED), code signing and integrity checks, swizzling detection, using static rules and Frida trace scripts on a test device."
---

# iOS Jailbreak Detection and Anti-Tampering

Assess an authorized iOS app's anti-reversing controls: jailbreak detection (files, URL schemes, sandbox writes, dyld images), DYLD_INSERT_LIBRARIES and Frida detection, anti-debugging (ptrace, sysctl P_TRACED), code signing and integrity checks, swizzling detection, using static rules and Frida trace scripts on a test device.

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

`ios_static.py` flags jailbreak-detection strings (Cydia, Sileo, /bin/bash, /etc/apt), canOpenURL schemes, ptrace/sysctl/getppid, dyld image enumeration, and code-signature checks. `frida/jailbreak_detect_trace.js` and `frida/antidebug_trace.js` log which checks the app runs at launch. Report weak detection as a hardening gap, not a vulnerability by itself.

## Coverage

- passive: 4
- bounded: 3
- authorized-only: 3
- total: 10
- sections: Jailbreak Detection & Anti-Tampering (10)

Checklist rows: `references/checklist.md` (IDs `IOS-0086` to `IOS-0095`).
