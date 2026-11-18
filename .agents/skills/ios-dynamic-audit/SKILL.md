---
name: ios-dynamic-audit
description: "Test a running iOS app on a jailbroken test device you own: Frida and Objection hooking, SSL pinning and jailbreak detection bypass, Burp interception, LLDB, keychain, UserDefaults, pasteboard, screenshot and backgrounding checks, using `ios_device.py` and the bundled Frida scripts. Active checks need written approval."
---

# iOS Dynamic Analysis

Test a running iOS app on a jailbroken test device you own: Frida and Objection hooking, SSL pinning and jailbreak detection bypass, Burp interception, LLDB, keychain, UserDefaults, pasteboard, screenshot and backgrounding checks, using `ios_device.py` and the bundled Frida scripts. Active checks need written approval.

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

Needs a jailbroken test device with frida-server, plus `frida`/`objection` on the workstation. Hooks live in `.agents/skills/ios-app-audit/scripts/frida/`. Run one at a time against the authorized app: `frida -U -f BUNDLE -l <hook>.js`. Trace hooks (`*_trace.js`, `*_monitor.js`, `*_inspect.js`, `*_dump.js`) observe only; bypass hooks (`ssl_pinning_bypass.js`, `jailbreak_bypass.js`, `biometric_trace.js` in bypass mode) change behaviour and need approval. `ios_device.py --print-frida BUNDLE` prints every command.

## Coverage

- bounded: 7
- authorized-only: 13
- total: 20
- sections: Dynamic Analysis (20)

Checklist rows: `references/checklist.md` (IDs `IOS-0031` to `IOS-0050`).
