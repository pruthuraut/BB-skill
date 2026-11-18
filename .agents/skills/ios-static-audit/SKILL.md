---
name: ios-static-audit
description: "Audit an authorized iOS IPA statically: Mach-O parsing (PIE, canary, ARC, encryption, symbols), class dump, Info.plist, ATS, URL schemes, entitlements and provisioning profile, hardcoded secrets, SDK inventory, CoreData models, WebView, keychain, crypto and logging API use, using `ios_static.py` with Kali and open-source tools (radare2, ipsw, class-dump, strings, Ghidra)."
---

# iOS Static Analysis

Audit an authorized iOS IPA statically: Mach-O parsing (PIE, canary, ARC, encryption, symbols), class dump, Info.plist, ATS, URL schemes, entitlements and provisioning profile, hardcoded secrets, SDK inventory, CoreData models, WebView, keychain, crypto and logging API use, using `ios_static.py` with Kali and open-source tools (radare2, ipsw, class-dump, strings, Ghidra).

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

Run first. `ios_static.py` extracts the IPA safely (zip-slip and symlink guarded), parses Info.plist, the provisioning profile and the code-signature entitlements with its own Mach-O reader, and checks binary hardening, imported APIs and strings. When installed it adds `rabin2` (radare2), `ipsw class-dump` or `class-dump`, and `strings`. App Store binaries are FairPlay-encrypted (`cryptid 1`); decrypt your own authorized install on the test device first (see `ios_device.py --print-decrypt`). Use Ghidra (Kali package `ghidra`) for disassembly.

## Coverage

- passive: 27
- bounded: 2
- authorized-only: 1
- total: 30
- sections: Static Analysis (30)

Checklist rows: `references/checklist.md` (IDs `IOS-0001` to `IOS-0030`).
