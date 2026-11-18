---
name: ios-extension-ipc-audit
description: "Audit app extensions and inter-app channels in an authorized iOS app: share, widget, keyboard, notification, intents, file provider, network and other extensions, app groups, shared keychain groups, Handoff, Universal Clipboard, Darwin notifications, XPC, document providers and App Clips, using the `ios_static.py` extension inventory and `frida/ipc_trace.js`."
---

# iOS App Extensions and Inter-App Communication

Audit app extensions and inter-app channels in an authorized iOS app: share, widget, keyboard, notification, intents, file provider, network and other extensions, app groups, shared keychain groups, Handoff, Universal Clipboard, Darwin notifications, XPC, document providers and App Clips, using the `ios_static.py` extension inventory and `frida/ipc_trace.js`.

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

`ios_static.py` lists every PlugIns/*.appex with its extension point, RequestsOpenAccess for keyboards, activation rules for share and action extensions, and entitlements compared with the host app (app groups, keychain groups). `frida/ipc_trace.js` logs app group containers, suite UserDefaults, Darwin notifications, NSUserActivity, Spotlight indexing and share-sheet items.

## Coverage

- passive: 15
- bounded: 43
- authorized-only: 6
- not-tested: 1
- total: 65
- sections: iOS App Extensions (15); Inter-App Security (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0151` to `IOS-0575`).
