---
name: ios-deeplink-audit
description: "Audit custom URL schemes and universal links for an authorized iOS app: scheme registration and collisions, apple-app-site-association (scope-gated fetch), parameter injection, open redirect, WebView loading, authentication and authorization on link handlers, callback leakage and malformed URL handling, using `ios_deeplink.py` and `frida/url_handler_trace.js`."
---

# iOS URL Schemes, Deep Links and Universal Links

Audit custom URL schemes and universal links for an authorized iOS app: scheme registration and collisions, apple-app-site-association (scope-gated fetch), parameter injection, open redirect, WebView loading, authentication and authorization on link handlers, callback leakage and malformed URL handling, using `ios_deeplink.py` and `frida/url_handler_trace.js`.

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

`ios_deeplink.py --static artifacts/<bundle>/ios-static.json --cases` builds a test matrix from CFBundleURLTypes, applinks: domains and route strings in the binary, and writes an HTML launcher to open on the test device in Safari. `--aasa` fetches apple-app-site-association for each applinks: domain after the scope check. `--run --active-approved --test-device UDID` opens each case on a jailbroken device with `uiopen` over SSH or on a simulator with `xcrun simctl openurl`. Use only marker hosts and harmless payloads.

## Coverage

- passive: 6
- bounded: 13
- authorized-only: 46
- total: 65
- sections: iOS URL Scheme Deep Testing (15); Deep Link Deep (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0096` to `IOS-0225`).
