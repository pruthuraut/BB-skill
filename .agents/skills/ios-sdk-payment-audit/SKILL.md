---
name: ios-sdk-payment-audit
description: "Audit third-party SDKs and payments in an authorized iOS app: SDK inventory and versions, analytics and ad SDK data flows, attribution SDKs, cloud credentials, database and keychain wrappers, StoreKit receipt and subscription validation, Apple Pay, card-form protections and wallet limits, using `ios_static.py`, `frida/storekit_trace.js`, and server-side tests with sandbox accounts."
---

# iOS Third-Party SDKs and Payments

Audit third-party SDKs and payments in an authorized iOS app: SDK inventory and versions, analytics and ad SDK data flows, attribution SDKs, cloud credentials, database and keychain wrappers, StoreKit receipt and subscription validation, Apple Pay, card-form protections and wallet limits, using `ios_static.py`, `frida/storekit_trace.js`, and server-side tests with sandbox accounts.

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

`ios_static.py` builds the SDK inventory from Frameworks/, ObjC class prefixes and Info.plist versions, and extracts SDK keys (redacted). Payment checks depend on server-side validation: use sandbox Apple IDs and test cards only, and run price, quantity and receipt replay tests with the `business-logic-vulns` skill. `frida/storekit_trace.js` shows whether the app validates receipts locally.

## Coverage

- passive: 1
- bounded: 61
- authorized-only: 34
- not-tested: 4
- total: 100
- sections: iOS Third-Party SDK Deep (50); iOS Payment Security Deep (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0576` to `IOS-0675`).
