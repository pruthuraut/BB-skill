---
name: android-sdk-payment-audit
description: "Audit third-party SDKs and in-app payments in an authorized Android app: SDK versions and data flows, ad and analytics SDK exposure, in-app purchase and subscription verification, wallet limits and payment-form protections, using SDK inventory, static rules and server-side tests on the owner's test accounts."
---

# Android Third-Party SDKs and Payments

Audit third-party SDKs and in-app payments in an authorized Android app: SDK versions and data flows, ad and analytics SDK exposure, in-app purchase and subscription verification, wallet limits and payment-form protections, using SDK inventory, static rules and server-side tests on the owner's test accounts.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-sdk-payment-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

`android_static.py` writes an SDK inventory from the decompiled packages and META-INF version files. Payment and ad checks depend on the vendor's server contract, so verify with test accounts and sandbox keys only.

## Coverage

- passive: 5
- bounded: 56
- authorized-only: 39
- total: 100
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0722` to `AND-0821`).
