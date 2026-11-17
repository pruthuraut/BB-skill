---
name: android-deeplink-audit
description: "Audit deep links, custom schemes and verified App Links for an authorized Android app: intent filters, auto-verify, assetlinks.json, parameter handling, WebView loading of link data and open redirects, using manifest audit plus `deeplink_probe.py` on in-scope domains."
---

# Android Deep Links and App Links

Audit deep links, custom schemes and verified App Links for an authorized Android app: intent filters, auto-verify, assetlinks.json, parameter handling, WebView loading of link data and open redirects, using manifest audit plus `deeplink_probe.py` on in-scope domains.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-deeplink-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

`deeplink_probe.py` fetches `/.well-known/assetlinks.json` on each verified host from the manifest and compares the package name and certificate fingerprint. Intent injection tests on a device use `android_device.py --active-approved`.

## Coverage

- passive: 9
- bounded: 20
- authorized-only: 21
- total: 50
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0277` to `AND-0326`).
