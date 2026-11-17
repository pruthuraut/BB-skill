---
name: android-webview-audit
description: "Audit Android WebView configuration for an authorized app: JavaScript enablement, addJavascriptInterface, file and content access, universal file access, SSL error handling, saved passwords, mixed content, URL override and postMessage, using static WebView rules over the decompiled source."
---

# Android WebView

Audit Android WebView configuration for an authorized app: JavaScript enablement, addJavascriptInterface, file and content access, universal file access, SSL error handling, saved passwords, mixed content, URL override and postMessage, using static WebView rules over the decompiled source.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-webview-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

WebView rules run over the jadx output and the layout XML. Confirm each finding by reading the Activity that loads the WebView and tracing the URL source. A JavaScript interface is only a finding if untrusted pages can reach it.

## Coverage

- passive: 3
- bounded: 7
- authorized-only: 10
- total: 20
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0162` to `AND-0181`).
