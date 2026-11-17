---
name: android-static-audit
description: "Audit authorized Android APKs statically: jadx and apktool decompilation, manifest exposure, hardcoded secrets, outdated SDKs, obfuscation, and risky storage, WebView, TLS and logging code patterns, using `android_static.py` with the Kali toolchain (jadx, apktool, aapt, apkleaks, mobsfscan, apkid)."
---

# Android Static Analysis

Audit authorized Android APKs statically: jadx and apktool decompilation, manifest exposure, hardcoded secrets, outdated SDKs, obfuscation, and risky storage, WebView, TLS and logging code patterns, using `android_static.py` with the Kali toolchain (jadx, apktool, aapt, apkleaks, mobsfscan, apkid).

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-static-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Run first. `android_static.py` decodes the APK with apktool, decompiles with jadx, reads `aapt`/`aapt2` badging, and runs `apkid`, `apkleaks` and `mobsfscan` when installed. Its manifest, code and secrets rules write findings with file:line. Use `--decoded` and `--jadx` to reuse existing output. Obfuscation is judged by the ratio of short class names in the jadx output.

## Coverage

- passive: 33
- bounded: 5
- authorized-only: 3
- total: 41
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0001` to `AND-0041`).
