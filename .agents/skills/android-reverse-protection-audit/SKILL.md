---
name: android-reverse-protection-audit
description: "Assess an authorized Android app's anti-reversing controls: root, emulator, Frida, Xposed and debugger detection, obfuscation effectiveness, repackaging and tamper checks, string and class encryption, and dynamic code loading, using static rules and Frida detection scripts on a test device."
---

# Android Reverse Engineering Protection

Assess an authorized Android app's anti-reversing controls: root, emulator, Frida, Xposed and debugger detection, obfuscation effectiveness, repackaging and tamper checks, string and class encryption, and dynamic code loading, using static rules and Frida detection scripts on a test device.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-reverse-protection-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Detection and obfuscation rules are static. Use the Frida scripts only to test whether detection logic can be bypassed on your own build, with approval. Report obfuscation as a weakness of the code, not a finding of compromise.

## Coverage

- passive: 7
- bounded: 2
- authorized-only: 6
- total: 15
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0117` to `AND-0131`).
