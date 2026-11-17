---
name: android-crypto-keystore-audit
description: "Audit cryptography, Android Keystore use, key storage, and biometric-bound keys in an authorized Android app: ECB, hardcoded keys, weak KDFs, IV reuse, MD5/SHA1, insecure random, key sizes, KeyGenParameterSpec settings and biometric crypto objects, using static crypto rules."
---

# Android Cryptography and Keystore

Audit cryptography, Android Keystore use, key storage, and biometric-bound keys in an authorized Android app: ECB, hardcoded keys, weak KDFs, IV reuse, MD5/SHA1, insecure random, key sizes, KeyGenParameterSpec settings and biometric crypto objects, using static crypto rules.

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/android-crypto-keystore-audit.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

## Notes

Crypto rules are static. Confirm hardcoded keys by checking whether the same key appears in more than one build. Keystore rules look for KeyGenParameterSpec settings: user authentication, invalidation on enrollment, and StrongBox.

## Coverage

- passive: 59
- bounded: 17
- authorized-only: 4
- total: 80
- sections: 

Checklist rows: `references/checklist.md` (IDs `AND-0182` to `AND-0261`).
