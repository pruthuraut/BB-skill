---
name: ios-crypto-keychain-audit
description: "Audit cryptography and keychain use in an authorized iOS app: weak algorithms and ECB, hardcoded keys, PBKDF2 rounds, IV reuse, insecure random, CommonCrypto vs CryptoKit, Secure Enclave, keychain accessibility classes, access control and biometrics, access groups, synchronizable and backup behaviour, using static symbol rules plus `frida/crypto_trace.js` and `frida/keychain_dump.js`."
---

# iOS Cryptography and Keychain

Audit cryptography and keychain use in an authorized iOS app: weak algorithms and ECB, hardcoded keys, PBKDF2 rounds, IV reuse, insecure random, CommonCrypto vs CryptoKit, Secure Enclave, keychain accessibility classes, access control and biometrics, access groups, synchronizable and backup behaviour, using static symbol rules plus `frida/crypto_trace.js` and `frida/keychain_dump.js`.

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

Static rules read imported symbols (CCCrypt, CC_MD5, kSecAttrAccessibleAlways, SecAccessControlCreateWithFlags, SecRandomCopyBytes, kSecAttrTokenIDSecureEnclave). `frida/crypto_trace.js` records algorithm, mode, key length, IV reuse and PBKDF2 rounds (key and IV are hashed, never printed). `frida/keychain_dump.js` lists the app's own keychain items with accessibility class and access control; feed the JSON to `ios_container_audit.py --keychain-json`. Item values are hashed by default.

## Coverage

- passive: 15
- bounded: 47
- authorized-only: 3
- not-tested: 5
- total: 70
- sections: Cryptography (10); iOS Keychain Deep Testing (10); Keychain Deep 2 (50)

Checklist rows: `references/checklist.md` (IDs `IOS-0076` to `IOS-0375`).
