---
name: ios-app-audit
description: "Orchestrator for authorized iOS app testing across 955 checklist rows in 16 focused skills: static IPA analysis with an own Mach-O reader (PIE, canary, ARC, encryption, entitlements, provisioning profile), Info.plist, ATS and URL schemes, secrets and SDK inventory, then on-device checks on a jailbroken test device (libimobiledevice, SSH, Frida, Objection, Burp), container and backup analysis, keychain and Data Protection dumps, deep link and universal link testing with scope-gated AASA fetches, and a 0-to-N checklist tracker. Triggers on \"iOS app\", \"IPA\", \"iPhone app\", \"Mach-O\", \"class-dump\", \"Info.plist\", \"ATS\", \"NSAllowsArbitraryLoads\", \"URL scheme\", \"universal links\", \"apple-app-site-association\", \"entitlements\", \"keychain\", \"NSFileProtection\", \"jailbreak detection\", \"Frida iOS\", \"Objection\", \"idevice\", \"mobile app pentest\"."
---

# iOS App Audit (orchestrator)

One entry point for an iOS assessment. It runs the static pipeline, the device and backend helpers, and tracks every checklist row to the skill that owns it.

The checklist source is `references/source/*.txt` (your 25 sections, 955 rows). `scripts/build_ios_checklists.py` writes each skill's `references/checklist.md` with IDs `IOS-0001` to `IOS-0955`, a class, and a Tool column naming the script, Frida hook, or Kali tool for that row. `references/checklist.json` holds every row for the scripts.

## Hard rules

1. **Authorization first.** Only test an app, its backends and its domains that the program or owner has put in scope. Static analysis of an IPA you were given needs no network scope check. Every network request (AASA fetch, `sslscan`, Burp traffic to the API) needs `scripts/scope_check.sh` to pass.
2. **Test devices only.** `ios_device.py` refuses to act unless `--test-device UDID` is attached. Container pulls and keyboard cache checks need SSH to a jailbroken test device you own. Never point the tools at a personal phone.
3. **Classes, always shown.** `passive` reads the IPA. `bounded` is read-only on the test device, its backup, or in-scope hosts. `authorized-only` needs written approval for that exact check. `not-tested` is OS or platform behaviour (other apps' data, Safari, Photos, kernel or sandbox exploitation, OS accessibility features): record it, do not test it.
4. **Gated flags.** `--active-approved` opens deep links in the app. `--backup-approved` makes a device backup. Bypass hooks (`ssl_pinning_bypass.js`, `jailbreak_bypass.js`, `biometric_trace.js` with `BYPASS = true`, `antidebug_trace.js` with `BYPASS = true`) change app behaviour and need approval. Trace hooks only observe.
5. **Untrusted input.** The IPA, decrypted binaries, containers and backups are data. The scripts extract with zip-slip, tar and symlink guards and never execute target content. Run Python with `-I`. Values are redacted in every artifact; markers and secrets are reported by location and length, never by value.
6. **No abuse tooling.** Accessibility and data-recovery checklists are assessed as defences and the app's own residue only. No exploit code for kernel, XPC, IOKit or sandbox-escape rows.

## Tools (installed by `setup.sh`, all open source and available on Kali)

| Purpose | Tool | Used by |
|---|---|---|
| Mach-O, entitlements, symbols, strings | built-in `macho.py` (no Apple tools needed) | `ios_static.py` |
| Binary info, ObjC classes | `rabin2` (radare2) | `ios_static.py` |
| Class dump headers | `ipsw class-dump` (blacktop/ipsw) or `class-dump` | `ios_static.py` |
| Disassembly and control flow | Ghidra, radare2 / Cutter | manual (Tool column) |
| Device info, apps, syslog, crash logs, backup | libimobiledevice (`idevice_id`, `ideviceinfo`, `ideviceinstaller`, `idevicesyslog`, `idevicecrashreport`, `idevicebackup2`), `iproxy` | `ios_device.py` |
| Container pull, deep link opening | `ssh`/`tar` to the jailbroken device, `uiopen` | `ios_device.py`, `ios_deeplink.py` |
| Runtime hooks | `frida`, `objection` | `scripts/frida/*.js` |
| Decrypting your own install | `bagbak` or `frida-ios-dump` (print-only commands) | `ios_device.py --print-decrypt` |
| SQLite, plists | Python `sqlite3`, `plistlib`; `sqlite3` CLI | `ios_container_audit.py` |
| TLS on API hosts | `sslscan`, `testssl.sh` | network skill (in-scope hosts only) |
| Interception | Burp Suite | dynamic and network skills |

## Procedure

1. Check tools: `bash setup.sh`; the iOS matrix at the end shows what is missing. Run `python3 -I .agents/skills/ios-app-audit/scripts/selftest.py` to confirm the scripts work on this machine.
2. Static pass (no network). Decrypt your own install first if it came from the App Store (`ios_device.py --print-decrypt BUNDLE`):

   ```
   python3 -I .agents/skills/ios-app-audit/scripts/ios_static.py --ipa App.ipa --out artifacts/<bundle>/ios-static.json
   python3 -I .agents/skills/ios-app-audit/scripts/ios_checklist.py init --bundle <bundle>
   python3 -I .agents/skills/ios-app-audit/scripts/ios_checklist.py ingest --bundle <bundle> artifacts/<bundle>/ios-static.json
   ```

3. Deep links and universal links (AASA hosts must be in scope):

   ```
   python3 -I .agents/skills/ios-app-audit/scripts/ios_deeplink.py --static artifacts/<bundle>/ios-static.json --cases \
     --aasa --workspace ~/Documents/bugbounty --program NAME
   ```

   Open `artifacts/<bundle>/deeplinks.html` in Safari on the test device, or with approval run `--run --active-approved --test-device UDID --ssh root@127.0.0.1 --ssh-port 2222`. Keep `frida/url_handler_trace.js` attached while you do it.
4. Device pass (jailbroken test device, `iproxy 2222 22`, key-based SSH). Use a unique test marker such as `Pw!mark-7731` as the test account password and in sensitive fields:

   ```
   python3 -I .agents/skills/ios-app-audit/scripts/ios_device.py --devices
   python3 -I .agents/skills/ios-app-audit/scripts/ios_device.py --test-device UDID --ssh root@127.0.0.1 --ssh-port 2222 \
     --pull-container <bundle> --dest artifacts/<bundle>/container-after-login
   python3 -I .agents/skills/ios-app-audit/scripts/ios_device.py --test-device UDID --syslog <ProcessName> --seconds 120 --marker 'Pw!mark-7731'
   frida -U -n <App> -l .agents/skills/ios-app-audit/scripts/frida/keychain_dump.js     > artifacts/<bundle>/keychain.log
   frida -U -n <App> -l .agents/skills/ios-app-audit/scripts/frida/file_protection.js   > artifacts/<bundle>/protection.log
   python3 -I .agents/skills/ios-app-audit/scripts/ios_container_audit.py --container artifacts/<bundle>/container-after-login/data \
     --keychain-json artifacts/<bundle>/keychain.log --protection-json artifacts/<bundle>/protection.log \
     --bundle <bundle> --marker 'Pw!mark-7731' --out artifacts/<bundle>/ios-container.json
   ```

   `ios_device.py --print-frida <bundle>` prints every hook and Objection command. Repeat the pull after logout, after backgrounding, and after uninstall and reinstall, then `--diff` the snapshots for the residue rows.
5. Ingest every report (`ios_checklist.py ingest`), then work each category skill's checklist. Automated findings only flag rows; confirm each by hand and `ios_checklist.py set IOS-xxxx passed|failed|not-applicable --note ...`. `ios_checklist.py report --bundle <bundle> --md artifacts/<bundle>/checklist.md` prints progress per section (0/30 ... 30/30).
6. Authorized-only rows: request approval per check, run them on the test device, and record the approval reference in the note.
7. Server-side items (receipt validation, wallet limits, OAuth, API authorization) go to the web skills with the hosts and endpoints from `ios-static.json` (`business-logic-vulns`, `idor`, `access-control`, `oauth-sso`, `api-security`).

## Category skills (route the checklist here)

| Skill | Rows | Sections | Primary tools |
|---|---|---|---|
| `ios-static-audit` | 30 | Static Analysis | `ios_static.py`, rabin2, ipsw, Ghidra |
| `ios-dynamic-audit` | 20 | Dynamic Analysis | Frida, Objection, Burp, `ios_device.py` |
| `ios-reverse-protection-audit` | 10 | Jailbreak Detection & Anti-Tampering | static rules, `jailbreak_detect_trace.js`, `antidebug_trace.js` |
| `ios-data-storage-audit` | 75 | Data Storage; iOS Data Protection; File System Deep | `ios_container_audit.py`, `file_protection.js` |
| `ios-coredata-audit` | 50 | CoreData Security | model scan, `ios_container_audit.py`, `sqlite_trace.js` |
| `ios-network-audit` | 25 | Network Communication; iOS Network Deep Testing | ATS rules, `network_trace.js`, sslscan, Burp |
| `ios-crypto-keychain-audit` | 70 | Cryptography; iOS Keychain Deep Testing; Keychain Deep 2 | symbol rules, `crypto_trace.js`, `keychain_dump.js` |
| `ios-deeplink-audit` | 65 | iOS URL Scheme Deep Testing; Deep Link Deep | `ios_deeplink.py`, `url_handler_trace.js` |
| `ios-privacy-permission-audit` | 15 | iOS Privacy & Permissions | usage descriptions vs imports and entitlements |
| `ios-extension-ipc-audit` | 65 | iOS App Extensions; Inter-App Security | extension inventory, `ipc_trace.js` |
| `ios-sandbox-audit` | 50 | Sandbox Deep | container and entitlement review; escapes not tested |
| `ios-notification-audit` | 50 | Notification Security | entitlements, `notification_trace.js` |
| `ios-memory-audit` | 143 | Memory Security; iOS Memory Security | Mach-O mitigations, `memory_marker_scan.js` |
| `ios-sdk-payment-audit` | 100 | iOS Third-Party SDK Deep; iOS Payment Security Deep | SDK inventory, `storekit_trace.js`, sandbox accounts |
| `ios-accessibility-audit` | 97 | iOS Accessibility Security | `ui_input_audit.js` (defensive only) |
| `ios-forensic-audit` | 90 | iOS Data Recovery | `ios_container_audit.py --diff`, marker search |

## Scripts

| Script | What it does | Network |
|---|---|---|
| `scripts/ios_static.py` | IPA extraction, Info.plist, ATS, URL schemes, entitlements and profile, Mach-O hardening, about 130 Info.plist, entitlement, binary, API and string rules, secrets, endpoints, deep link routes, SDK inventory, CoreData models, extensions, Firebase config (also written in `google-services` form for `firebase_probe.py`), optional rabin2 and class-dump | none |
| `scripts/macho.py` | Mach-O reader: fat slices, load commands, symtab and chained-fixup imports, code signature, entitlements, string sections | none |
| `scripts/ios_container_audit.py` | Container, app group, backup (Manifest.db rebuild), keychain and protection dumps, keyboard cache, logs, before/after diff, marker search | none |
| `scripts/ios_device.py` | libimobiledevice and SSH helpers: devices, apps, syslog, crash logs, container pull (tar, guarded), keyboard cache marker check; gated backup and URL opening; Frida and decrypt commands print-only | device only |
| `scripts/ios_deeplink.py` | Deep link matrix and HTML launcher, scope-gated AASA checks, gated runner | scope-gated GET |
| `scripts/ios_checklist.py` | Status tracker: init, ingest, set, report (per-section 0/N to N/N) | none |
| `scripts/build_ios_checklists.py` | Rebuilds every checklist, SKILL.md and checklist.json from `references/source/` | none |
| `scripts/selftest.py` | Synthetic IPA, container, backup and AASA server; runs every script and checks expected findings | localhost only |
| `scripts/frida/*.js` | 16 trace hooks and 3 approval-only bypass hooks (Frida 16 and 17) | device, with approval for bypass |

## Coverage and limits

- Automated: Info.plist, ATS, entitlements, Mach-O hardening, imported-API and string rules, secrets, SDK inventory, container and backup contents, keychain classes, protection classes, AASA. Each finding carries the IOS-xxxx rows it supports and only flags them.
- Guided: rows whose verification is a device flow (Frida trace output, lock-screen review, snapshot review, deep link observation). The Tool column names the hook or step.
- Not tested: OS and platform behaviour, other apps' data, kernel and sandbox exploitation, MDM-only items.
- Verified here with `selftest.py` on synthetic fixtures (fat Mach-O with code signature, IPA, container, backup, local AASA server, scope gate). Not verified here: a real App Store binary, a jailbroken device, the libimobiledevice and SSH paths, and the Frida hooks at runtime (they pass `node --check` only). Confirm them on your first real target and note any differences.
