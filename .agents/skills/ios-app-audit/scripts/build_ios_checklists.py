#!/usr/bin/env python3
"""Generate per-skill iOS checklists and SKILL.md files from the source checklist.

Input:  .agents/skills/ios-app-audit/references/source/*.txt
Output: .agents/skills/<skill>/references/checklist.md   (one table per skill, IDs IOS-0001...)
        .agents/skills/<skill>/SKILL.md                  (generated; edit SKILL_META/NOTES below, not the file)
        .agents/skills/ios-app-audit/references/checklist.json  (all rows, read by the scripts)

Source format:
  @skill <name>            start rows for a skill
  ## <section>             section title (kept as the row's section)
  @prefix <text>           prepend text to following lines until @prefix (empty) or @skill
  <check text>             one check per line; optional suffix ::passive|bounded|authorized-only|not-tested

Class rules (a heuristic; the suffix always wins):
  not-tested       OS or platform behaviour, other apps' data, kernel or sandbox exploitation
  passive          review wording (Check/Verify/Analyze/Look) on the IPA, binary, plist or entitlements
  authorized-only  active wording (bypass, hook, inject, hijack, manipulate, replay, intercept, ...)
  bounded          everything else: read-only checks on the test device, its backup, or in-scope hosts
Each row also gets a "Tool" route: the script, Frida hook, or Kali tool that verifies it.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
AUDIT_DIR = os.path.join(SKILLS_DIR, "ios-app-audit")
SOURCE_DIR = os.path.join(AUDIT_DIR, "references", "source")

# OS / platform behaviour that app testing cannot change or own.
PLATFORM_RE = re.compile(
    r"Guided Access|Back Tap|Hearing Devices|RTT/TTY|LED Flash|Sound Recognition|Personal Voice|Live Speech|"
    r"Live Captions|Reachability|Assistive Access|Display Accommodation|Invert Colors|Color Filters|Reduce Motion|"
    r"Increase Contrast|Reduce Transparency|On/Off Labels|Button Shapes|Bold Text|AssistiveTouch device settings|"
    r"AssistiveTouch control center|Zoom feature FLAG_SECURE|"
    r"Quick Start|WiFi known networks|Bluetooth paired|CoreLocation visited|significant location|location services cache|"
    r"Maps route history|Siri interaction history|Dictation history|Safari|photo library thumbnail|camera roll|"
    r"recently deleted photos|photo stream|shared album|Contacts database|Calendar database|Reminders database|"
    r"Notes database|Messages attachment|Mail draft|Apple Watch paired|Continuity camera|Sidecar|AirPlay session|"
    r"HomeKit configuration|Face ID enrollment|Touch ID configuration|Secure Enclave key metadata|Apple Pay transaction cache|"
    r"CallKit call history|sysdiagnose|device-to-device migration|Wallet pass data", re.I)
REVIEW_START_RE = re.compile(r"^(Check|Verify|Analyze|Look|Decompile|Inspect|Review)\b", re.I)
PASSIVE_RE = re.compile(
    r"Info\.plist|entitlement|binary|hardcod|class-dump|symbols|NSLog|framework|librar|model|GoogleService|"
    r"background modes|extension|WKWebView|JavaScript enabled|access group|CommonCrypto|CryptoKit|arc4random|"
    r"format string|buffer overflow|swizzl|app group|SiriKit|ATS|NSAllows|pinning|URL scheme|scheme|"
    r"usage description|transformable|predicate|PIE|ASLR|canary|stack protection|weak encryption|ECB|DES|RC4|"
    r"hardcoded|code signing|anti-debug|jailbreak detection|Secure Enclave|kSecAttr|kSecAccess|NSPersistent|"
    r"NSFileProtection|Data Protection API|configuration files", re.I)
ACTIVE_RE = re.compile(
    r"bypass|hook|inject|injection|brute|hijack|manipulat|tamper|replay|intercept|spoof|exfiltrat|escape|exploit|"
    r"abuse|fraud|race|refund|enumerat|extract|dump|traversal|takeover|steal|theft|keylog|automat|Burp|Frida|"
    r"Objection|Cycript|LLDB|denial of service|DoS|SQL injection|XSS|open redirect|escalat|override|"
    r"trigger|unauthorized action|monitor", re.I)
EXPLICIT_RE = re.compile(r"::(passive|bounded|authorized-only|not-tested)\s*$")

CLASS_PREFIX = {
    "passive": "Static, no device or network.",
    "bounded": "Read-only on your test device, its backup, or in-scope hosts.",
    "authorized-only": "Written approval for this check first; test device and own test accounts only.",
    "not-tested": "OS or platform behaviour, not the app. Record as not tested; report to Apple if found.",
}

S = "`ios_static.py`"
C = "`ios_container_audit.py`"
D = "`ios_device.py`"
L = "`ios_deeplink.py`"


def F(name: str) -> str:
    return f"`frida/{name}.js`"


ROUTES: list[tuple[re.Pattern, str]] = [(re.compile(p, re.I), t) for p, t in [
    (r"hardcoded secrets|binary strings|entitlements for dangerous",
     f"{S} secrets rules over __cstring and bundle files, entitlements and provisioning profile (values redacted)"),
    (r"file coordination|NSFileCoordinator|document picker|bookmark",
     f"{S} file APIs and entitlements; {F('ipc_trace')} and {F('file_protection')} on the test device"),
    (r"keyboard cache|autocorrect|keyboard prediction|Keyboard learned",
     f"{F('ui_input_audit')} (secureTextEntry, autocorrectionType on sensitive fields); {C} --keyboard-dir with a --marker "
     "on the jailbroken test device's /var/mobile/Library/Keyboard"),
    (r"Data Protection|NSFileProtection|encryption at rest|protection class|file protection",
     f"{F('file_protection')} lists the protection class of every container file; feed it to {C} --protection-json; "
     f"{S} reports the com.apple.developer.default-data-protection entitlement"),
    (r"Cycript",
     "Cycript is unmaintained on current iOS; use the Frida REPL (`frida -U -n APP`) or Objection for the same runtime checks"),
    (r"class-dump|Hopper|IDA|disassembl|debug symbols|stripped|format string|buffer overflow|stack canary|"
     r"stack protection|position-independent|ASLR|Address Space|Control Flow|return-oriented|heap spray|"
     r"use-after-free|double-free|integer overflow|pointer arithmetic|memory buffer sizes|guard pages|"
     r"uninitialized|alignment|malloc_zone|objc_destructInstance|non-cacheable|withUnsafeBytes|Data object instead|"
     r"memory-mapped|memory mapping|region permissions|\bARC\b|reference cycle|CoreFoundation object|UIWebView|"
     r"string literal|static string|timing side|secure memory comparison|ARC weak",
     f"{S} binary section (Mach-O flags, imports, `rabin2`/`ipsw class-dump`); confirm in Ghidra or radare2"),
    (r"jailbreak|Cydia|cydia|dylib|DYLD|debugg|P_TRACED|anti-debug|swizzl|integrity|code signing|reverse engineering|"
     r"Frida or similar|memory inspection|memory dumping|compromised processes",
     f"{S} anti-tamper rules; {F('jailbreak_detect_trace')} and {F('antidebug_trace')} show which checks run; "
     f"{F('jailbreak_bypass')} only with approval"),
    (r"apple-app-site-association|AASA|universal link",
     f"{L} --aasa (one scope-gated GET per applinks: domain); {S} entitlements; {L} --cases for link paths"),
    (r"deep link|URL scheme|continueUserActivity|scheme confusion|callback URL|URL schemes from other apps",
     f"{L} --cases builds the matrix from Info.plist schemes and binary routes; send with {L} --run on the test "
     f"device or the generated HTML launcher; watch {F('url_handler_trace')}"),
    (r"keychain|kSecAttr|kSecAccess|LAContext|Secure Enclave|Touch ID|Face ID|biometric",
     f"{S} keychain and LocalAuthentication symbols; {F('keychain_dump')} then {C} --keychain-json; {F('biometric_trace')}"),
    (r"pasteboard|clipboard",
     f"{F('pasteboard_monitor')}; {S} UIPasteboard imports; {C} --marker after the app exits"),
    (r"WKWebView|WebView|JavaScript|SFSafariViewController|content security policy|XSS|cross-site",
     f"{S} WebView rules; {F('webview_inspect')} on the live view"),
    (r"CoreData|Core Data|NSManagedObject|NSFetchedResults|predicate|transformable|value transformer|NSPersistent",
     f"{S} CoreData model scan (.momd); {C} SQLite, WAL and protection checks; {F('sqlite_trace')} for predicates and SQL"),
    (r"SQLite|SQLCipher|Realm|FMDB|GRDB|database|\bWAL\b|journal",
     f"{C} (SQLite, WAL/SHM, Realm header, SQLCipher detection, freelist pages); {F('sqlite_trace')}"),
    (r"SSL|TLS|pinning|certificate|server trust|trust evaluation|AFNetworking|Alamofire|URL ?session delegate",
     f"{S} TLS rules (SecTrust, pinning libraries); `sslscan`/`testssl.sh` on in-scope API hosts; "
     f"{F('ssl_pinning_bypass')} only with approval"),
    (r"crypt|cipher|\bDES\b|RC4|ECB|\bIV\b|nonce|key derivation|PBKDF2|Argon2|random|timing|CommonCrypto|CryptoKit|"
     r"RNCryptor|CryptoSwift|SwiftyRSA|key material|cryptographic|encryption key",
     f"{S} crypto imports and constants; {F('crypto_trace')} (algorithm, mode, IV reuse, PBKDF2 rounds)"),
    (r"StoreKit|receipt|in-app purchase|Apple Pay|wallet|payment|refund|subscription|offer code|introductory|"
     r"promotional|family sharing|App Store|purchase",
     f"{S} StoreKit and PassKit symbols; {F('storekit_trace')}; server-side checks with sandbox accounts via `business-logic-vulns`"),
    (r"notification|APNs|push|badge|Focus|Do Not Disturb",
     f"{S} (aps-environment, notification extensions, UNNotification symbols); {F('notification_trace')}; lock-screen review on the test device"),
    (r"Firebase|GoogleService|Google Analytics|Crashlytics|Fabric|Mixpanel|Amplitude|Segment|Branch|AppsFlyer|Adjust|"
     r"Braze|OneSignal|Pusher|PubNub|Twilio|SendGrid|AWS|Azure|Google Cloud|Stripe|PayPal|Braintree|AdMob|MoPub|"
     r"IronSource|Unity Ads|Vungle|AppLovin|InMobi|SDWebImage|Kingfisher|Nuke|KeychainAccess|Locksmith|SAMKeychain|"
     r"third-party|framework|audio session|watch connectivity|shared with you",
     f"{S} SDK inventory (frameworks, ObjC class prefixes, versions, keys); {F('network_trace')} for SDK traffic; "
     f"Firebase keys with `firebase_probe.py` (scope-gated)"),
    (r"extension|widget|keyboard|Siri|intent|App Clip|XPC|Darwin|Handoff|user activity|activity continuation|AirDrop|"
     r"Universal Clipboard|document provider|file provider|CallKit|CarPlay|app group|shared container|Spotlight|"
     r"UIActivityViewController|sharing|shortcut|live activity|Game Center|Sign in with Apple|CloudKit|iCloud container|"
     r"inter-app|NSUbiquitousKeyValueStore",
     f"{S} extension inventory (NSExtensionPointIdentifier, appex entitlements, app groups); {F('ipc_trace')}"),
    (r"camera|microphone|location|contacts|photo|calendar|reminder|health|home ?kit|motion|Bluetooth|local network|"
     r"Tracking|NFC|EventKit|MapKit|multicast|AdSupport",
     f"{S} usage descriptions, entitlements and framework imports; check prompt timing on the test device"),
    (r"ATS|Transport Security|NSAllows|cleartext|HTTP|WebSocket|\bws\b|proxy|network|DNS|multipart|URLCredential|"
     r"cookie|OAuth|token handling|API|endpoint|background URL|background transfer|URLSession|request",
     f"{S} ATS and URL inventory; {F('network_trace')}; Burp on the test device proxy with approval"),
    (r"UserDefaults|plist|cache|tmp|temporary|Documents|Library|file|backup|iCloud|Data Protection|NSFileProtection|"
     r"protection|storage|snapshot|screenshot|screen recording|background|crash|log|diagnostic|persist|deletion|"
     r"delete|residue|sandbox|container|POSIX|symbolic link",
     f"{C} on the pulled container (`--backup` for backups, `--diff` for before/after); {F('file_protection')}; "
     f"{D} --syslog / --crashlogs for logs"),
    (r"memory|retention|zero|dealloc|autorelease|heap|stack|buffer|object|closure|singleton|delegate|KVO|observer|"
     r"Timer|queue|lazy|thread|CFString|CFData|CFDictionary|image buffer|layer|Metal|OpenGL|Audio Unit|AVFoundation|"
     r"PhotoKit|WatchConnectivity|MultipeerConnectivity|JavaScriptCore|PushKit|malloc|CoreImage",
     f"{F('memory_marker_scan')} searches process memory for a known test marker after the action (login, logout, background)"),
]]

MEMORY_TOOL = (f"{F('memory_marker_scan')} with a known test marker after the action (login, logout, background); "
               f"{S} shows which framework is linked")
ACCESSIBILITY_TOOL = (f"Defensive check: {F('ui_input_audit')} lists text fields on the sensitive screen (secureTextEntry, "
                      f"autocorrection, textContentType, accessibility label and value); {S} reports keyboard-extension and "
                      "screen-capture defences. No accessibility abuse tooling is built or run.")
FORENSIC_TOOL = (f"{C} --diff BEFORE AFTER --marker M on container snapshots taken before and after the action; "
                 f"--backup for backup rows; {D} --syslog/--crashlogs for logs. Record residue location only, own app only.")

SKILL_META = {
    "ios-static-audit": ("iOS Static Analysis", "Audit an authorized iOS IPA statically: Mach-O parsing (PIE, canary, ARC, encryption, symbols), class dump, Info.plist, ATS, URL schemes, entitlements and provisioning profile, hardcoded secrets, SDK inventory, CoreData models, WebView, keychain, crypto and logging API use, using `ios_static.py` with Kali and open-source tools (radare2, ipsw, class-dump, strings, Ghidra)."),
    "ios-dynamic-audit": ("iOS Dynamic Analysis", "Test a running iOS app on a jailbroken test device you own: Frida and Objection hooking, SSL pinning and jailbreak detection bypass, Burp interception, LLDB, keychain, UserDefaults, pasteboard, screenshot and backgrounding checks, using `ios_device.py` and the bundled Frida scripts. Active checks need written approval."),
    "ios-reverse-protection-audit": ("iOS Jailbreak Detection and Anti-Tampering", "Assess an authorized iOS app's anti-reversing controls: jailbreak detection (files, URL schemes, sandbox writes, dyld images), DYLD_INSERT_LIBRARIES and Frida detection, anti-debugging (ptrace, sysctl P_TRACED), code signing and integrity checks, swizzling detection, using static rules and Frida trace scripts on a test device."),
    "ios-data-storage-audit": ("iOS Data Storage, Data Protection and File System", "Audit how an authorized iOS app stores data: keychain, UserDefaults, plists, SQLite and CoreData, caches, tmp, snapshots, cookies, backups and iCloud, file protection classes and POSIX permissions, using `ios_container_audit.py` on a pulled container or backup and `frida/file_protection.js` on a test device."),
    "ios-coredata-audit": ("iOS CoreData Security", "Audit CoreData in an authorized iOS app: store file protection, WAL/SHM and journal files, predicate injection, transformable attributes and value transformers, CloudKit mirroring, Spotlight indexing, migrations and logout cleanup, using the static model scan, `ios_container_audit.py`, and `frida/sqlite_trace.js`."),
    "ios-network-audit": ("iOS Network Communication", "Audit iOS app network security: ATS exceptions (NSAllowsArbitraryLoads, local networking, exception domains), cleartext and ws:// URLs, certificate pinning (AFNetworking, Alamofire, TrustKit), custom trust evaluation, URLCredentialStorage, cookies, background sessions and token handling, using static rules, `sslscan`/`testssl.sh` on in-scope hosts, Frida network tracing and Burp."),
    "ios-crypto-keychain-audit": ("iOS Cryptography and Keychain", "Audit cryptography and keychain use in an authorized iOS app: weak algorithms and ECB, hardcoded keys, PBKDF2 rounds, IV reuse, insecure random, CommonCrypto vs CryptoKit, Secure Enclave, keychain accessibility classes, access control and biometrics, access groups, synchronizable and backup behaviour, using static symbol rules plus `frida/crypto_trace.js` and `frida/keychain_dump.js`."),
    "ios-deeplink-audit": ("iOS URL Schemes, Deep Links and Universal Links", "Audit custom URL schemes and universal links for an authorized iOS app: scheme registration and collisions, apple-app-site-association (scope-gated fetch), parameter injection, open redirect, WebView loading, authentication and authorization on link handlers, callback leakage and malformed URL handling, using `ios_deeplink.py` and `frida/url_handler_trace.js`."),
    "ios-privacy-permission-audit": ("iOS Privacy and Permissions", "Audit privacy permissions in an authorized iOS app: usage descriptions for camera, microphone, location, contacts, photos, calendars, reminders, HealthKit, HomeKit, motion, Bluetooth, local network, tracking (ATT) and Focus, matched against entitlements, imported frameworks and prompt timing, using `ios_static.py` and a test device."),
    "ios-extension-ipc-audit": ("iOS App Extensions and Inter-App Communication", "Audit app extensions and inter-app channels in an authorized iOS app: share, widget, keyboard, notification, intents, file provider, network and other extensions, app groups, shared keychain groups, Handoff, Universal Clipboard, Darwin notifications, XPC, document providers and App Clips, using the `ios_static.py` extension inventory and `frida/ipc_trace.js`."),
    "ios-sandbox-audit": ("iOS Sandbox Boundaries", "Audit how an authorized iOS app uses its sandbox: container isolation, files outside the container, app group and iCloud containers, security-scoped bookmarks, path sanitization and symlinks, pasteboard and share-sheet exits. Kernel and platform sandbox escapes are recorded as not tested; no exploit work is done."),
    "ios-notification-audit": ("iOS Notification Security", "Audit notifications in an authorized iOS app: lock-screen and preview content, notification service and content extensions, action authentication options, critical alert and communication entitlements, silent pushes, attachments and device-token handling, using `ios_static.py`, `frida/notification_trace.js`, and lock-screen review on a test device."),
    "ios-memory-audit": ("iOS Memory Security", "Audit memory handling in an authorized iOS app: binary mitigations (PIE, canary, ARC, PAC), unsafe C functions, and retention of credentials, tokens, keys and PII in process memory after login, logout and backgrounding, using the Mach-O checks in `ios_static.py` and `frida/memory_marker_scan.js` with a known test marker."),
    "ios-sdk-payment-audit": ("iOS Third-Party SDKs and Payments", "Audit third-party SDKs and payments in an authorized iOS app: SDK inventory and versions, analytics and ad SDK data flows, attribution SDKs, cloud credentials, database and keychain wrappers, StoreKit receipt and subscription validation, Apple Pay, card-form protections and wallet limits, using `ios_static.py`, `frida/storekit_trace.js`, and server-side tests with sandbox accounts."),
    "ios-accessibility-audit": ("iOS Accessibility Defences", "Check an authorized iOS app's defences against accessibility and input leakage: secure text entry, autocorrection and keyboard cache, third-party keyboard rejection, accessibility labels and values on sensitive fields, screen-capture and snapshot protection. The skill does not build or run accessibility abuse tooling; OS feature rows are recorded as not tested."),
    "ios-forensic-audit": ("iOS Data Residue and Recovery", "Review data residue left by an authorized iOS app on the owner's own test device: after logout, data clearing, uninstall and reinstall, in the container, keychain, backups, caches, logs, crash and MetricKit reports, using `ios_container_audit.py --diff` and marker search. System and other apps' data (Safari, Photos, Messages) is recorded as not tested."),
}

NOTES = {
    "ios-static-audit": """Run first. `ios_static.py` extracts the IPA safely (zip-slip and symlink guarded), parses Info.plist, the provisioning profile and the code-signature entitlements with its own Mach-O reader, and checks binary hardening, imported APIs and strings. When installed it adds `rabin2` (radare2), `ipsw class-dump` or `class-dump`, and `strings`. App Store binaries are FairPlay-encrypted (`cryptid 1`); decrypt your own authorized install on the test device first (see `ios_device.py --print-decrypt`). Use Ghidra (Kali package `ghidra`) for disassembly.""",
    "ios-dynamic-audit": """Needs a jailbroken test device with frida-server, plus `frida`/`objection` on the workstation. Hooks live in `.agents/skills/ios-app-audit/scripts/frida/`. Run one at a time against the authorized app: `frida -U -f BUNDLE -l <hook>.js`. Trace hooks (`*_trace.js`, `*_monitor.js`, `*_inspect.js`, `*_dump.js`) observe only; bypass hooks (`ssl_pinning_bypass.js`, `jailbreak_bypass.js`, `biometric_trace.js` in bypass mode) change behaviour and need approval. `ios_device.py --print-frida BUNDLE` prints every command.""",
    "ios-reverse-protection-audit": """`ios_static.py` flags jailbreak-detection strings (Cydia, Sileo, /bin/bash, /etc/apt), canOpenURL schemes, ptrace/sysctl/getppid, dyld image enumeration, and code-signature checks. `frida/jailbreak_detect_trace.js` and `frida/antidebug_trace.js` log which checks the app runs at launch. Report weak detection as a hardening gap, not a vulnerability by itself.""",
    "ios-data-storage-audit": """Pull the container from the jailbroken test device with `ios_device.py --pull-container BUNDLE`, or make a backup with `ios_device.py --backup-approved`. Then run `ios_container_audit.py --container DIR` (or `--backup DIR --bundle ID`). It scans plists, UserDefaults, SQLite (with WAL), Cache.db, Cookies.binarycookies, Realm files, snapshots and tmp for secrets and for your own `--marker` value. File protection classes come from `frida/file_protection.js` output (`--protection-json`).""",
    "ios-coredata-audit": """`ios_static.py` lists CoreData models (.momd/.mom) and flags sensitive attribute names and NSKeyedUnarchiveFromData transformers. `ios_container_audit.py` identifies CoreData stores (Z_METADATA), WAL/SHM files, freelist pages and protection classes. `frida/sqlite_trace.js` logs NSPredicate format strings and SQL so you can see whether user input reaches a format string.""",
    "ios-network-audit": """`ios_static.py` reports ATS keys and exceptions, cleartext http:// and ws:// URLs, and pinning libraries. Run `sslscan` or `testssl.sh` only against API hosts listed in scope. Use Burp with the test device proxy; if pinning blocks it, `frida/ssl_pinning_bypass.js` needs approval. `frida/network_trace.js` logs request URLs, header names and sensitive query parameters (values redacted).""",
    "ios-crypto-keychain-audit": """Static rules read imported symbols (CCCrypt, CC_MD5, kSecAttrAccessibleAlways, SecAccessControlCreateWithFlags, SecRandomCopyBytes, kSecAttrTokenIDSecureEnclave). `frida/crypto_trace.js` records algorithm, mode, key length, IV reuse and PBKDF2 rounds (key and IV are hashed, never printed). `frida/keychain_dump.js` lists the app's own keychain items with accessibility class and access control; feed the JSON to `ios_container_audit.py --keychain-json`. Item values are hashed by default.""",
    "ios-deeplink-audit": """`ios_deeplink.py --static artifacts/<bundle>/ios-static.json --cases` builds a test matrix from CFBundleURLTypes, applinks: domains and route strings in the binary, and writes an HTML launcher to open on the test device in Safari. `--aasa` fetches apple-app-site-association for each applinks: domain after the scope check. `--run --active-approved --test-device UDID` opens each case on a jailbroken device with `uiopen` over SSH or on a simulator with `xcrun simctl openurl`. Use only marker hosts and harmless payloads.""",
    "ios-privacy-permission-audit": """`ios_static.py` lists every NS*UsageDescription, flags empty or vague text, and compares them with entitlements (HealthKit, HomeKit, Siri, NFC) and imported frameworks. Check on the test device when each prompt appears and what the app does after a denial.""",
    "ios-extension-ipc-audit": """`ios_static.py` lists every PlugIns/*.appex with its extension point, RequestsOpenAccess for keyboards, activation rules for share and action extensions, and entitlements compared with the host app (app groups, keychain groups). `frida/ipc_trace.js` logs app group containers, suite UserDefaults, Darwin notifications, NSUserActivity, Spotlight indexing and share-sheet items.""",
    "ios-sandbox-audit": """Container isolation is checked from the pulled container and `frida/file_protection.js` (paths outside the container are flagged). App groups and iCloud containers come from entitlements. Sandbox escape rows that need kernel, XPC or IOKit exploitation are not tested.""",
    "ios-notification-audit": """`ios_static.py` reads aps-environment, critical-alert and communication entitlements, notification extensions, and UNNotification symbols. `frida/notification_trace.js` logs categories and their action options (authenticationRequired, destructive, foreground), and incoming payload keys (values redacted). Review the lock screen with the device locked and previews set to Always.""",
    "ios-memory-audit": """Mitigation rows are static: PIE, stack canary, ARC, PAC (arm64e), encryption and unsafe C imports from `ios_static.py`. Retention rows use a marker: log in with a test password that contains a unique marker, perform the action, then run `frida/memory_marker_scan.js` with that marker. A hit after logout or backgrounding is a finding.""",
    "ios-sdk-payment-audit": """`ios_static.py` builds the SDK inventory from Frameworks/, ObjC class prefixes and Info.plist versions, and extracts SDK keys (redacted). Payment checks depend on server-side validation: use sandbox Apple IDs and test cards only, and run price, quantity and receipt replay tests with the `business-logic-vulns` skill. `frida/storekit_trace.js` shows whether the app validates receipts locally.""",
    "ios-accessibility-audit": """This skill covers defences only. `frida/ui_input_audit.js` lists text fields on the current screen with secureTextEntry, autocorrection, spell checking, textContentType and accessibility values (redacted). `ios_static.py` reports whether the app rejects third-party keyboards (shouldAllowExtensionPointIdentifier) and observes screen capture. Rows about OS accessibility features are recorded as not tested.""",
    "ios-forensic-audit": """Run on your own test device only. Snapshot the container before and after the action (`ios_device.py --pull-container`), then `ios_container_audit.py --diff BEFORE AFTER --marker M`. For uninstall rows, reinstall and check whether keychain items survive (`frida/keychain_dump.js`). System-wide stores and other apps' data are not tested.""",
}

TEMPLATE_SKILL = """---
name: {name}
description: "{description}"
---

# {title}

{description}

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

{notes}

## Coverage

{coverage}

Checklist rows: `references/checklist.md` (IDs `{id_first}` to `{id_last}`).
"""


def parse_source() -> list[dict]:
    rows: list[dict] = []
    for path in sorted(glob.glob(os.path.join(SOURCE_DIR, "*.txt"))):
        skill, section, prefix = None, "", ""
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or (line.startswith("#") and not line.startswith("## ")):
                    continue
                if line.startswith("@skill "):
                    skill, section, prefix = line.split(None, 1)[1].strip(), "", ""
                    continue
                if line.startswith("## "):
                    section, prefix = line[3:].strip(), ""
                    continue
                if line.startswith("@prefix"):
                    prefix = line[len("@prefix"):].strip()
                    continue
                if skill is None:
                    raise SystemExit(f"{path}: check before @skill")
                text = f"{prefix} {line}".strip() if prefix else line
                cls = None
                m = EXPLICIT_RE.search(text)
                if m:
                    cls = m.group(1)
                    text = EXPLICIT_RE.sub("", text).strip()
                rows.append({"skill": skill, "section": section, "check": text, "class": cls})
    return rows


def classify(row: dict) -> str:
    if row["class"]:
        return row["class"]
    t = row["check"]
    if PLATFORM_RE.search(t):
        return "not-tested"
    if row["skill"] == "ios-accessibility-audit":
        return "bounded"
    if REVIEW_START_RE.match(t) and PASSIVE_RE.search(t) and not ACTIVE_RE.search(t):
        return "passive"
    if ACTIVE_RE.search(t):
        return "authorized-only"
    if REVIEW_START_RE.match(t) and PASSIVE_RE.search(t):
        return "passive"
    return "bounded"


def tool_for(row: dict) -> str:
    if row["class"] == "not-tested":
        return "-"
    if row["skill"] == "ios-accessibility-audit":
        return ACCESSIBILITY_TOOL
    if row["skill"] == "ios-forensic-audit":
        return FORENSIC_TOOL
    if (row["skill"] == "ios-memory-audit" and row["class"] != "passive"
            and re.search(r"retention|in (application |process )?memory|retain|leak|persistence|exposure", row["check"], re.I)):
        return MEMORY_TOOL
    for rx, text in ROUTES:
        if rx.search(row["check"]):
            return text
    return f"{S} for the static part; manual test on the test device"


def esc(s: str) -> str:
    return s.replace("|", "\\|")


def main() -> int:
    rows = parse_source()
    for i, r in enumerate(rows, 1):
        r["id"] = f"IOS-{i:04d}"
        r["class"] = classify(r)
        r["tool"] = tool_for(r)
        r["verify"] = CLASS_PREFIX[r["class"]]

    by_skill: dict[str, list[dict]] = {}
    for r in rows:
        by_skill.setdefault(r["skill"], []).append(r)
    missing = set(by_skill) - set(SKILL_META)
    if missing:
        raise SystemExit(f"no SKILL_META for: {sorted(missing)}")

    for skill, items in by_skill.items():
        title, description = SKILL_META[skill]
        skill_dir = os.path.join(SKILLS_DIR, skill)
        os.makedirs(os.path.join(skill_dir, "references"), exist_ok=True)
        counts = {c: sum(1 for r in items if r["class"] == c) for c in CLASS_PREFIX}
        cov = "\n".join(f"- {c}: {n}" for c, n in counts.items() if n) + f"\n- total: {len(items)}"
        sections: dict[str, int] = {}
        for r in items:
            sections[r["section"]] = sections.get(r["section"], 0) + 1
        cov += "\n- sections: " + "; ".join(f"{s} ({n})" for s, n in sections.items())

        out = [f"# {title} checklist", "",
               "Generated by `.agents/skills/ios-app-audit/scripts/build_ios_checklists.py` from the source checklist. "
               "Edit the source and rebuild; do not edit this table. Track status with `ios_checklist.py`.", "",
               "Class key: `passive` = read the IPA only. `bounded` = read-only on the test device, its backup, or in-scope "
               "hosts. `authorized-only` = active, needs written approval for that check. `not-tested` = OS or platform "
               "behaviour, recorded only.", ""]
        for section in sections:
            out += [f"## {section}", "", "| ID | Check | Class | Tool |", "|---|---|---|---|"]
            out += [f"| {r['id']} | {esc(r['check'])} | {r['class']} | {esc(r['tool'])} |"
                    for r in items if r["section"] == section]
            out.append("")
        with open(os.path.join(skill_dir, "references", "checklist.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(out))

        md = TEMPLATE_SKILL.format(name=skill, description=description.replace('"', "'"), title=title,
                                   notes=NOTES[skill], coverage=cov, id_first=items[0]["id"], id_last=items[-1]["id"])
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(md)

    with open(os.path.join(AUDIT_DIR, "references", "checklist.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump([{k: r[k] for k in ("id", "skill", "section", "check", "class", "tool", "verify")} for r in rows], fh, indent=1)

    totals = {c: sum(1 for r in rows if r["class"] == c) for c in CLASS_PREFIX}
    print(f"rows: {len(rows)}  skills: {len(by_skill)}  classes: {totals}")
    for skill, items in by_skill.items():
        print(f"  {skill:32s} {len(items):4d}  {items[0]['id']}..{items[-1]['id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
