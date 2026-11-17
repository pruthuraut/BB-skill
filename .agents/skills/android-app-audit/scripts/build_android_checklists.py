#!/usr/bin/env python3
"""Generate per-skill Android checklists and SKILL.md files from the source checklist.

Input:  .agents/skills/android-app-audit/references/source/*.txt
Output: .agents/skills/<skill>/references/checklist.md   (one table per skill, IDs AND-0001...)
        .agents/skills/<skill>/SKILL.md                  (generated; edit NOTES below, not the file)
        .agents/skills/android-app-audit/references/checklist.json  (all rows, read by the scripts)

Source format:
  @skill <name>            start rows for a skill
  ## <section>             section title (kept as the row's section)
  @prefix <text>           prepend text to following lines until @prefix (empty) or @skill
  <check text>             one check per line; optional suffix ::passive|bounded|authorized-only|not-tested

Class rules (a heuristic; the suffix always wins):
  not-tested       device or OEM platform bypass (FRP, Knox, bootloader, OEM unlock, firmware)
  passive          review wording (Check/Verify/Analyze/Review/Look) on code, manifest or config
  authorized-only  active wording (bypass, hook, launch, grant, delete, intercept, extract, ...)
  bounded          everything else: read-only checks on a device or backend
Run with -I when Python reads anything from a downloaded app. This script only reads repo files.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
AUDIT_DIR = os.path.join(SKILLS_DIR, "android-app-audit")
SOURCE_DIR = os.path.join(AUDIT_DIR, "references", "source")

NOT_TESTED_RE = re.compile(r"factory reset protection|Knox|bootloader|OEM unlock|OEM-specific|E-FOTA|"
                           r"enterprise firmware|Google account enrollment|smart switch|Smart Switch", re.I)
REVIEW_START_RE = re.compile(r"^(Check|Verify|Analyze|Review|Look|Inspect)\b", re.I)
PASSIVE_RE = re.compile(r"manifest|source|decompil|strings\.xml|build|gradle|smali|resource|hardcod|hard-cod|"
                        r"allowBackup|debuggable|exported|assetlinks|network security config|proguard|R8|obfusc|"
                        r"google-services|code|config|declar|cleartext|Log\.|setJavaScript|addJavascript|"
                        r"setAllow|setSave|TrustManager|onReceivedSslError|PendingIntent|setPrimaryClip|"
                        r"intent filter|taskAffinity|sharedUserId|protectionLevel|SharedPreferences|shared pref|"
                        r"setVisibility|FLAG_SECURE|Keystore|KeyGenParameterSpec|ECB|MD5|SHA1|random|Random|"
                        r"CertificatePinner|pinning|HostnameVerifier|checkSelfPermission|permission|"
                        r"usesCleartext|fullBackupContent|dangerous permission|BiometricPrompt", re.I)
ACTIVE_RE = re.compile(r"bypass|hook|inject|injection|brute|overlay|tapjack|drozer|launch|replay|escape|"
                       r"exfiltrat|steal|theft|keylog|enumerat|dump|reboot|force stop|revok|grant|enabl|"
                       r"install|delet|clear|traversal|intercept|spoof|clickjack|automat|provision|monitor|"
                       r"escalat|abuse|manipulat|forg|tamper|race|refund|purchase|withdraw|transfer|recover|"
                       r"extract|sniff|mitm|downgrade|hijack|fraud|activation|execution|modif|create|sql|"
                       r"flood|rate limit|reset|unlock|dump|residue|recovery|attack|adb|burp|frida|objection|proxy|intent-based", re.I)
EXPLICIT_RE = re.compile(r"::(passive|bounded|authorized-only|not-tested)\s*$")

VERIFY = {
    "passive": "Static review: run `android_static.py` (manifest, code and secrets rules), then confirm the cited file:line by hand.",
    "bounded": "Read-only check: `android_device.py` on a test device, or `firebase_probe.py` / `deeplink_probe.py` for backend items. One read or request per item, scope-gated.",
    "authorized-only": "Only with written approval for this exact check, on a test device or account you own. Run it through `android_device.py --active-approved` or the Frida steps in the skill notes.",
    "not-tested": "Device or OEM platform bypass, out of scope for app testing. Record as not tested; report to the vendor if found.",
}
ACCESSIBILITY_VERIFY = ("Defensive check: confirm the app sets FLAG_SECURE on sensitive screens, marks password and card "
                        "fields, and does not rely on accessibility for security. No accessibility abuse tooling is built or run.")
FORENSIC_VERIFY = ("Residue review on your own test device after the app's own deletion. Record the residue location and "
                   "sensitivity only; never collect third-party data.")

SKILL_META = {
    "android-static-audit": ("Android Static Analysis", "Audit authorized Android APKs statically: jadx and apktool decompilation, manifest exposure, hardcoded secrets, outdated SDKs, obfuscation, and risky storage, WebView, TLS and logging code patterns, using `android_static.py` with the Kali toolchain (jadx, apktool, aapt, apkleaks, mobsfscan, apkid)."),
    "android-dynamic-audit": ("Android Dynamic Analysis", "Test a running Android app on a test device you own: Frida and Objection hooking, Burp interception, Drozer component testing, adb intent checks, file permissions, clipboard, screenshots and keyboard cache, using `android_device.py` and the bundled Frida scripts. Active checks need written approval."),
    "android-data-storage-audit": ("Android Data Storage", "Audit how an authorized Android app stores data: SharedPreferences and SQLite plaintext, file permissions, external and cache storage, backups, logcat leakage, content providers and Keystore use, using static rules and `android_device.py --storage` on a test device."),
    "android-network-audit": ("Android Network Communication", "Audit Android app network security: cleartext traffic, network security config, certificate pinning, custom TrustManagers, hostname verifiers, SSL error handlers, TLS versions, WebSocket schemes and OAuth token handling, using static rules, network security config review and sslscan on in-scope hosts."),
    "android-reverse-protection-audit": ("Android Reverse Engineering Protection", "Assess an authorized Android app's anti-reversing controls: root, emulator, Frida, Xposed and debugger detection, obfuscation effectiveness, repackaging and tamper checks, string and class encryption, and dynamic code loading, using static rules and Frida detection scripts on a test device."),
    "android-ipc-intent-audit": ("Android IPC and Intents", "Test Android inter-process communication for an authorized app: exported components, intent injection and redirection, PendingIntent misuse, broadcast abuse, content provider injection and traversal, task hijacking and service binding, using manifest audit plus gated adb and Drozer checks on a test device."),
    "android-webview-audit": ("Android WebView", "Audit Android WebView configuration for an authorized app: JavaScript enablement, addJavascriptInterface, file and content access, universal file access, SSL error handling, saved passwords, mixed content, URL override and postMessage, using static WebView rules over the decompiled source."),
    "android-crypto-keystore-audit": ("Android Cryptography and Keystore", "Audit cryptography, Android Keystore use, key storage, and biometric-bound keys in an authorized Android app: ECB, hardcoded keys, weak KDFs, IV reuse, MD5/SHA1, insecure random, key sizes, KeyGenParameterSpec settings and biometric crypto objects, using static crypto rules."),
    "android-firebase-audit": ("Android Firebase and Cloud", "Audit Firebase and cloud backends used by an authorized Android app: Realtime Database and Firestore rules, Storage access, Remote Config, Cloud Functions, google-services.json exposure and App Check, using `firebase_probe.py` read-only checks scoped to the program's listed project."),
    "android-deeplink-audit": ("Android Deep Links and App Links", "Audit deep links, custom schemes and verified App Links for an authorized Android app: intent filters, auto-verify, assetlinks.json, parameter handling, WebView loading of link data and open redirects, using manifest audit plus `deeplink_probe.py` on in-scope domains."),
    "android-notification-audit": ("Android Notification Security", "Audit notification exposure in an authorized Android app: sensitive content on the lock screen, public versions, pending intents and immutable flags, channel importance, notification listeners and remote views, using static notification review and on-device checks."),
    "android-permission-audit": ("Android Permissions", "Audit permissions in an authorized Android app: requested versus needed permissions, dangerous and special permissions, custom permission protection levels, runtime checks and revocation handling, using manifest audit and static code checks."),
    "android-backup-audit": ("Android Backup Security", "Audit backup exposure in an authorized Android app: allowBackup, fullBackupContent rules, ADB backup extraction on a test device, backup agents, and secrets that reach backup, using manifest audit and gated `android_device.py --backup-approved`."),
    "android-logging-audit": ("Android Logging", "Audit logging in an authorized Android app: sensitive data in Log calls, release log stripping, logcat exposure, crash reports, HTTP header and token logging, using static logging rules and gated on-device logcat review."),
    "android-component-audit": ("Android Components", "Audit Android components in an authorized app: exported activities, services, receivers and providers, permission enforcement, caller identity checks, provider query and path handling, task affinity and launch modes, using the manifest audit and static code checks."),
    "android-enterprise-audit": ("Android Work Profile and Enterprise", "Audit work-profile isolation and enterprise behaviour in an authorized Android app: cross-profile data, clipboard, notifications, sharing, MDM and managed configuration, using manifest and static review. Device-platform bypass items are recorded as not tested."),
    "android-sdk-payment-audit": ("Android Third-Party SDKs and Payments", "Audit third-party SDKs and in-app payments in an authorized Android app: SDK versions and data flows, ad and analytics SDK exposure, in-app purchase and subscription verification, wallet limits and payment-form protections, using SDK inventory, static rules and server-side tests on the owner's test accounts."),
    "android-accessibility-audit": ("Android Accessibility Defences", "Check an authorized Android app's defences against accessibility-service abuse: FLAG_SECURE on sensitive screens, password and card field flags, overlay and tapjacking protection, and secure-view handling. The skill does not build or run accessibility abuse tooling."),
    "android-forensic-audit": ("Android Forensic Residue", "Review data residue left by an authorized Android app on the owner's own test device: after uninstall, cache clearing, deletion, backup and log files, WebView storage and thumbnails. Only the app's own data is examined and only on test devices you own."),
}

NOTES = {
    "android-static-audit": """Run first. `android_static.py` decodes the APK with apktool, decompiles with jadx, reads `aapt`/`aapt2` badging, and runs `apkid`, `apkleaks` and `mobsfscan` when installed. Its manifest, code and secrets rules write findings with file:line. Use `--decoded` and `--jadx` to reuse existing output. Obfuscation is judged by the ratio of short class names in the jadx output.""",
    "android-dynamic-audit": """Needs a rooted or emulator test device, Frida server, and `frida`/`objection` on the workstation. Bundled hooks live in `scripts/frida/`: `ssl_pinning_bypass.js`, `root_bypass.js`, `emulator_bypass.js`, `debug_check.js`. Run one hook at a time against your own build. `android_device.py --print-drozer PACKAGE` prints Drozer commands for the in-scope package. Nothing here is run automatically.""",
    "android-data-storage-audit": """Static rules flag plaintext storage and world-readable modes. `android_device.py --storage PACKAGE` reads permissions and listing of shared_prefs, databases and cache with `run-as` (debuggable builds) or with `adb shell ls -l` on the test device. Backup extraction needs `--backup-approved`.""",
    "android-network-audit": """Static rules cover pinning, TrustManager, hostname verifier and cleartext. Run `sslscan` directly against in-scope API hosts (it is not called by `android_static.py`). Use Burp with the test device proxy for interception, and only with approval.""",
    "android-reverse-protection-audit": """Detection and obfuscation rules are static. Use the Frida scripts only to test whether detection logic can be bypassed on your own build, with approval. Report obfuscation as a weakness of the code, not a finding of compromise.""",
    "android-ipc-intent-audit": """Manifest audit lists every exported component and its intent filters. `android_device.py --intents PACKAGE` lists exported components on the device; `--active-approved` allows one explicit `am start` per activity. Drozer commands are printed, not run.""",
    "android-webview-audit": """WebView rules run over the jadx output and the layout XML. Confirm each finding by reading the Activity that loads the WebView and tracing the URL source. A JavaScript interface is only a finding if untrusted pages can reach it.""",
    "android-crypto-keystore-audit": """Crypto rules are static. Confirm hardcoded keys by checking whether the same key appears in more than one build. Keystore rules look for KeyGenParameterSpec settings: user authentication, invalidation on enrollment, and StrongBox.""",
    "android-firebase-audit": """`firebase_probe.py` reads `google-services.json` and tests only read access to the Realtime Database, Firestore, Storage and Remote Config endpoints for the project id listed in your scope file. Writes are never attempted. A Maps key check sends one request per API.""",
    "android-deeplink-audit": """`deeplink_probe.py` fetches `/.well-known/assetlinks.json` on each verified host from the manifest and compares the package name and certificate fingerprint. Intent injection tests on a device use `android_device.py --active-approved`.""",
    "android-notification-audit": """Notification checks are mostly code review of the notification builder (visibility, pending intents, flags, channel importance). Device checks read notification history with `dumpsys notification` on the test device.""",
    "android-permission-audit": """Dangerous permissions and their justification come from the manifest audit. Custom permission protection levels are read from the same manifest. Runtime checks are code review.""",
    "android-backup-audit": """Manifest audit reads allowBackup and fullBackupContent. ADB backup extraction is gated: `android_device.py --active-approved --backup-approved PKG` writes a scratch file under artifacts/, reports its header and encryption flag only, and you delete the file after reporting. Confirm the prompt on the device screen.""",
    "android-logging-audit": """Static logging rules match Log.* and println calls against sensitive names (token, password, card, session). Release log stripping is checked in proguard-rules and the build.gradle release block. On-device logcat is read with `android_device.py --logcat PACKAGE`.""",
    "android-component-audit": """Manifest audit lists component exports, permissions and launch modes. Static rules check ContentProvider query and openFile code.""",
    "android-enterprise-audit": """Most work-profile items need a managed device and an MDM. Record items you cannot set up as not tested rather than marking them passed. Device-platform bypass items are not tested by this skill.""",
    "android-sdk-payment-audit": """`android_static.py` writes an SDK inventory from the decompiled packages and META-INF version files. Payment and ad checks depend on the vendor's server contract, so verify with test accounts and sandbox keys only.""",
    "android-accessibility-audit": """This skill covers defences only. Static rules check FLAG_SECURE, password and card input types, filterTouchesWhenObscured, and accessibility declarations. Do not build or run accessibility abuse tooling; the authorized-only rows describe what the defence must withstand.""",
    "android-forensic-audit": """Run on your own test device only. `android_device.py --residue PACKAGE` lists the app's data directories and file sizes after uninstall or clearing, and reports residue locations. It never collects other apps' data.""",
}

TEMPLATE_SKILL = """---
name: {name}
description: "{description}"
---

# {title}

{description}

This skill is generated from the Android checklist source (`.agents/skills/android-app-audit/references/source/`). Edit the source and rerun `scripts/build_android_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device or account you own.
2. `passive` rows read the APK or repo only. `bounded` rows make read-only requests to in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are device or OEM platform bypasses. They are recorded, not tested.
4. Save evidence to `artifacts/<package>/{name}.json`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the package: `python3 -I .agents/skills/android-app-audit/scripts/android_static.py --apk APK --out artifacts/<package>/android-static.json`.
2. Work this skill's checklist: `references/checklist.md`. Mark each row passed, failed, not applicable, or not tested.
3. For each `bounded` row, run the matching helper (see the verification column).
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand before reporting.

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
                line = raw.rstrip("\n").strip()
                if not line or line.startswith("#"):
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
                explicit = EXPLICIT_RE.search(text)
                cls = None
                if explicit:
                    cls = explicit.group(1)
                    text = EXPLICIT_RE.sub("", text).strip()
                rows.append({"skill": skill, "section": section, "check": text, "class": cls, "source": os.path.basename(path)})
    return rows


def classify(row: dict) -> str:
    if row["class"]:
        return row["class"]
    t = row["check"]
    if NOT_TESTED_RE.search(t):
        return "not-tested"
    if REVIEW_START_RE.match(t) and PASSIVE_RE.search(t):
        return "passive"
    if ACTIVE_RE.search(t):
        return "authorized-only"
    if PASSIVE_RE.search(t):
        return "passive"
    return "bounded"


def verification(row: dict) -> str:
    if row["skill"] == "android-accessibility-audit":
        return ACCESSIBILITY_VERIFY
    if row["skill"] == "android-forensic-audit":
        return FORENSIC_VERIFY
    return VERIFY[row["class"]]


def esc(s: str) -> str:
    return s.replace("|", "\\|")


def main() -> int:
    rows = parse_source()
    for i, r in enumerate(rows, 1):
        r["id"] = f"AND-{i:04d}"
        r["class"] = classify(r)
        r["verify"] = verification(r)

    by_skill: dict[str, list[dict]] = {}
    for r in rows:
        by_skill.setdefault(r["skill"], []).append(r)

    for skill, items in by_skill.items():
        title, description = SKILL_META[skill]
        skill_dir = os.path.join(SKILLS_DIR, skill)
        os.makedirs(os.path.join(skill_dir, "references"), exist_ok=True)
        counts = {c: sum(1 for r in items if r["class"] == c) for c in VERIFY}
        cov = "\n".join(f"- {c}: {n}" for c, n in counts.items() if n) + f"\n- total: {len(items)}"
        sections = []
        for r in items:
            if r["section"] not in sections:
                sections.append(r["section"])
        cov += "\n- sections: " + "; ".join(s for s in sections if s)

        table = ["| ID | Product | Check | Class | Safe verification |", "|---|---|---|---|---|"]
        for r in items:
            table.append(f"| {r['id']} | Android app | {esc(r['check'])} | {r['class']} | {esc(r['verify'])} |")
        checklist = (f"# {title} checklist\n\n"
                     "Generated by `.agents/skills/android-app-audit/scripts/build_android_checklists.py` from the "
                     "source checklist. Edit the source and rebuild; do not edit this table.\n\n"
                     "Class key: `passive` = read the APK or repo. `bounded` = read-only device or backend check. "
                     "`authorized-only` = active, needs written approval for that check. `not-tested` = device or OEM "
                     "platform bypass, recorded only.\n\n" + "\n".join(table) + "\n")
        with open(os.path.join(skill_dir, "references", "checklist.md"), "w", encoding="utf-8") as fh:
            fh.write(checklist)

        md = TEMPLATE_SKILL.format(name=skill, description=description.replace('"', "'"), title=title,
                                   notes=NOTES[skill], coverage=cov, id_first=items[0]["id"], id_last=items[-1]["id"])
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write(md)

    with open(os.path.join(AUDIT_DIR, "references", "checklist.json"), "w", encoding="utf-8") as fh:
        json.dump([{k: r[k] for k in ("id", "skill", "section", "check", "class", "verify")} for r in rows], fh, indent=1)

    totals = {c: sum(1 for r in rows if r["class"] == c) for c in VERIFY}
    print(f"rows: {len(rows)}  skills: {len(by_skill)}  classes: {totals}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
