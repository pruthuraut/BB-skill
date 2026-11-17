#!/usr/bin/env python3
"""Static code rules and secret scanning over decompiled Android sources (jadx output) and resources.

Rules are regular expressions over text files (.java, .kt, .xml, .json, .properties, .js, .gradle,
.txt, .yml). Each finding carries file:line, a redacted snippet and checklist IDs. Matches are
leads: confirm the call path by reading the code before reporting.

Usage:
  code_rules.py --src DIR [--res DIR] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import Finding, checklist_ids, redact_value, shannon, snippet  # noqa: E402

TEXT_EXT = (".java", ".kt", ".xml", ".json", ".properties", ".js", ".gradle", ".txt", ".yml", ".yaml", ".html", ".pro", ".cfg")
MAX_BYTES = 2_000_000

# (rule, severity, title, regex, checklist phrase, flags)
RULES = [
    ("wv-js-enabled", "medium", "WebView JavaScript enabled", r"setJavaScriptEnabled\(\s*true\s*\)", "setJavaScriptEnabled", 0),
    ("wv-js-interface", "medium", "addJavascriptInterface exposes Java object to WebView JS", r"addJavascriptInterface\(", "addJavascriptInterface", 0),
    ("wv-file-access", "medium", "WebView setAllowFileAccess(true)", r"setAllowFileAccess\(\s*true\s*\)", "setAllowFileAccess", 0),
    ("wv-content-access", "low", "WebView setAllowContentAccess(true)", r"setAllowContentAccess\(\s*true\s*\)", "setAllowContentAccess", 0),
    ("wv-universal-file", "high", "WebView setAllowUniversalAccessFromFileURLs(true)", r"setAllowUniversalAccessFromFileURLs\(\s*true\s*\)", "setAllowUniversalAccessFromFileURLs", 0),
    ("wv-file-from-file", "high", "WebView setAllowFileAccessFromFileURLs(true)", r"setAllowFileAccessFromFileURLs\(\s*true\s*\)", "setAllowFileAccessFromFileURLs", 0),
    ("wv-save-password", "low", "WebView setSavePassword(true)", r"setSavePassword\(\s*true\s*\)", "setSavePassword", 0),
    ("wv-save-form", "low", "WebView setSaveFormData(true)", r"setSaveFormData\(\s*true\s*\)", "setSaveFormData", 0),
    ("wv-mixed-content", "high", "WebView mixed content always allowed", r"MIXED_CONTENT_ALWAYS_ALLOW", "mixed content", 0),
    ("wv-ssl-proceed", "high", "onReceivedSslError proceeds on error", r"onReceivedSslError[\s\S]{0,400}?\.proceed\(", "onReceivedSslError", re.S),
    ("wv-geolocation", "low", "WebView geolocation callback grants without prompt", r"onGeolocationPermissionsShowPrompt[\s\S]{0,200}?\.invoke\(", "geolocation permission", re.S),
    ("wv-url-override", "info", "shouldOverrideUrlLoading present; review allowed schemes", r"shouldOverrideUrlLoading", "shouldOverrideUrlLoading", 0),
    ("wv-loadurl-extra", "high", "WebView loadUrl from intent extra", r"loadUrl\(\s*(getIntent\(\)|intent)\.getStringExtra", "intent extras", 0),
    ("wv-loadurl-deeplink", "high", "WebView loadUrl from deep link query", r"loadUrl\([^;]*getQueryParameter", "deep link", 0),
    ("wv-postmessage", "info", "WebView postMessage/onMessage handler; review origin checks", r"postWebMessage|addWebMessageListener", "postMessage", 0),
    ("tls-trust-all", "high", "Empty checkServerTrusted (trusts any certificate)", r"checkServerTrusted\s*\([^)]*\)\s*(throws[^{]*)?\{\s*\}", "custom TrustManager", re.S),
    ("tls-hostname-all", "high", "HostnameVerifier accepts all hosts", r"ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*\([^)]*\)\s*\{\s*return\s+true", "hostname verifier", re.S),
    ("tls-custom-tm", "info", "Custom X509TrustManager implementation; review", r"implements\s+X509TrustManager", "custom TrustManager", 0),
    ("net-cleartext-url", "low", "Cleartext http:// URL in code", r"[\"']http://(?!www\.w3\.org|schemas\.|localhost|127\.0\.0\.1|10\.0\.2\.2)[^\"'\s]+[\"']", "Cleartext", 0),
    ("net-ws-cleartext", "medium", "Cleartext ws:// WebSocket URL", r"[\"']ws://[^\"'\s]+[\"']", "WebSocket", 0),
    ("cry-ecb-default", "high", "Cipher.getInstance with no mode (defaults to ECB on Android)", r"Cipher\.getInstance\(\s*\"(AES|DES|DESede)\"\s*\)", "ECB mode", 0),
    ("cry-ecb", "high", "Cipher uses ECB mode", r"Cipher\.getInstance\(\s*\"[^\"]*/ECB/", "ECB mode", 0),
    ("cry-weak-cipher", "medium", "Weak cipher algorithm (DES, 3DES, RC4, Blowfish)", r"Cipher\.getInstance\(\s*\"(DES|DESede|RC4|ARCFOUR|Blowfish)", "weak", 0),
    ("cry-md5-sha1", "medium", "MD5 or SHA-1 digest used", r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "MD5/SHA1", 0),
    ("cry-java-random", "medium", "java.util.Random used", r"new\s+(java\.util\.)?Random\s*\(", "java.util.Random", 0),
    ("cry-math-random", "low", "Math.random used (check if security-relevant)", r"Math\.random\(", "random", 0),
    ("cry-hardcoded-key", "high", "Hardcoded key bytes in SecretKeySpec", r"SecretKeySpec\(\s*(\"[^\"]{8,}\"\s*\.getBytes|new\s+byte\[\]\s*\{)", "hardcoded cryptographic keys", 0),
    ("cry-const-iv", "high", "Constant IV for IvParameterSpec", r"IvParameterSpec\(\s*(\"[^\"]*\"\s*\.getBytes|new\s+byte\[\]\s*\{)", "IV reuse", 0),
    ("cry-low-rsa", "high", "RSA key size below 2048", r"setKeySize\(\s*(512|768|1024)\s*\)|initialize\(\s*(512|768|1024)\s*\)", "RSA key size", 0),
    ("cry-low-aes", "low", "AES key size below 256", r"setKeySize\(\s*(128|192)\s*\)", "AES key size", 0),
    ("cry-low-pbkdf", "medium", "PBEKeySpec with low iteration count", r"PBEKeySpec\([^;]*?,\s*([1-9]\d{0,3})\s*,\s*\d+\s*\)", "PBKDF2", 0),
    ("ks-invalidate-off", "medium", "Keystore key not invalidated on biometric enrollment", r"setInvalidatedByBiometricEnrollment\(\s*false\s*\)", "invalidated on fingerprint enrollment", 0),
    ("ks-no-user-auth", "info", "KeyGenParameterSpec without user authentication", r"KeyGenParameterSpec\.Builder(?![\s\S]{0,1200}setUserAuthenticationRequired\(\s*true)", "KeyGenParameterSpec", re.S),
    ("sto-world-readable", "high", "World-readable or writeable file mode", r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", "world-readable", 0),
    ("sto-prefs-credential", "high", "Credential or token written to SharedPreferences in plaintext", r"\.edit\(\)\s*\.put(String|Int|Long)?\(\s*\"[^\"]*(password|passwd|token|secret|apikey|api_key|session|auth)", "SharedPrefs", re.I),
    ("sto-external", "medium", "Data written to external storage directory", r"Environment\.getExternalStorageDirectory\(\)|getExternalStorageDirectory\(", "external storage", 0),
    ("sto-sql-concat", "high", "SQL built by string concatenation", r"(rawQuery|execSQL|query)\(\s*\"[^\"]*\"\s*\+", "SQL injection", 0),
    ("log-sensitive", "high", "Sensitive value passed to Log call", r"Log\.[dviwe]\(\s*[^,;]*,[^;]*(password|passwd|token|secret|session|authorization|cvv|card|ssn|pin\b)", "Log.d", re.I),
    ("log-println", "low", "System.out/err print in app code", r"System\.(out|err)\.print", "Log.d", 0),
    ("log-stacktrace", "low", "printStackTrace in app code (may reach logs)", r"\.printStackTrace\(\)", "crash logs", 0),
    ("clip-set", "low", "Data placed on the clipboard; check sensitivity", r"setPrimaryClip\(", "clipboard", 0),
    ("notif-public", "medium", "Notification visibility set to PUBLIC", r"VISIBILITY_PUBLIC", "lock screen", 0),
    ("re-root-check", "info", "Root detection present (review bypass resistance)", r"/system/xbin/su|/system/bin/su|Superuser\.apk|RootBeer|com\.topjohnwu\.magisk", "root detection", 0),
    ("re-frida-check", "info", "Frida detection present (review bypass resistance)", r"frida|gum-js|27042|linjector", "Frida detection", 0),
    ("re-emu-check", "info", "Emulator detection present", r"goldfish|ranchu|Genymotion|isEmulator", "emulator detection", 0),
    ("re-debug-check", "info", "Debugger detection present", r"isDebuggerConnected|FLAG_DEBUGGABLE", "debugging detection", 0),
    ("re-dynamic-load", "medium", "Dynamic code loading (DexClassLoader or System.load)", r"DexClassLoader|loadDex\(|System\.load\(", "DexClassLoader", 0),
    ("re-runtime-exec", "medium", "Runtime.exec used; check input handling", r"Runtime\.getRuntime\(\)\.exec\(", "command", 0),
    ("pi-mutable", "medium", "PendingIntent created without FLAG_IMMUTABLE", r"PendingIntent\.get(Activity|Broadcast|Service)\((?![^;]*FLAG_IMMUTABLE)[^;]*\)", "PendingIntent", 0),
    ("ipc-provider-sql", "high", "ContentProvider query built by concatenation", r"(query|update|delete)\([^;]*\"\s*\+\s*[a-zA-Z]", "content provider SQL", re.S),
    ("ipc-provider-openfile", "high", "ContentProvider openFile without canonical path check", r"openFile\((?![\s\S]{0,400}getCanonicalPath)", "openFile", re.S),
    ("ipc-sendbroadcast", "info", "sendBroadcast used; check receiver scope and extras", r"sendBroadcast\(", "broadcast", 0),
    ("deep-query-param", "info", "Deep link query parameter read; trace its use", r"getQueryParameter\(", "deep link parameters", 0),
    ("a11y-password-no-secure", "low", "Password input in a class without FLAG_SECURE", r"TYPE_TEXT_VARIATION_PASSWORD|textPassword", "accessibility", 0),
    ("pay-local-verify", "info", "In-app purchase handled in app code; confirm server-side verification", r"getPurchaseToken|getOriginalJson|Purchase\s*\(", "purchase token", 0),
    ("sdk-facebook", "info", "Facebook SDK in use; review data sent", r"com\.facebook\.(appevents|FacebookSdk)", "Facebook SDK", 0),
    ("sdk-firebase-analytics", "info", "Firebase Analytics events in use; review parameters", r"FirebaseAnalytics|logEvent\(", "Firebase Analytics", 0),
]

SECRET_RULES = [
    ("secret-aws-key", "high", "AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("secret-google-api", "high", "Google API key (AIza)", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("secret-firebase-url", "info", "Firebase Realtime Database URL", r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("secret-slack", "high", "Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    ("secret-stripe-live", "critical", "Stripe live key", r"\b(sk|rk)_live_[0-9A-Za-z]{16,}"),
    ("secret-github", "high", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    ("secret-jwt", "medium", "JSON Web Token literal", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("secret-private-key", "critical", "Private key block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    ("secret-basic-auth-url", "high", "Credentials in URL", r"https?://[^/\s:@\"']+:[^/\s:@\"']+@[^\s\"']+"),
]
GENERIC_KV = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|secret|access[_-]?token|auth[_-]?token|password|passwd)[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']")
STRINGS_NAME = re.compile(r"(?i)name=\"([a-z0-9_]*(key|token|secret|password|client_id|app_id|sender)[a-z0-9_]*)\"[^>]*>([^<]{6,})<")


def iter_files(root: str):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "build", "__MACOSX")]
        for f in fn:
            if f.endswith(TEXT_EXT):
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) <= MAX_BYTES:
                        yield p
                except OSError:
                    continue


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan(roots: list[str]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats = {"files": 0, "rule_hits": {}}
    compiled = [(r, s, t, re.compile(p, f), ph) for r, s, t, p, ph, f in RULES]
    secret_c = [(r, s, t, re.compile(p)) for r, s, t, p in SECRET_RULES]
    seen = set()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for path in iter_files(root):
            stats["files"] += 1
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            for rule, sev, title, rx, phrase in compiled:
                for m in rx.finditer(text):
                    if rule == "cry-low-pbkdf" and int(m.group(1)) >= 10000:
                        continue
                    ln = line_of(text, m.start())
                    key = (rule, rel, ln)
                    if key in seen:
                        continue
                    seen.add(key)
                    stats["rule_hits"][rule] = stats["rule_hits"].get(rule, 0) + 1
                    findings.append(Finding(rule, sev, title, f"{rel}:{ln}", snippet(text[m.start():m.end() + 80]),
                                            checklist_ids(phrase) if phrase else []))
            for rule, sev, title, rx in secret_c:
                for m in rx.finditer(text):
                    ln = line_of(text, m.start())
                    key = (rule, rel, ln)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(rule, sev, title, f"{rel}:{ln}", redact_value(m.group(0)),
                                            checklist_ids("hardcoded secrets")))
            for m in GENERIC_KV.finditer(text):
                val = m.group(2)
                if shannon(val) < 3.2 or re.fullmatch(r"[a-z_\-]+", val):
                    continue
                ln = line_of(text, m.start())
                key = ("secret-generic", rel, ln)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding("secret-generic", "medium", f"hardcoded {m.group(1)} with high-entropy value",
                                        f"{rel}:{ln}", f"{m.group(1)}={redact_value(val)}",
                                        checklist_ids("hardcoded secrets")))
            if rel.replace(os.sep, "/").startswith("res/values") or "/values" in rel.replace(os.sep, "/"):
                for m in STRINGS_NAME.finditer(text):
                    ln = line_of(text, m.start())
                    findings.append(Finding("res-string-secret", "medium", f"resource string '{m.group(1)}' holds a key-like value",
                                            f"{rel}:{ln}", f"{m.group(1)}={redact_value(m.group(3))}",
                                            checklist_ids("API keys and URLs in strings.xml")))
    return findings, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", action="append", default=[], help="decompiled source root (jadx output); repeatable")
    ap.add_argument("--res", action="append", default=[], help="decoded resource root (apktool output); repeatable")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    findings, stats = scan(args.src + args.res)
    if args.json:
        print(json.dumps({"stats": stats, "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        print(f"files scanned: {stats['files']}  findings: {len(findings)}")
        for f in findings:
            print(f"[{f.severity:>6}] {f.rule} {f.where} {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
