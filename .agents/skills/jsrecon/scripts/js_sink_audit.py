#!/usr/bin/env python3
"""Offline JavaScript audit for the JSA rows that js_analyzer.py does not cover.

Run after js_analyzer.py (on its beautified output and recovered source maps), or
directly on a folder of .js/.mjs/.html/.vue/.jsx/.tsx files. No network access.

Categories (JSA row in brackets): feature flags [004], admin routes [005], debug toggles [006],
connection strings [008], crypto keys [009], OAuth client secrets [010], payment secrets [013],
Mailgun keys [015], WebSocket endpoints [018], debug/legacy routes [019], env config objects [021],
JWT handling [022], web storage [023/024], IndexedDB [025], sanitizers [027], eval/Function [028],
HTML sinks [029], document.write [030], React [031], Vue [032], AngularJS [033], prototype pollution [034],
DOM clobbering [035], location redirects [036], fetch CORS [037], credentials include [038],
service workers [039], web workers [040], notifications [041], geolocation [042], media capture [043],
clipboard [044], SharedArrayBuffer [045], WebAssembly [046], CSP gadgets [047], nonce gadgets [048],
Trusted Types [049], third-party scripts [050].

Sink rows are raised to "high" when a user-controlled source (location, URL params, hash, referrer,
postMessage data, window.name, cookies, storage) appears within a few lines.

Example:
  js_sink_audit.py artifacts/js_analysis/beautified --out artifacts/example.com/js_sink_audit.json --host example.com
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".html", ".htm", ".svelte")
SOURCES = re.compile(r"location\.(hash|search|href|pathname)|document\.(URL|documentURI|referrer|cookie)|window\.name|URLSearchParams|"
                     r"\bparams\.get\(|searchParams|event\.data|\be\.data\b|\bmsg\.data\b|localStorage\.getItem|sessionStorage\.getItem|\$route\.query|"
                     r"router\.query|useSearchParams|getParameter|\.query\.")
I = re.I
RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    # (category, JSA, base severity, description, regex)
    ("feature-flag", "JSA-004", "info", "feature flag definitions", re.compile(r"(feature_?flags?|featureToggles?|isBeta|enable[A-Z]\w+|launchdarkly|ldclient|optimizely|split\.io|unleash|flagsmith|growthbook)", I)),
    ("admin-route", "JSA-005", "medium", "admin/internal routes", re.compile(r"['\"`]/(admin|administrator|internal|staff|superuser|backoffice|manage|moderator|ops|root|sudo)(/[\w\-/:]*)?['\"`]", I)),
    ("debug-toggle", "JSA-006", "low", "debug toggles", re.compile(r"__DEV__|localStorage\.(getItem|setItem)\(['\"]debug|[?&]debug=|enableDebug|debugMode|\.debug\s*=\s*true|verbose(Logging)?\s*:\s*true", I)),
    ("conn-string", "JSA-008", "critical", "database connection string with credentials", re.compile(r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|amqps?|mssql|sqlserver)://[^\s'\"`:/]+:[^\s'\"`@]+@[^\s'\"`]+|Server=[^;'\"]+;[^'\"]*Password=[^;'\"]+", I)),
    ("crypto-key", "JSA-009", "high", "client-side encryption key or IV", re.compile(r"CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit|HmacSHA\d+)\.\w+\([^,]+,\s*['\"][^'\"]{6,}['\"]|(aes|encryption|crypt|hmac|signing|private)_?(key|secret|iv)\s*[:=]\s*['\"][^'\"]{8,}['\"]|\"d\"\s*:\s*\"[A-Za-z0-9_-]{40,}\"", I)),
    ("oauth-client-secret", "JSA-010", "high", "OAuth client secret in client code", re.compile(r"client_?secret['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", I)),
    ("payment-secret", "JSA-013", "critical", "payment provider secret", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}|access_token\$production\$[0-9a-z]+\$[0-9a-f]{32}|(braintree|adyen|paypal)[\w.]*(private|secret)[\w]*\s*[:=]\s*['\"][^'\"]{10,}", I)),
    ("mailgun-key", "JSA-015", "high", "Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("websocket-endpoint", "JSA-018", "info", "WebSocket endpoints", re.compile(r"new\s+WebSocket\(\s*[^)]{1,200}|['\"`]wss?://[^'\"`\s]+|\bio\(\s*['\"`][^'\"`]+|new\s+SockJS\(|HubConnectionBuilder\(\)|graphql-ws|subscriptions-transport-ws", I)),
    ("debug-route", "JSA-019", "low", "debug/legacy API routes", re.compile(r"['\"`]/(api/)?(v0|beta|alpha|test|testing|debug|dev|internal|legacy|old|private)/[\w\-/]*['\"`]", I)),
    ("env-config", "JSA-021", "medium", "environment config objects", re.compile(r"window\.__(ENV|CONFIG|APP_CONFIG|RUNTIME_CONFIG|INITIAL_STATE|NUXT)__|__NEXT_DATA__|process\.env\.[A-Z_]+|(REACT_APP|VITE|NEXT_PUBLIC|NUXT_ENV|GATSBY)_[A-Z0-9_]+|['\"](staging|development|production|qa|uat)['\"]\s*:\s*\{", I)),
    ("jwt-handling", "JSA-022", "medium", "client-side JWT handling", re.compile(r"jwt[_-]?decode|jwtDecode|atob\([^)]*split\(['\"]\.['\"]\)|\.split\(['\"]\.['\"]\)\[1\]|jsonwebtoken|jose\.|\bexp\s*[<>]=?\s*Date\.now|alg['\"]?\s*:\s*['\"](none|HS256)", I)),
    ("storage-sensitive", "JSA-023/024", "medium", "token/PII in web storage", re.compile(r"(local|session)Storage\.setItem\(\s*['\"`][^'\"`]*(token|jwt|auth|session|secret|password|refresh|apikey|api_key|user|email|card)[^'\"`]*['\"`]", I)),
    ("indexeddb", "JSA-025", "low", "IndexedDB usage", re.compile(r"indexedDB\.open\(|new\s+Dexie\(|localforage|idb-keyval|openDB\(", I)),
    ("sanitizer", "JSA-027", "medium", "sanitizer configuration", re.compile(r"DOMPurify\.sanitize\([^)]*(ADD_TAGS|ADD_ATTR|ALLOW_UNKNOWN_PROTOCOLS|SAFE_FOR_TEMPLATES|WHOLE_DOCUMENT|RETURN_DOM|ALLOWED_URI_REGEXP)|DOMPurify\.addHook|sanitize-html|xss\(\s*[^,)]+,\s*\{|\.replace\(/<script|\.replace\(/[<>]", I)),
    ("eval-sink", "JSA-028", "medium", "eval/Function/string timers", re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|set(Timeout|Interval)\(\s*['\"`]|set(Timeout|Interval)\(\s*[a-zA-Z_$][\w$.]*\s*[,)]", I)),
    ("html-sink", "JSA-029", "medium", "HTML sinks", re.compile(r"\.(innerHTML|outerHTML)\s*\+?=|insertAdjacentHTML\(|\.html\(\s*[^)'\"`]|createContextualFragment\(|\.srcdoc\s*=", I)),
    ("document-write", "JSA-030", "medium", "document.write", re.compile(r"document\.write(ln)?\s*\(", I)),
    ("react-dangerous", "JSA-031", "medium", "React dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML", I)),
    ("vue-vhtml", "JSA-032", "medium", "Vue v-html / innerHTML domProps", re.compile(r"v-html\s*=|domProps\s*:\s*\{[^}]*innerHTML|\"v-html\"", I)),
    ("angularjs", "JSA-033", "medium", "AngularJS template/expression risk", re.compile(r"\$sce\.trustAs(Html|Js|ResourceUrl|Url)|\$compile\(|\$interpolate\(|\$parse\(|ng-bind-html-unsafe|angular\.version|ng-app|\$sceProvider\.enabled\(\s*false", I)),
    ("proto-pollution", "JSA-034", "medium", "prototype pollution vector", re.compile(r"__proto__|constructor\s*\]\s*\[\s*['\"]prototype|\[\s*['\"]constructor['\"]\s*\]|(deepmerge|merge|extend|defaultsDeep|setWith|set|assignDeep|mergeWith)\s*\([^)]*(JSON\.parse|params|query|body|location)|for\s*\(\s*(const|let|var)\s+\w+\s+in\s+\w+\)\s*\{[^}]*\[\w+\]\s*=", I)),
    ("dom-clobbering", "JSA-035", "low", "DOM clobbering pattern", re.compile(r"window\.\w+\s*\|\|\s*\{|document\.\w+\s*\|\|\s*\{|(var|let|const)\s+\w+\s*=\s*window\.\w+\s*\|\||document\.getElementById\([^)]+\)\.(src|href|value|getAttribute)\b|\bdocument\.forms\.\w+", I)),
    ("location-redirect", "JSA-036", "medium", "location/window.open redirect", re.compile(r"(window\.|document\.|top\.)?location(\.href)?\s*=(?!=)|location\.(assign|replace)\(|window\.open\(", I)),
    ("fetch-cors", "JSA-037", "low", "fetch/axios CORS mode or dynamic base URL", re.compile(r"mode\s*:\s*['\"](cors|no-cors)['\"]|axios\.create\(\s*\{\s*baseURL\s*:\s*[^'\"`]|fetch\(\s*(`\$\{|[a-zA-Z_$][\w$.]*\s*\+)", I)),
    ("credentials-include", "JSA-038", "medium", "credentialed cross-origin requests", re.compile(r"credentials\s*:\s*['\"]include['\"]|withCredentials\s*[:=]\s*true", I)),
    ("service-worker", "JSA-039", "medium", "service worker registration", re.compile(r"serviceWorker\.register\(|self\.addEventListener\(['\"]fetch['\"]|caches\.open\(|workbox", I)),
    ("web-worker", "JSA-040", "low", "web worker messaging", re.compile(r"new\s+(Shared)?Worker\(|importScripts\(|self\.onmessage|onmessage\s*=", I)),
    ("notification", "JSA-041", "low", "Notification / Push API", re.compile(r"Notification\.requestPermission|new\s+Notification\(|pushManager\.subscribe|showNotification\(", I)),
    ("geolocation", "JSA-042", "medium", "geolocation access", re.compile(r"geolocation\.(getCurrentPosition|watchPosition)", I)),
    ("media-capture", "JSA-043", "medium", "camera/microphone/screen capture", re.compile(r"getUserMedia\(|getDisplayMedia\(|navigator\.permissions\.query\(\s*\{\s*name\s*:\s*['\"](camera|microphone)", I)),
    ("clipboard", "JSA-044", "medium", "clipboard access", re.compile(r"clipboard\.(readText|read)\(|addEventListener\(\s*['\"]paste['\"]|execCommand\(\s*['\"](copy|paste)['\"]", I)),
    ("sharedarraybuffer", "JSA-045", "low", "SharedArrayBuffer / Atomics", re.compile(r"\bSharedArrayBuffer\b|\bAtomics\.\w+|crossOriginIsolated", I)),
    ("wasm", "JSA-046", "low", "WebAssembly loading", re.compile(r"WebAssembly\.(instantiate|instantiateStreaming|compile|compileStreaming)\(", I)),
    ("csp-gadget", "JSA-047", "medium", "CSP bypass gadget", re.compile(r"[?&](callback|jsonp|cb)=|\$\.getScript\(|\$\.ajax\([^)]*dataType\s*:\s*['\"]jsonp|angular\.module|ng-csp|Vue\.compile\(|new\s+Vue\(\{[^}]*template", I)),
    ("nonce-gadget", "JSA-048", "high", "script creation that may inherit trust (nonce/strict-dynamic)", re.compile(r"\.nonce\s*=|getAttribute\(['\"]nonce['\"]\)|setAttribute\(['\"]nonce['\"]|createElement\(['\"]script['\"]\)[\s\S]{0,200}?\.src\s*=\s*(?!['\"`]https?://)", I)),
    ("trusted-types", "JSA-049", "high", "Trusted Types policy", re.compile(r"trustedTypes\.createPolicy\(\s*['\"]([\w-]+)['\"][\s\S]{0,300}?create(HTML|Script|ScriptURL)\s*:\s*(\(?\s*(?P<a>\w+)\s*\)?\s*=>\s*(?P=a)\b|function\s*\(\s*(?P<f>\w+)\s*\)\s*\{\s*return\s+(?P=f)\s*;?\s*\})|trustedTypes\.createPolicy\(\s*['\"]default['\"]", I)),
]
SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"][^>]*>", I)
DYN_SCRIPT = re.compile(r"createElement\(['\"]script['\"]\)[\s\S]{0,300}?\.src\s*=\s*['\"`](https?:)?//([^/'\"`]+)", I)
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SINK_CATS = {"eval-sink", "html-sink", "document-write", "react-dangerous", "vue-vhtml", "location-redirect", "angularjs"}


def scan_file(path, host, out, third):
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    if len(text) > 15_000_000:
        return
    lines = text.split("\n")
    line_starts = [0]
    for ln in lines:
        line_starts.append(line_starts[-1] + len(ln) + 1)

    def line_no(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for cat, row, sev, desc, rx in RULES:
        for m in rx.finditer(text):
            ln = line_no(m.start())
            ctx_lo, ctx_hi = max(0, ln - 4), min(len(lines), ln + 3)
            ctx = "\n".join(lines[ctx_lo:ctx_hi])
            s = sev
            sourced = bool(SOURCES.search(ctx))
            if cat in SINK_CATS and sourced:
                s = "high"
            if cat == "proto-pollution" and sourced:
                s = "high"
            snippet = m.group(0)[:160].replace("\n", " ")
            if cat in ("conn-string", "crypto-key", "oauth-client-secret", "payment-secret", "mailgun-key"):
                snippet = re.sub(r"(['\"]?)([^'\"\s:@]{4})[^'\"\s@]{4,}([^'\"\s:@]{2})(['\"]?)", r"\1\2...\3\4", snippet)
            out.append({"file": path, "line": ln, "category": cat, "row": row, "severity": s, "desc": desc,
                        "user_source_nearby": sourced, "match": snippet})
    for rx in (SCRIPT_SRC, DYN_SCRIPT):
        for m in rx.finditer(text):
            src = m.group(1) if rx is SCRIPT_SRC else "//" + m.group(2)
            h = urlsplit(src if "//" in src else "").hostname
            if h and (not host or not (h == host or h.endswith("." + host))):
                tag = m.group(0) if rx is SCRIPT_SRC else text[m.start(): m.end() + 300]
                third[h].append({"file": path, "line": line_no(m.start()), "sri": re.search(r"integrity\s*=", tag, re.I) is not None,
                                 "dynamic": rx is DYN_SCRIPT})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="files or folders (beautified JS, recovered sources, HTML)")
    ap.add_argument("--host", help="target registrable domain, used to classify third-party scripts")
    ap.add_argument("--min-severity", default="info", choices=list(SEV_ORDER))
    ap.add_argument("--max-per-category", type=int, default=25, help="cap printed hits per category (all are saved)")
    ap.add_argument("--out")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
                files += [os.path.join(root, n) for n in names if n.lower().endswith(EXTS)]
        else:
            files.append(p)
    hits: list = []
    third: dict = defaultdict(list)
    host = (a.host or "").lower()
    for f in files:
        scan_file(f, host, hits, third)
    hits = [h for h in hits if SEV_ORDER[h["severity"]] <= SEV_ORDER[a.min_severity]]
    hits.sort(key=lambda h: (SEV_ORDER[h["severity"]], h["row"], h["file"], h["line"]))
    by_cat = Counter(h["category"] for h in hits)
    shown = Counter()
    for h in hits:
        if shown[h["category"]] >= a.max_per_category:
            continue
        shown[h["category"]] += 1
        src = " [user source nearby]" if h["user_source_nearby"] and h["category"] in SINK_CATS | {"proto-pollution", "nonce-gadget", "trusted-types"} else ""
        print(f"[{h['severity']}] {h['row']} {h['category']} {h['file']}:{h['line']}{src}  {h['match'][:110]}")
    tp = []
    for h, uses in sorted(third.items()):
        no_sri = [u for u in uses if not u["sri"] and not u["dynamic"]]
        tp.append({"host": h, "uses": len(uses), "without_sri": len(no_sri), "dynamic": sum(u["dynamic"] for u in uses)})
    if tp:
        print("third-party script hosts (JSA-050):")
        for t in tp:
            print(f"  {t['host']}: {t['uses']} includes, {t['without_sri']} static without SRI, {t['dynamic']} dynamic")
    print(f"files {len(files)}, hits {len(hits)}, by category {dict(by_cat.most_common())}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump({"files": len(files), "hits": hits, "third_party_scripts": tp}, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
