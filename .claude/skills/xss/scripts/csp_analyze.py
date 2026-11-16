#!/usr/bin/env python3
"""Offline Content-Security-Policy analyser for XSS impact and bypass planning (XS-46).

Usage:
  csp_analyze.py --csp "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com"
  csp_analyze.py --headers saved_headers.txt          (raw response headers, one per line)
  csp_analyze.py --har capture.har                    (every distinct CSP in the HAR)

Reports weaknesses that let an injected payload execute or exfiltrate despite the policy, plus other
XSS-relevant headers when available (X-Content-Type-Options, legacy X-XSS-Protection, Trusted Types).
"""
import argparse
import json
import re
import sys

GADGET_HOSTS = {  # hosts that serve JSONP endpoints or script gadgets (AngularJS etc.) usable for script-src bypass
    "ajax.googleapis.com": "AngularJS/old libraries hosted -> CSTI gadget",
    "cdnjs.cloudflare.com": "any library version (AngularJS, prototype.js) -> gadget",
    "cdn.jsdelivr.net": "any npm/GitHub file -> attacker-published script",
    "unpkg.com": "any npm package -> attacker-published script",
    "raw.githubusercontent.com": "any GitHub file",
    "www.google.com": "JSONP endpoints (e.g. /complete/search) historically",
    "accounts.google.com": "JSONP/redirect gadgets historically",
    "www.youtube.com": "JSONP gadgets historically",
    "*.googleusercontent.com": "user-uploaded content",
    "*.amazonaws.com": "any S3 bucket -> attacker-controlled script",
    "*.cloudfront.net": "any CloudFront distribution",
    "*.azurewebsites.net": "any Azure app", "*.herokuapp.com": "any Heroku app",
    "*.firebaseapp.com": "any Firebase app", "*.github.io": "any GitHub Pages site",
    "*.appspot.com": "any App Engine app", "*.blob.core.windows.net": "any Azure blob",
}


def parse(csp):
    d = {}
    for part in csp.split(";"):
        toks = part.strip().split()
        if toks:
            d.setdefault(toks[0].lower(), toks[1:])
    return d


def analyse(csp, report_only=False):
    out = []
    add = lambda sev, msg: out.append((sev, msg))
    d = parse(csp)
    if report_only:
        add("HIGH", "Content-Security-Policy-Report-Only: nothing is enforced")
    script = d.get("script-src-elem") or d.get("script-src") or d.get("default-src")
    if script is None:
        add("HIGH", "no script-src or default-src: inline and external scripts unrestricted")
        script = []
    s = [x.lower() for x in script]
    has_nonce = any(x.startswith("'nonce-") for x in s)
    has_hash = any(x.startswith(("'sha256-", "'sha384-", "'sha512-")) for x in s)
    strict = "'strict-dynamic'" in s
    if "'unsafe-inline'" in s and not (has_nonce or has_hash):
        add("HIGH", "script-src 'unsafe-inline' without nonce/hash: inline handlers and <script> run")
    if "'unsafe-eval'" in s:
        add("MEDIUM", "'unsafe-eval': eval/Function/setTimeout-string sinks and CSTI gadgets (AngularJS) work")
    if "'unsafe-hashes'" in s:
        add("MEDIUM", "'unsafe-hashes': hashed inline event handlers allowed")
    for x in s:
        if x in ("*", "http:", "https:"):
            add("HIGH", f"script-src {x}: any external script host")
        elif x == "data:":
            add("HIGH", "script-src data: -> <script src=data:,alert(document.domain)>")
        elif x == "blob:":
            add("MEDIUM", "script-src blob: -> script from a blob URL if a script-writing gadget exists")
        elif x.startswith("http") or "." in x:
            host = re.sub(r"^https?://", "", x).split("/")[0]
            for g, why in GADGET_HOSTS.items():
                if host == g or (g.startswith("*.") and (host == g or host.endswith(g[1:]))):
                    add("HIGH" if not strict else "MEDIUM", f"script-src allows {x}: {why}")
            if host.startswith("*."):
                add("MEDIUM", f"wildcard host {x}: any subdomain (takeover / user content) can serve script")
    if "'self'" in s and not strict:
        add("INFO", "'self' allowed: look for same-origin JSONP, uploads served as JS, or user-controlled .js paths")
    if strict and not (has_nonce or has_hash):
        add("MEDIUM", "'strict-dynamic' without nonce/hash: no trusted root script")
    if has_nonce:
        add("INFO", "nonce-based: check the nonce changes per response and is not reflected/cached; "
                    "injections before a nonced <script> may hijack it (dangling <script src=...)")
    obj = d.get("object-src") or d.get("default-src")
    if obj is None or [x.lower() for x in obj] not in (["'none'"],):
        add("MEDIUM", "object-src is not 'none': <object>/<embed> plugin content may load")
    if "base-uri" not in d:
        add("MEDIUM", "no base-uri: <base href=//attacker/> hijacks relative script URLs (XS-20)")
    if "form-action" not in d:
        add("LOW", "no form-action: injected forms can post credentials off-site (XS-21)")
    if "frame-ancestors" not in d:
        add("INFO", "no frame-ancestors: clickjacking may help interaction-dependent payloads")
    if "require-trusted-types-for" in d:
        add("INFO", "Trusted Types enforced for DOM sinks - check policies that pass input through unchanged")
    if not d.get("default-src") and not d.get("connect-src"):
        add("INFO", "no connect-src/default-src: fetch/XHR exfiltration unrestricted")
    return out


def headers_report(hdrs):
    out = []
    lower = {k.lower(): v for k, v in hdrs.items()}
    if "nosniff" not in lower.get("x-content-type-options", "").lower():
        out.append(("LOW", "no X-Content-Type-Options: nosniff (JSON/text responses may be sniffed; XSSI)"))
    xx = lower.get("x-xss-protection")
    if xx:
        out.append(("INFO", f"X-XSS-Protection: {xx} (legacy; ignored by modern browsers, '1; mode=block' can be abused in old IE)"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csp")
    ap.add_argument("--headers")
    ap.add_argument("--har")
    a = ap.parse_args()
    policies = []
    if a.csp:
        policies.append((a.csp, False, {}))
    if a.headers:
        hdrs = {}
        with open(a.headers, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                if v:
                    hdrs[k.strip()] = v.strip()
        low = {k.lower(): v for k, v in hdrs.items()}
        policies.append((low.get("content-security-policy") or low.get("content-security-policy-report-only", ""),
                         "content-security-policy" not in low and "content-security-policy-report-only" in low, hdrs))
    if a.har:
        with open(a.har, encoding="utf-8", errors="replace") as fh:
            har = json.load(fh)
        seen = set()
        for e in har.get("log", {}).get("entries", []):
            hdrs = {h["name"]: h["value"] for h in e.get("response", {}).get("headers", [])}
            low = {k.lower(): v for k, v in hdrs.items()}
            c = low.get("content-security-policy") or low.get("content-security-policy-report-only")
            if c and c not in seen:
                seen.add(c)
                policies.append((c, "content-security-policy" not in low, hdrs))
    if not policies:
        ap.error("give --csp, --headers or --har")
    for csp, ro, hdrs in policies:
        print(f"== {csp[:150] or '(no CSP header)'}")
        res = analyse(csp, ro) if csp else [("HIGH", "no Content-Security-Policy: no mitigation for injected scripts")]
        for sev, msg in res + headers_report(hdrs) if hdrs else res:
            print(f"  {sev:<6} {msg}")


if __name__ == "__main__":
    main()
