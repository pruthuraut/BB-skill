#!/usr/bin/env python3
"""Scope-gated XSSI / JSONP checker: find script-includable responses that carry session-dependent data.

Usage:
  xssi_check.py --target example.com --urls artifacts/xss/js_endpoints.txt --auth-header 'Cookie: session=...'
                [--auth-header 'Authorization: Bearer ...'] [--delay 0.5] [--out-dir artifacts/xss/xssi]

For each URL (JS files, JSONP endpoints, JSON APIs) it fetches the response with and without your own
session, and also with ?callback=bbxcb (and jsonp=, cb=) added. It reports:
  DYNAMIC     authenticated and anonymous bodies differ (dynamic JS - DetectDynamicJS logic)
  JSONP       the callback name is reflected as a function call: bbxcb(...)
  INCLUDABLE  JavaScript/plain content type (or no nosniff) so <script src> will execute it cross-origin
  SENSITIVE   keys/values that look like personal data or tokens appear only in the authenticated body
  PROTECTED   anti-XSSI prefix present ()]}', while(1);, for(;;);)
and writes a PoC HTML page per JSONP/dynamic finding for testing with YOUR OWN session only.
"""
import argparse
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SENSITIVE = re.compile(r"""["']?(e-?mail|phone|mobile|address|token|csrf|xsrf|api_?key|secret|session|ssn|dob|"""
                       r"""birth|card|iban|account_?(id|number)|user_?id|username|full_?name)["']?\s*[:=]""", re.I)
PREFIX = re.compile(r"^\s*(\)\]\}'|while\s*\(1\)\s*;|for\s*\(\s*;\s*;\s*\)\s*;|throw\s+1\s*;|<!--)")


def gate(host):
    script = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--urls", required=True, help="file with one URL per line")
    ap.add_argument("--auth-header", action="append", default=[])
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--out-dir", default="artifacts/xss/xssi")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    t = a.target.lower()
    with open(a.urls, encoding="utf-8") as fh:
        urls = [u.strip() for u in fh if u.strip() and not u.startswith("#")]
    hosts = set()
    for u in urls:
        h = (urlsplit(u).hostname or "").lower()
        if h != t and not h.endswith("." + t):
            sys.exit(f"{u}: host outside target {a.target}")
        hosts.add(h)
    for h in sorted(hosts):
        gate(h)
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    auth = {}
    for h in a.auth_header:
        k, _, v = h.partition(":")
        auth[k.strip()] = v.strip()

    def get(url, headers):
        req = urllib.request.Request(url, headers={"User-Agent": "bbtest-xssi/1.0", **headers})
        try:
            with opener.open(req, timeout=20) as r:
                res = (r.status, r.headers.get("Content-Type", ""), r.headers.get("X-Content-Type-Options", ""),
                       r.read(2_000_000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            res = (e.code, e.headers.get("Content-Type", ""), e.headers.get("X-Content-Type-Options", ""),
                   e.read(2_000_000).decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            res = (0, "", "", str(e))
        time.sleep(a.delay)
        return res

    os.makedirs(a.out_dir, exist_ok=True)
    rows = []
    for u in urls:
        code, ctype, nosniff, body = get(u, auth)
        acode, _, _, abody = get(u, {})
        flags = []
        if body != abody and code == 200:
            flags.append("DYNAMIC")
        includable = any(x in ctype.lower() for x in ("javascript", "ecmascript", "text/plain")) or \
            ("nosniff" not in nosniff.lower() and "json" not in ctype.lower() and "html" not in ctype.lower())
        if includable:
            flags.append("INCLUDABLE")
        if PREFIX.match(body):
            flags.append("PROTECTED")
        sens = {m.group(1).lower() for m in SENSITIVE.finditer(body)} - {m.group(1).lower() for m in SENSITIVE.finditer(abody)}
        if sens and code == 200:
            flags.append("SENSITIVE:" + ",".join(sorted(sens)))
        jsonp_url = ""
        parts = urlsplit(u)
        for pname in ("callback", "jsonp", "cb", "jsonpCallback"):
            qs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != pname] + [(pname, "bbxcb")]
            cu = urlunsplit(parts._replace(query=urlencode(qs)))
            c2, ct2, _, b2 = get(cu, auth)
            if re.search(r"(^|[;\s/*])bbxcb\s*\(", b2[:2000]):
                flags.append(f"JSONP:{pname}")
                jsonp_url = cu
                break
        rows.append((u, code, ctype, nosniff or "-", " ".join(flags)))
        print(f"{' '.join(flags) or '-':<60} {code} {ctype[:28]:<28} {u}")
        if jsonp_url and any(f.startswith(("SENSITIVE", "DYNAMIC")) for f in flags):
            poc = os.path.join(a.out_dir, f"poc_{len(rows)}.html")
            with open(poc, "w", encoding="utf-8") as fh:
                fh.write("<!doctype html><title>XSSI PoC (own session only)</title><pre id=o></pre>\n"
                         "<script>function bbxcb(d){document.getElementById('o').textContent=JSON.stringify(d,null,2)}</script>\n"
                         f"<script src=\"{jsonp_url.replace('&', '&amp;')}\"></script>\n")
            print(f"      PoC -> {poc} (open while logged in as your own test account; data stays in the page)")
    with open(os.path.join(a.out_dir, "xssi.tsv"), "w", encoding="utf-8") as fh:
        fh.write("url\tstatus\tcontent_type\tnosniff\tflags\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"[+] {len(rows)} URLs -> {os.path.join(a.out_dir, 'xssi.tsv')}")
    print("    Finding = INCLUDABLE + (JSONP or DYNAMIC) + SENSITIVE and not PROTECTED; confirm cross-origin with the PoC.")


if __name__ == "__main__":
    main()
