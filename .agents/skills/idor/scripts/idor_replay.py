#!/usr/bin/env python3
"""Cross-account replay for IDOR / BOLA (Autorize / Auth Analyzer style). Scope-gated.

Usage:
  idor_replay.py --target example.com --har A.har --as-b 'Cookie: session=B' [--as-b 'Authorization: Bearer B']
                 [--markers 'a@your-domain.test,Alice A,1041'] [--methods GET,HEAD] [--delay 0.5]
                 [--strip-header X-CSRF-Token] [--include REGEX] [--exclude REGEX] [--max 300]
                 [--out artifacts/idor/replay_results.tsv] [--insecure]

For each in-scope request in A's HAR (A acting on A's own objects) it sends:
  A   - the original request (fresh baseline)
  B   - same request with A's Cookie/Authorization removed and B's credentials added
  anon- same request with no credentials
and compares status, size, body similarity and A-specific markers.

Verdicts for B/anon:  LEAK(markers)  SAME  SIMILAR  ENFORCED  DIFFERENT  ERROR
SIMILAR on "current user" endpoints (/me) is expected (B sees B's own data) - markers decide.

Safety: DELETE is never replayed. Non-GET/HEAD methods only with --methods, and only
replay HARs where A acted on objects you own. Logout/delete/revoke-like URLs are skipped.
"""
import argparse
import difflib
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

AUTH_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token"}
HOP = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "te", "upgrade",
       "keep-alive", "proxy-connection", ":authority", ":method", ":path", ":scheme"}
DANGEROUS = re.compile(r"(log_?out|sign_?out|delete|remove|destroy|revoke|unsubscribe|deactivate|cancel|terminate|"
                       r"reset|close-account|disable)", re.I)
STATIC = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map|webp|mp4|webm)(\?|$)", re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def gate(host, checked):
    if host in checked:
        return checked[host]
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
        ok = r.returncode == 0
        sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    checked[host] = ok
    return ok


def send(opener, method, url, headers, body, timeout=30):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(1_000_000), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1_000_000), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode(), {}


def verdict(base, test, markers):
    bcode, bbody, _ = base
    code, body, hdrs = test
    if code == 0:
        return "ERROR"
    text = body.decode("utf-8", "replace")
    hits = [m for m in markers if m and m.lower() in text.lower()]
    if hits and 200 <= code < 400:
        return "LEAK(" + ",".join(hits)[:60] + ")"
    if code in (401, 403, 404, 405) or (300 <= code < 400 and re.search(r"login|signin|auth",
                                                                         hdrs.get("Location", "") or "", re.I)):
        return "ENFORCED"
    if code == bcode and 200 <= code < 300:
        ratio = difflib.SequenceMatcher(None, bbody[:50000], body[:50000]).quick_ratio()
        if ratio > 0.98:
            return "SAME"
        if ratio > 0.80:
            return f"SIMILAR({ratio:.2f})"
    return "DIFFERENT"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--har", required=True)
    ap.add_argument("--as-b", action="append", required=True, help="'Header: value' for account B (repeatable)")
    ap.add_argument("--markers", default="", help="comma-separated strings unique to account A")
    ap.add_argument("--methods", default="GET,HEAD")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--strip-header", action="append", default=[])
    ap.add_argument("--include")
    ap.add_argument("--exclude")
    ap.add_argument("--max", type=int, default=300)
    ap.add_argument("--out", default="artifacts/idor/replay_results.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    methods = {m.strip().upper() for m in a.methods.split(",") if m.strip()} - {"DELETE"}
    markers = [m.strip() for m in a.markers.split(",") if m.strip()]
    strip = AUTH_HEADERS | {h.lower() for h in a.strip_header}
    b_headers = {}
    for h in a.as_b:
        k, sep, v = h.partition(":")
        if not sep:
            sys.exit(f"--as-b must be 'Header: value': {h}")
        b_headers[k.strip()] = v.strip()
    target = a.target.lower()

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    with open(a.har, encoding="utf-8", errors="replace") as fh:
        entries = json.load(fh).get("log", {}).get("entries", [])

    checked, seen, results = {}, set(), []
    skipped = {"method": 0, "scope": 0, "static": 0, "dangerous": 0, "filter": 0, "dup": 0}
    for e in entries:
        if len(results) >= a.max:
            break
        req = e.get("request", {})
        m, url = req.get("method", "GET").upper(), req.get("url", "")
        host = (urlsplit(url).hostname or "").lower()
        if m not in methods:
            skipped["method"] += 1; continue
        if STATIC.search(url):
            skipped["static"] += 1; continue
        if DANGEROUS.search(urlsplit(url).path):
            skipped["dangerous"] += 1; continue
        if (a.include and not re.search(a.include, url)) or (a.exclude and re.search(a.exclude, url)):
            skipped["filter"] += 1; continue
        if host != target and not host.endswith("." + target):
            skipped["scope"] += 1; continue
        if not gate(host, checked):
            skipped["scope"] += 1; continue
        body = ((req.get("postData") or {}).get("text") or "").encode() or None
        key = (m, url, body)
        if key in seen:
            skipped["dup"] += 1; continue
        seen.add(key)

        base_h = {h["name"]: h["value"] for h in req.get("headers", []) if h.get("name", "").lower() not in HOP}
        clean = {k: v for k, v in base_h.items() if k.lower() not in strip}
        A = send(opener, m, url, base_h, body)
        time.sleep(a.delay)
        if not (200 <= A[0] < 300):
            results.append((m, url, A[0], len(A[1]), "-", "-", "-", "-", "skip(baseline not 2xx)"))
            continue
        B = send(opener, m, url, {**clean, **b_headers}, body)
        time.sleep(a.delay)
        N = send(opener, m, url, clean, body)
        time.sleep(a.delay)
        vb, vn = verdict(A, B, markers), verdict(A, N, markers)
        results.append((m, url, A[0], len(A[1]), B[0], len(B[1]), N[0], len(N[1]), f"B:{vb} anon:{vn}"))
        flag = "!!" if any(x.startswith(("LEAK", "SAME")) for x in (vb, vn)) else "  "
        print(f"{flag} {m:5} {A[0]}/{B[0]}/{N[0]}  B:{vb:<16} anon:{vn:<16} {url[:110]}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("method\turl\tA_status\tA_size\tB_status\tB_size\tanon_status\tanon_size\tverdict\n")
        for r in results:
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"\n[+] {len(results)} requests replayed -> {a.out}; skipped {skipped}")
    print("    Verify every LEAK/SAME/SIMILAR manually; same-size error pages and /me-style endpoints cause false positives.")


if __name__ == "__main__":
    main()
