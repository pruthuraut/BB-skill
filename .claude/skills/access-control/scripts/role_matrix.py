#!/usr/bin/env python3
"""Role / tenant authorization matrix (BFLA, vertical privilege escalation). Scope-gated.

Usage:
  role_matrix.py --target example.com --har ADM.har --role 'U1=Cookie: session=u1' [--role 'M=Authorization: Bearer m'] ...
                 [--admin-markers 'Manage users,"role":"admin"'] [--methods GET,HEAD] [--delay 0.5]
                 [--include REGEX] [--exclude REGEX] [--max 300] [--out artifacts/access_control/role_matrix.tsv]
                 [--strip-header X-CSRF-Token] [--insecure]

ADM.har is captured with your highest self-owned role. Each in-scope request is replayed:
  baseline (original credentials), each --role (original Cookie/Authorization removed, role's header added),
  and anon (no credentials).
Cells: ALLOWED (2xx and body similar to baseline or admin markers present), DENIED (401/403/404/405 or
redirect to login), PARTIAL (2xx but different body), ERROR.
Rows where any lower role or anon is ALLOWED are flagged '!!' for manual verification.

Safety: DELETE is never sent; non-GET/HEAD only with --methods; logout/delete/revoke-like URLs are skipped.
Replay only HARs of actions on your own tenant.
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
DANGEROUS = re.compile(r"(log_?out|sign_?out|delete|remove|destroy|revoke|deactivate|disable|terminate|purge|wipe|"
                       r"reset|transfer|cancel)", re.I)
STATIC = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map|webp|mp4)(\?|$)", re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def gate(host, cache):
    if host not in cache:
        here = os.path.dirname(os.path.abspath(__file__))
        script = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "scripts", "scope_check.sh"))
        try:
            r = subprocess.run(["bash", script, host], capture_output=True, text=True)
        except FileNotFoundError:
            sys.exit("bash not found; cannot run scope gate")
        sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
        cache[host] = r.returncode == 0
    return cache[host]


def send(opener, method, url, headers, body):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read(1_000_000), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1_000_000), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode(), {}


def cell(base, res, markers):
    code, body, hdrs = res
    if code == 0:
        return "ERROR"
    if code in (401, 403, 404, 405) or (300 <= code < 400 and re.search(r"login|signin|auth|denied",
                                                                         hdrs.get("Location", "") or "", re.I)):
        return "DENIED"
    if 200 <= code < 300:
        text = body.decode("utf-8", "replace").lower()
        if any(m.lower() in text for m in markers):
            return "ALLOWED(markers)"
        ratio = difflib.SequenceMatcher(None, base[1][:50000], body[:50000]).quick_ratio()
        return "ALLOWED" if ratio > 0.9 else f"PARTIAL({ratio:.2f})"
    return f"OTHER({code})"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--har", required=True)
    ap.add_argument("--role", action="append", required=True, help="NAME=Header: value (repeat; same NAME adds headers)")
    ap.add_argument("--admin-markers", default="")
    ap.add_argument("--methods", default="GET,HEAD")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--include")
    ap.add_argument("--exclude")
    ap.add_argument("--max", type=int, default=300)
    ap.add_argument("--strip-header", action="append", default=[])
    ap.add_argument("--out", default="artifacts/access_control/role_matrix.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    roles = {}
    for spec in a.role:
        name, sep, hdr = spec.partition("=")
        k, sep2, v = hdr.partition(":")
        if not sep or not sep2:
            sys.exit(f"--role must be NAME=Header: value, got {spec}")
        roles.setdefault(name.strip(), {})[k.strip()] = v.strip()
    markers = [m.strip() for m in a.admin_markers.split(",") if m.strip()]
    methods = {m.strip().upper() for m in a.methods.split(",") if m.strip()} - {"DELETE"}
    strip = AUTH_HEADERS | {h.lower() for h in a.strip_header}
    target = a.target.lower()

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    entries = json.load(open(a.har, encoding="utf-8", errors="replace")).get("log", {}).get("entries", [])

    cols = list(roles) + ["anon"]
    rows, cache, seen = [], {}, set()
    print(f"{'':2} {'method':6} {'base':4}  " + "  ".join(f"{c:<16}" for c in cols) + "  url")
    for e in entries:
        if len(rows) >= a.max:
            break
        req = e.get("request", {})
        m, url = req.get("method", "GET").upper(), req.get("url", "")
        host = (urlsplit(url).hostname or "").lower()
        if (m not in methods or STATIC.search(url) or DANGEROUS.search(urlsplit(url).path)
                or (a.include and not re.search(a.include, url)) or (a.exclude and re.search(a.exclude, url))
                or (host != target and not host.endswith("." + target)) or not gate(host, cache)):
            continue
        body = ((req.get("postData") or {}).get("text") or "").encode() or None
        if (m, url, body) in seen:
            continue
        seen.add((m, url, body))
        orig = {h["name"]: h["value"] for h in req.get("headers", []) if h.get("name", "").lower() not in HOP}
        clean = {k: v for k, v in orig.items() if k.lower() not in strip}
        base = send(opener, m, url, orig, body)
        time.sleep(a.delay)
        if not (200 <= base[0] < 300):
            continue
        cells = []
        for c in cols:
            hdrs = {**clean, **roles[c]} if c != "anon" else clean
            cells.append(cell(base, send(opener, m, url, hdrs, body), markers))
            time.sleep(a.delay)
        flag = "!!" if any(x.startswith("ALLOWED") for x in cells) else "  "
        rows.append((m, url, base[0], *cells))
        print(f"{flag} {m:6} {base[0]:<4}  " + "  ".join(f"{x:<16}" for x in cells) + f"  {url[:100]}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("method\turl\tbaseline\t" + "\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(str(x) for x in r) + "\n")
    print(f"\n[+] {len(rows)} admin requests tested -> {a.out}")
    print("    '!!' rows: confirm the function really executed/returned privileged data for that role; "
          "compare against artifacts/access_control/permission_model.md.")


if __name__ == "__main__":
    main()
