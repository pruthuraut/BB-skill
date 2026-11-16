#!/usr/bin/env python3
"""Probe web cache poisoning and deception safely (unique cache busters only).

Poisoning checks (each under its own random cache buster ?cb=...):
  - cache detection (Age, X-Cache, CF-Cache-Status, X-Varnish, ...)
  - unkeyed headers (CP-001), cookies (CP-002), query params (CP-003):
      step 1 send canary in the input -> reflected?
      step 2 same URL without the input -> canary still there = cached + unkeyed
  - fat GET body (CP-008), method override headers (CP-006), Vary report (CP-007)
Deception (CP-004 / CP-009), only with --auth-url, --cookie and --marker:
  request unique static-looking variants of your own account URL with your
  session, then without cookies; your marker in the anonymous response = deception.

Safety: scope-gated; every poisoning probe uses a fresh buster so no real
cache key is touched; deception uses unique random file names. Never purges.

Example:
  cache_probe.py --target example.com --workspace ~/Documents/bugbounty --url https://www.example.com/ \
     --auth-url https://www.example.com/account --cookie 'session=OWN' --marker cpd-91af \
     --out artifacts/example.com/cache_probe.json
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded",
           "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix",
           "X-Original-URL", "X-Rewrite-URL", "X-Original-Host", "X-Forwarded-For", "True-Client-IP",
           "Accept-Language", "Origin", "User-Agent"]
COOKIES = ["lang", "language", "locale", "currency", "country", "region", "theme", "fehost", "variant"]
PARAMS = ["utm_source", "utm_content", "utm_campaign", "fbclid", "gclid", "_", "callback", "ref"]
OVERRIDES = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]
DECEPTION = ["/{r}.css", "/{r}.js", ";{r}.css", "%2f{r}.css", "%3b{r}.css", "%23{r}.css", "%3f{r}.css",
             ".css?{r}", "/{r}.png", "/{r}.ico", "%00{r}.css", "%0a{r}.css", "/..%2f{r}.css", "\\{r}.css"]
HIT_HEADERS = ["age", "x-cache", "cf-cache-status", "x-cache-status", "x-cache-hits", "x-varnish", "x-served-by",
               "x-proxy-cache", "akamai-cache-status", "x-drupal-cache", "x-nextjs-cache", "x-vercel-cache", "server-timing"]


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class Client:
    total = 0

    def __init__(self, base: str, insecure: bool, timeout: float, delay: float):
        self.p = urlsplit(base)
        self.insecure, self.timeout, self.delay, self.n = insecure, timeout, delay, 0

    def req(self, path: str, headers: dict | None = None, method: str = "GET", body: bytes | None = None) -> dict:
        if self.n:
            time.sleep(self.delay)
        self.n += 1
        Client.total += 1
        p = self.p
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.timeout)
        h = {"User-Agent": "Mozilla/5.0 cache-audit", "Accept": "*/*"}
        h.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read(1_000_000)
            hd = {k.lower(): v for k, v in r.getheaders()}
            return {"status": r.status, "headers": hd, "body": data.decode("utf-8", errors="replace"),
                    "raw_headers": "\n".join(f"{k}: {v}" for k, v in r.getheaders())}
        except Exception as e:
            return {"status": None, "headers": {}, "body": "", "raw_headers": "", "error": str(e)}
        finally:
            conn.close()


def cache_view(r: dict) -> dict:
    return {k: r["headers"][k] for k in HIT_HEADERS if k in r["headers"]} | (
        {"cache-control": r["headers"]["cache-control"]} if "cache-control" in r["headers"] else {})


def with_q(path: str, extra: dict) -> str:
    sep = "&" if "?" in path else "?"
    return path + sep + urlencode(extra)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="cacheable page to test for poisoning")
    ap.add_argument("--auth-url", help="your own authenticated page for deception tests")
    ap.add_argument("--cookie", help="your own session cookie (deception only)")
    ap.add_argument("--marker", help="unique string from your own profile shown on --auth-url")
    ap.add_argument("--headers", help="comma list to override the header set")
    ap.add_argument("--cookie-names", help="comma list to override cookie names")
    ap.add_argument("--params", help="comma list to override parameter names")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    target = args.target.lower()
    for u in [args.url] + ([args.auth_url] if args.auth_url else []):
        h = (urlsplit(u).hostname or "").lower()
        if not (h == target or h.endswith("." + target)):
            sys.exit(f"{u}: host is not {target} or a subdomain of it")
        run_scope_check(h, args.workspace, args.target.lower())

    c = Client(args.url, args.insecure, args.timeout, args.delay)
    p = urlsplit(args.url)
    base_path = (p.path or "/") + (("?" + p.query) if p.query else "")
    rnd = lambda: secrets.token_hex(4)
    canary = lambda: f"cp{secrets.token_hex(3)}.example"
    rep: dict = {"url": args.url, "findings": [], "tests": []}

    # cache detection
    cb = rnd()
    a = c.req(with_q(base_path, {"cb": cb}))
    b = c.req(with_q(base_path, {"cb": cb}))
    rep["cache"] = {"first": cache_view(a), "second": cache_view(b), "vary": b["headers"].get("vary")}
    hit = any(("hit" in str(v).lower()) for v in cache_view(b).values()) or (b["headers"].get("age", "0") not in ("0", ""))
    rep["cache"]["second_looks_like_hit"] = hit
    print(f"cache: {rep['cache']['second']}  hit-on-repeat={hit}  vary={rep['cache']['vary']}")
    if not hit:
        print("  no cache hit observed on this URL with a buster; poisoning results may be negative because nothing is cached")

    def two_step(kind: str, row: str, name: str, poison_kw: dict, value: str):
        cbv = rnd()
        path = with_q(base_path, {"cb": cbv})
        if kind == "param":
            ppath = with_q(path, {name: value})
            r1 = c.req(ppath)
        elif kind == "fat":
            r1 = c.req(path, {"Content-Type": "application/x-www-form-urlencoded"}, "GET", f"{name}={value}".encode())
        else:
            r1 = c.req(path, poison_kw)
        reflected = value in r1["body"] or value in r1["raw_headers"]
        rec = {"row": row, "kind": kind, "input": name, "status": r1["status"], "reflected": reflected}
        if reflected:
            r2 = c.req(path)
            cached = value in r2["body"] or value in r2["raw_headers"]
            rec.update({"cached_for_clean_request": cached, "clean_cache_headers": cache_view(r2)})
            if cached:
                rep["findings"].append(f"{row}: {kind} '{name}' is unkeyed and its reflection was cached (buster cb={cbv})")
            else:
                rep["findings"].append(f"{row} lead: {kind} '{name}' reflected but not served from cache on the clean request")
        rep["tests"].append(rec)
        mark = "CACHED" if rec.get("cached_for_clean_request") else ("reflected" if reflected else "")
        print(f"  {row} {kind:6} {name:22} status={r1['status']} {mark}")

    print("unkeyed headers:")
    for hname in (args.headers.split(",") if args.headers else HEADERS):
        v = canary()
        val = f"for={v};host={v}" if hname == "Forwarded" else (f"https://{v}" if hname == "Origin" else v)
        two_step("header", "CP-001", hname, {hname: val}, v)
    print("unkeyed cookies:")
    for cn in (args.cookie_names.split(",") if args.cookie_names else COOKIES):
        v = canary()
        two_step("cookie", "CP-002", cn, {"Cookie": f"{cn}={v}"}, v)
    print("unkeyed params:")
    for pn in (args.params.split(",") if args.params else PARAMS):
        two_step("param", "CP-003", pn, {}, canary())
    print("fat GET:")
    existing = [kv.split("=")[0] for kv in p.query.split("&") if kv] or ["q"]
    two_step("fat", "CP-008", existing[0], {}, canary())

    print("method override:")
    for oh in OVERRIDES:
        cbv = rnd()
        path = with_q(base_path, {"cb": cbv})
        r1 = c.req(path, {oh: "POST"})
        changed = r1["status"] != a["status"]
        rec = {"row": "CP-006", "header": oh, "status": r1["status"], "baseline_status": a["status"]}
        if changed:
            r2 = c.req(path)
            rec["clean_status"] = r2["status"]
            if r2["status"] == r1["status"]:
                rep["findings"].append(f"CP-006: {oh} changed status to {r1['status']} and it was cached (buster cb={cbv})")
        rep["tests"].append(rec)
        print(f"  CP-006 {oh:24} status={r1['status']} (baseline {a['status']})")

    if rep["cache"]["vary"] is None and hit:
        rep["findings"].append("CP-007 lead: cached response without Vary; check inputs that change content (UA, language, Origin, Cookie)")

    if args.auth_url and args.cookie and args.marker:
        print("deception:")
        ap_ = urlsplit(args.auth_url)
        dc = Client(args.auth_url, args.insecure, args.timeout, args.delay)
        apath = (ap_.path or "/").rstrip("/") or "/"
        base_auth = dc.req(apath, {"Cookie": args.cookie})
        if args.marker not in base_auth["body"]:
            print(f"  marker not found on {args.auth_url} with your session; check --marker/--cookie")
        else:
            for tpl in DECEPTION:
                variant = apath + tpl.format(r="cpd" + rnd())
                r1 = dc.req(variant, {"Cookie": args.cookie})
                served = r1["status"] == 200 and args.marker in r1["body"]
                rec = {"row": "CP-004/CP-009", "variant": variant, "auth_status": r1["status"], "auth_has_marker": served}
                if served:
                    r2 = dc.req(variant)
                    leaked = args.marker in r2["body"]
                    rec.update({"anon_status": r2["status"], "anon_has_marker": leaked, "anon_cache": cache_view(r2)})
                    if leaked:
                        rep["findings"].append(f"CP-004/CP-009: private page cached and served anonymously at {variant}")
                rep["tests"].append(rec)
                print(f"  {variant:50} auth={r1['status']}{'+marker' if served else ''} "
                      f"{'LEAKED' if rec.get('anon_has_marker') else ''}")

    print("findings:")
    for f in rep["findings"] or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {Client.total}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
