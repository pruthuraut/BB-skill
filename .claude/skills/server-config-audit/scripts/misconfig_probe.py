#!/usr/bin/env python3
"""Bounded generic server misconfiguration probe (SMC rows).

Per base URL, a small fixed set of requests:
  SMC-004  version headers from the baseline response
  SMC-007/009  OPTIONS on / and per-method status on a random non-existent path
  SMC-008  one TRACE with a marker header (echo = XST)
  SMC-005/006/015/017  error triggers (random 404, '%' path, bad method, malformed JSON,
           array and long params) scanned for stack-trace, debug, and leak signatures;
           GET of known debug paths (status only plus signature match)
  SMC-003  directory listing on common folders
  SMC-012/013  Host and X-Forwarded-Host canaries (cache-busted) reflected in Location/body
  SMC-018/019/020  only with --crlf-url containing FUZZ: CRLF payload variants
No credentials, no PUT/DELETE to real resources, no execution endpoints.

Example:
  misconfig_probe.py --target example.com --workspace ~/Documents/bugbounty --url https://www.example.com/ \
     --crlf-url 'https://www.example.com/redirect?next=FUZZ' --out artifacts/example.com/misconfig.json
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via",
                   "x-runtime", "x-version", "x-drupal-cache", "x-varnish", "x-backend-server", "x-served-by"]
SIGS = {
    "django-debug": r"You're seeing this error because you have <code>DEBUG = True|DEBUG = True in your Django settings",
    "python-traceback": r"Traceback \(most recent call last\)",
    "werkzeug-debugger": r"Werkzeug Debugger|__debugger__|The debugger caught an exception",
    "laravel": r"Whoops! There was an error|Ignition|laravel/framework|vendor/laravel",
    "symfony": r"Symfony\\Component|sf-toolbar|/_profiler/",
    "rails": r"Action Controller: Exception caught|ActiveRecord::|app/controllers/",
    "spring": r"Whitelabel Error Page|org\.springframework|java\.lang\.\w+Exception|\bat org\.\w+",
    "aspnet": r"Server Error in '/' Application|<b>Stack Trace:</b>|System\.Web\.|ASP\.NET is configured to show verbose",
    "node": r"at Object\.<anonymous>|at Module\._compile|node_modules/|SyntaxError: Unexpected token",
    "php": r"<b>(Fatal error|Warning|Parse error|Notice)</b>:|Stack trace:\s*#0| on line <b>\d+",
    "go-panic": r"goroutine \d+ \[running\]|panic: ",
    "sql-error": r"SQLSTATE\[|ORA-\d{5}|MySQL server version|PG::\w+Error|syntax error at or near|SQLite3::",
    "internal-ip": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "fs-path": r"(/var/www/|/home/\w+/|/usr/local/|/opt/\w+/|[A-Z]:\\\\(inetpub|Users|Windows)\\\\)",
    "phpinfo": r"<title>phpinfo\(\)</title>|PHP Version \d",
}
SIG_RE = {k: re.compile(v, re.I) for k, v in SIGS.items()}
DEBUG_PATHS = ["/_profiler", "/__debug__/", "/console", "/_ignition/health-check", "/telescope", "/actuator",
               "/actuator/env", "/trace.axd", "/elmah.axd", "/phpinfo.php", "/info.php", "/server-status",
               "/server-info", "/debug/pprof/", "/debug/vars", "/rails/info/properties", "/.env"]
LIST_DIRS = ["/uploads/", "/files/", "/images/", "/static/", "/assets/", "/backup/", "/backups/", "/logs/", "/tmp/",
             "/data/", "/media/", "/public/", "/docs/", "/downloads/"]
LISTING_RE = re.compile(r"<title>\s*Index of|Directory Listing For|\[To Parent Directory\]|<h1>Index of", re.I)
CRLF_PAYLOADS = ["%0d%0aX-Injected:%20{m}", "%0aX-Injected:%20{m}", "%0dX-Injected:%20{m}", "%E5%98%8A%E5%98%8DX-Injected:%20{m}",
                 "%0d%0a%20X-Injected:%20{m}", "%23%0d%0aX-Injected:%20{m}", "%0d%0aSet-Cookie:%20{m}=1",
                 "%0d%0a%0d%0a{m}SPLIT"]


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class C:
    def __init__(self, base, insecure, timeout, delay, cookie):
        self.p, self.insecure, self.timeout, self.delay, self.cookie, self.n = urlsplit(base), insecure, timeout, delay, cookie, 0

    def req(self, method, path, headers=None, body=None, host_header=None):
        if self.n:
            time.sleep(self.delay)
        self.n += 1
        p = self.p
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.timeout)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host_header or p.netloc)
            conn.putheader("User-Agent", "Mozilla/5.0 server-config-audit")
            if self.cookie:
                conn.putheader("Cookie", self.cookie)
            for k, v in (headers or {}).items():
                conn.putheader(k, v)
            if body is not None:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            r = conn.getresponse()
            data = r.read(600_000).decode("utf-8", errors="replace")
            return {"status": r.status, "headers": r.getheaders(), "body": data}
        except Exception as e:
            return {"status": None, "headers": [], "body": "", "error": str(e)}
        finally:
            conn.close()


def sigs(text: str) -> list[str]:
    return [k for k, r in SIG_RE.items() if r.search(text)]


def hget(r, name):
    return [v for k, v in r["headers"] if k.lower() == name]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--api-path", default=None, help="API path for malformed JSON test (default: /api/)")
    ap.add_argument("--crlf-url", help="URL with FUZZ where a value is reflected into a header (e.g. redirect)")
    ap.add_argument("--cookie", help="own session cookie (optional)")
    ap.add_argument("--skip", default="", help="comma list of sections to skip: methods,trace,errors,debug,listing,host,crlf")
    ap.add_argument("--delay", type=float, default=0.4)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    skip = set(args.skip.split(",")) if args.skip else set()

    target = args.target.lower()
    hosts = {(urlsplit(u).hostname or "").lower() for u in [args.url] + ([args.crlf_url] if args.crlf_url else [])}
    for h in hosts:
        if not (h == target or h.endswith("." + target)):
            sys.exit(f"{h} is not {target} or a subdomain of it")
        run_scope_check(h, args.workspace, args.target.lower())

    c = C(args.url, args.insecure, args.timeout, args.delay, args.cookie)
    m = "smc" + secrets.token_hex(4)
    F: list[str] = []
    rep: dict = {"url": args.url, "marker": m}

    base = c.req("GET", "/")
    vh = {k.lower(): v for k, v in base["headers"] if k.lower() in VERSION_HEADERS}
    rep["version_headers"] = vh
    if any(re.search(r"\d", v) for v in vh.values()):
        F.append(f"SMC-004: version disclosure {vh}")
    elif vh:
        F.append(f"SMC-004 info: product headers {vh}")

    if "methods" not in skip:
        o = c.req("OPTIONS", "/")
        allow = ", ".join(hget(o, "allow") + hget(o, "public"))
        dav = hget(o, "dav") + hget(o, "ms-author-via")
        rep["options"] = {"status": o["status"], "allow": allow, "dav": dav}
        if allow:
            F.append(f"SMC-009: OPTIONS Allow: {allow}")
            risky = [x for x in ("PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL", "COPY", "MOVE", "CONNECT", "TRACE") if x in allow.upper()]
            if risky:
                F.append(f"SMC-007: risky methods advertised {risky}")
        if dav:
            F.append(f"SMC-009: WebDAV advertised {dav}")
        rnd = f"/{m}-nonexistent"
        per = {}
        for meth in ("PUT", "DELETE", "PATCH", "PROPFIND"):
            r = c.req(meth, rnd, body=b"" if meth in ("PUT", "PATCH") else None)
            per[meth] = r["status"]
        rep["method_status_on_random_path"] = per
        odd = {k: v for k, v in per.items() if v not in (None, 400, 401, 403, 404, 405, 501)}
        if odd:
            F.append(f"SMC-007 lead: methods not rejected on a random path {odd} (verify with class M canary only)")

    if "trace" not in skip:
        t = c.req("TRACE", "/", {"X-Smc-Trace": m})
        rep["trace"] = t["status"]
        if t["status"] == 200 and m in t["body"]:
            F.append("SMC-008: TRACE enabled and echoes request headers (XST)")

    if "errors" not in skip:
        triggers = [("GET", f"/{m}-404", None, {}), ("GET", "/%", None, {}), ("GET", f"/?{m}[]=1&{m}[x]=2", None, {}),
                    ("GET", f"/?q={'A' * 5000}", None, {}), ("FOO", "/", None, {}),
                    ("POST", args.api_path or "/api/", b'{"a":', {"Content-Type": "application/json"}),
                    ("POST", args.api_path or "/api/", b'{"id":{"$gt":""},"n":[1,{"x":true}]}', {"Content-Type": "application/json"})]
        errs = []
        for meth, path, body, hd in triggers:
            r = c.req(meth, path, hd, body)
            s = sigs(r["body"]) + [f"header:{k}" for k, v in r["headers"] if sigs(v)]
            errs.append({"method": meth, "path": path[:60], "status": r["status"], "signatures": s})
            if s:
                row = "SMC-006" if any(x in s for x in ("django-debug", "werkzeug-debugger", "laravel", "symfony", "rails")) else \
                      "SMC-005" if any(x in s for x in ("python-traceback", "spring", "aspnet", "node", "php", "go-panic")) else "SMC-015"
                F.append(f"{row}: {meth} {path[:40]} -> {r['status']} signatures {s}")
                if meth == "POST":
                    F.append(f"SMC-017: verbose API error on malformed input ({s})")
        rep["error_triggers"] = errs

    if "debug" not in skip:
        dbg = []
        for path in DEBUG_PATHS:
            r = c.req("GET", path)
            s = sigs(r["body"])
            dbg.append({"path": path, "status": r["status"], "signatures": s, "length": len(r["body"])})
            if r["status"] == 200 and (s or path in ("/actuator/env", "/server-status", "/.env", "/telescope", "/_profiler")):
                F.append(f"SMC-006: debug/diagnostic path {path} returns 200 {s or ''} (verify content; do not call execution endpoints)")
        rep["debug_paths"] = dbg

    if "listing" not in skip:
        lst = []
        for d in LIST_DIRS:
            r = c.req("GET", d)
            if r["status"] == 200 and LISTING_RE.search(r["body"]):
                lst.append(d)
                F.append(f"SMC-003: directory listing at {d}")
        rep["listings"] = lst

    if "host" not in skip:
        canary = f"{m}.example"
        hh = []
        for label, kwargs in [("Host", {"host_header": canary}),
                              ("X-Forwarded-Host", {"headers": {"X-Forwarded-Host": canary}}),
                              ("X-Host", {"headers": {"X-Host": canary}}),
                              ("X-Forwarded-Server", {"headers": {"X-Forwarded-Server": canary}}),
                              ("Forwarded", {"headers": {"Forwarded": f"host={canary}"}}),
                              ("Host+port", {"host_header": f"{c.p.hostname}:{m[:5]}"})]:
            r = c.req("GET", f"/?cb={secrets.token_hex(4)}", **kwargs)
            loc = " ".join(hget(r, "location"))
            needle = m[:5] if label == "Host+port" else canary
            where = [w for w, txt in (("location", loc), ("body", r["body"])) if needle in txt]
            hh.append({"input": label, "status": r["status"], "reflected_in": where})
            if where:
                row = "SMC-012" if label.startswith("Host") else "SMC-013"
                F.append(f"{row}: {label} canary reflected in {where} (status {r['status']})")
        rep["host_header"] = hh

    if args.crlf_url and "crlf" not in skip:
        cp = urlsplit(args.crlf_url)
        cc = C(args.crlf_url, args.insecure, args.timeout, args.delay, args.cookie)
        crl = []
        for tpl in CRLF_PAYLOADS:
            pl = tpl.format(m=m)
            path = ((cp.path or "/") + ("?" + cp.query if cp.query else "")).replace("FUZZ", pl)
            r = cc.req("GET", path)
            injected = [f"{k}: {v}" for k, v in r["headers"] if (k.lower() == "x-injected" and m in v) or (k.lower() == "set-cookie" and v.startswith(m))]
            split = tpl.startswith("%0d%0a%0d%0a") and r["body"].lstrip().startswith(m + "SPLIT")
            crl.append({"payload": pl, "status": r["status"], "injected": injected, "split_body": split})
            if injected:
                F.append(f"SMC-018/SMC-019: CRLF injection with {pl} -> {injected}")
            if split:
                F.append(f"SMC-020: response splitting with {pl}")
        rep["crlf"] = crl
        c.n += cc.n

    F = list(dict.fromkeys(F))
    rep["findings"] = F
    rep["requests"] = c.n
    for f in F or ["none"]:
        print(f"- {f}")
    print(f"requests sent: {c.n}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
