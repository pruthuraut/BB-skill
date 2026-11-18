#!/usr/bin/env python3
"""Deep link, URL scheme and universal link testing for an authorized iOS app.

Modes:
  --cases   Build a test matrix from ios_static.py output (CFBundleURLTypes schemes, applinks: domains,
            route strings and parameter names found in the binary). Writes cases JSON and an HTML launcher
            page: open it in Safari on the test device and tap each link (the realistic "link from a web
            page" source). Sends nothing.
  --aasa    For each applinks:/webcredentials: domain, run the scope gate, then one GET for
            /.well-known/apple-app-site-association (and the root fallback). Redirects are recorded, not
            followed (Apple does not follow them). Checks status, content type, size, JSON, appID match,
            wildcard paths and exclusions.
  --run     Open each case on the test device: needs --active-approved and --test-device; uses
            ios_device.py's opener (SSH uiopen on a jailbroken device, or --via simctl on a simulator).

Payloads are harmless markers: a unique token, document.title changes, example.org redirect targets,
a single quote, and ../ paths to world-readable files. Oversize and format-string cases (DoS class) are
only added with --include-dos, and still need approval to run.

Usage:
  ios_deeplink.py --static artifacts/<bundle>/ios-static.json --cases
  ios_deeplink.py --static artifacts/<bundle>/ios-static.json --aasa --workspace ~/Documents/bugbounty --program NAME
  ios_deeplink.py --static ... --run --active-approved --test-device UDID --ssh root@127.0.0.1 --ssh-port 2222 --category redirect
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ios_common import ARTIFACTS, Finding, ids, scope_ok, sort_findings, write_json  # noqa: E402

UA = "Mozilla/5.0 (compatible; ios-audit-aasa/1.0)"
URLISH = re.compile(r"(?i)url|redirect|return|next|continue|goto|dest|target|link|callback|uri|web")
FILEISH = re.compile(r"(?i)file|path|doc|page|template|resource|image|attachment")
SENSITIVE_ROUTE = re.compile(r"(?i)account|settings|admin|profile|payment|pay|transfer|wallet|password|delete|withdraw|"
                             r"purchase|buy|subscribe|checkout|order|reset|verify|confirm|token|login|auth|kyc|card")
TEST_BASE = os.environ.get("IOS_AASA_TEST_BASE", "").rstrip("/")  # local test harness only


# --------------------------------------------------------------------------- cases
def build_cases(static: dict, callback_host: str, include_dos: bool, max_routes: int) -> list[dict]:
    schemes = [s["scheme"] for s in static.get("app", {}).get("url_schemes", [])
               if not re.match(r"^(fb\d+|com\.googleusercontent\.apps\.|msauth|db-)", s["scheme"])]
    dl = static.get("deeplinks", {})
    params = dl.get("params_seen") or ["url", "redirect", "next", "token", "path"]
    routes = [r for r in dl.get("routes", []) if "://" not in r][:max_routes]
    full = [r for r in dl.get("routes", []) if "://" in r][:max_routes]
    domains = dl.get("applinks_domains", [])
    mark = "iosdl" + secrets.token_hex(3)
    cases: list[dict] = []

    def add(cat, url, note, pats):
        cases.append({"id": f"DL-{len(cases) + 1:04d}", "category": cat, "url": url, "note": note,
                      "checklist": ids(*pats, limit=6)})

    bases = []
    for s in schemes:
        bases.append(f"{s}://")
        for r in routes:
            bases.append(f"{s}:/{r}" if r.startswith("/") else f"{s}://{r}")
    bases += full
    seen = set()
    bases = [b for b in bases if not (b in seen or seen.add(b))]
    for b in bases:
        add("baseline", b, "app opens the expected screen; no crash", [r"custom URL schemes are properly validated"])
        if SENSITIVE_ROUTE.search(b):
            add("auth", b, "open while logged out and while locked by biometrics: the screen must require auth",
                [r"bypass authentication", r"authentication bypass", r"bypass biometric", r"internal feature access",
                 r"authorization before executing sensitive"])
    q = lambda base: base + ("&" if "?" in base else "?")  # noqa: E731
    for b in bases[: max_routes + len(schemes)]:
        for p in params:
            add("param", f"{q(b)}{p}={mark}", f"marker '{mark}' must not reach logs, UI unescaped, or other apps",
                [r"parameter injection", r"parameters can be manipulated", r"logged without sanitization"])
            if URLISH.search(p):
                add("redirect", f"{q(b)}{p}=https://{callback_host}/{mark}", "app must not open or load an external host",
                    [r"open redirect", r"callback URLs", r"redirect chains", r"SSRF", r"bypass app Transport"])
                add("javascript", f"{q(b)}{p}=" + urllib.parse.quote(f"javascript:document.title='{mark}'", safe=""),
                    "a WebView must not execute javascript: URLs", [r"JavaScript execution in WebView", r"inject JavaScript into WKWebView"])
                add("file", f"{q(b)}{p}=" + urllib.parse.quote("file:///etc/hosts", safe=""), "a WebView must not load file:// URLs",
                    [r"file access vulnerability", r"file URL scheme"])
                add("http", f"{q(b)}{p}=http://{callback_host}/{mark}", "cleartext URL must be refused",
                    [r"bypass app Transport Security"])
            if FILEISH.search(p) or p in ("path", "file", "page"):
                add("traversal", f"{q(b)}{p}=" + urllib.parse.quote("../../../../../../etc/hosts", safe=""),
                    "path must be normalised and confined", [r"path traversal", r"protected app resources"])
            add("xss", f"{q(b)}{p}=" + urllib.parse.quote(f"\"><img src=x onerror=document.title='{mark}'>", safe=""),
                "reflected value must be escaped in any WebView", [r"XSS via parameter reflection", r"sanitize input"])
            add("sqli", f"{q(b)}{p}={mark}%27", "a single quote must not change behaviour or error", [r"SQL injection in parameters"])
        add("fragment", f"{b}#{mark}", "fragment must not change app state", [r"URL fragment parameters"])
        add("encoding", f"{q(b)}{params[0]}=%252e%252e%252f{mark}", "double encoding must be decoded once", [r"URL encoding and decoding"])
    for s in schemes:
        for u in (f"{s}:", f"{s}:////", f"{s}://%00", f"{s}://@{callback_host}", f"{s}://{callback_host}%2F%2E%2E",
                  f"{s.upper()}://", f"{s}://аdmin"):
            add("malformed", u, "no crash and no data shown", [r"malformed URLs", r"scheme confusion", r"parsing handles malformed"])
        if include_dos:
            add("dos", f"{s}://x?{params[0]}=" + "A" * 20000, "DoS class: approval required", [r"excessive parameter sizes", r"denial of service"])
            add("dos", f"{s}://x?{params[0]}=%25@%25@%25@%25n", "format string: approval required", [r"format string"])
    for d in domains:
        add("universal", f"https://{d}/", "opens the app (not Safari) only for declared paths", [r"universal links", r"universal link validation"])
        for r in routes[:20]:
            add("universal", f"https://{d}{r if r.startswith('/') else '/' + r}", "check app vs Safari handling",
                [r"universal links properly handle multiple matching patterns"])
    return cases


def write_launcher(cases: list[dict], path: str, bundle: str) -> None:
    rows = []
    cat = None
    for c in cases:
        if c["category"] != cat:
            cat = c["category"]
            rows.append(f"<h2>{html.escape(cat)}</h2>")
        rows.append(f'<p><a href="{html.escape(c["url"], quote=True)}">{html.escape(c["id"])}</a> '
                    f'<code>{html.escape(c["url"][:160])}</code><br><small>{html.escape(c["note"])} '
                    f'[{html.escape(", ".join(c["checklist"]))}]</small></p>')
    doc = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Deep link tests</title><style>body{{font:15px -apple-system,sans-serif;margin:16px}}code{{word-break:break-all}}"
           "a{font-weight:600}</style>"
           f"<h1>Deep link tests: {html.escape(bundle)}</h1><p>Authorized test device only. Tap one link at a time and record "
           "the result with ios_checklist.py.</p>" + "\n".join(rows))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------- AASA
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str) -> dict:
    if TEST_BASE:
        url = TEST_BASE + "/" + url.split("://", 1)[1]
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=15) as r:
            body = r.read(512 * 1024 + 1)
            return {"url": url, "status": r.status, "content_type": r.headers.get("Content-Type", ""), "body": body}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "content_type": e.headers.get("Content-Type", "") if e.headers else "",
                "location": e.headers.get("Location") if e.headers else None, "body": b""}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"url": url, "status": None, "error": str(e)[:160], "body": b""}


def check_aasa(domain: str, app_id: str | None, findings: list) -> dict:
    res = {"domain": domain}
    r = fetch(f"https://{domain}/.well-known/apple-app-site-association")
    if r.get("status") != 200:
        r2 = fetch(f"https://{domain}/apple-app-site-association")
        res["well_known_status"] = r.get("status")
        r = r2 if r2.get("status") == 200 else r
    res.update(status=r.get("status"), url=r.get("url"), content_type=r.get("content_type"), location=r.get("location"),
               size=len(r.get("body") or b""))

    def f(rule, sev, title, *pats):
        findings.append(Finding(rule, sev, title, domain, "", ids(*pats)).as_dict())
    if r.get("status") in (301, 302, 303, 307, 308):
        f("aasa-redirect", "medium", f"AASA on {domain} redirects (Apple does not follow redirects)", r"apple-app-site-association")
    if r.get("status") != 200:
        f("aasa-missing", "medium", f"no AASA file on {domain} (status {r.get('status')})", r"apple-app-site-association",
          r"universal links validate the associated domain")
        return res
    body = r["body"]
    if len(body) > 128 * 1024:
        f("aasa-too-large", "low", "AASA larger than 128 KB", r"apple-app-site-association")
    if "json" not in (r.get("content_type") or "").lower():
        f("aasa-content-type", "low", f"AASA content type is {r.get('content_type')!r}, not application/json",
          r"AASA file is served over HTTPS with proper content-type")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        if body[:2] == b"\x30\x82":
            f("aasa-signed-legacy", "info", "signed (PKCS#7) AASA: legacy format", r"apple-app-site-association")
        else:
            f("aasa-bad-json", "medium", "AASA does not parse as JSON", r"apple-app-site-association")
        return res
    details = (data.get("applinks") or {}).get("details") or []
    app_ids, wild, nots = [], [], []
    for d in details:
        ids_ = d.get("appIDs") or ([d["appID"]] if d.get("appID") else [])
        app_ids += ids_
        for p in d.get("paths") or []:
            if p in ("*", "/*", "/") or p.startswith("*"):
                wild.append(p)
            if p.startswith("NOT "):
                nots.append(p)
        for c in d.get("components") or []:
            if c.get("/") in ("*", "/*") and not c.get("exclude"):
                wild.append(json.dumps(c))
            if c.get("exclude"):
                nots.append(json.dumps(c))
    res.update(app_ids=app_ids, wildcard_paths=wild[:20], exclusions=nots[:20],
               webcredentials=(data.get("webcredentials") or {}).get("apps"), appclips=(data.get("appclips") or {}).get("apps"))
    if app_id and app_id not in app_ids:
        f("aasa-appid-mismatch", "high", f"AASA on {domain} does not list {app_id}", r"validate app ID in AASA",
          r"universal links verification bypass")
    if wild:
        f("aasa-wildcard", "low", f"AASA routes every path to the app ({', '.join(wild[:3])}): every link handler must validate input",
          r"universal links properly handle multiple matching patterns", r"apple-app-site-association file security")
    if len(set(app_ids)) > 1:
        f("aasa-multiple-apps", "info", f"AASA lists {len(set(app_ids))} apps", r"apple-app-site-association")
    return res


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--static", required=True, help="ios_static.py JSON report")
    ap.add_argument("--cases", action="store_true")
    ap.add_argument("--aasa", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--domain", action="append", default=[], help="extra associated domain to check")
    ap.add_argument("--callback-host", default="example.org", help="host you control for redirect cases (default example.org)")
    ap.add_argument("--include-dos", action="store_true")
    ap.add_argument("--max-routes", type=int, default=25)
    ap.add_argument("--category", action="append", default=[], help="with --run: only these categories")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--workspace")
    ap.add_argument("--program")
    ap.add_argument("--active-approved", action="store_true")
    ap.add_argument("--test-device")
    ap.add_argument("--ssh")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--via", choices=["ssh", "simctl"], default="ssh")
    ap.add_argument("--out")
    args = ap.parse_args()
    with open(args.static, encoding="utf-8") as fh:
        static = json.load(fh)
    bundle = static.get("app", {}).get("bundle_id") or "app"
    team = (static.get("entitlements") or {}).get("team_id")
    app_id = f"{team}.{bundle}" if team else None
    outdir = os.path.join(ARTIFACTS, bundle)
    report = {"bundle": bundle, "app_id": app_id}
    findings: list[dict] = []

    if args.cases or args.run:
        cases = build_cases(static, args.callback_host, args.include_dos, args.max_routes)
        report["cases"] = cases
        report["cases_by_category"] = {c: sum(1 for x in cases if x["category"] == c) for c in dict.fromkeys(x["category"] for x in cases)}
        launcher = os.path.join(outdir, "deeplinks.html")
        write_launcher(cases, launcher, bundle)
        report["launcher"] = launcher
        print(f"{len(cases)} cases {report['cases_by_category']}\nlauncher: {launcher} (open in Safari on the test device)")

    if args.aasa:
        domains = list(dict.fromkeys((static.get("deeplinks") or {}).get("applinks_domains", []) + args.domain +
                                     [d.split(":", 1)[1].split("?")[0] for d in (static.get("entitlements") or {}).get("associated_domains", [])
                                      if d.startswith("webcredentials:")]))
        report["aasa"] = []
        for d in domains:
            ok, msg = scope_ok(d, args.workspace, args.program)
            if not ok:
                report["aasa"].append({"domain": d, "skipped": msg})
                print(f"skip {d}: {msg}")
                continue
            res = check_aasa(d, app_id, findings)
            report["aasa"].append(res)
            print(f"{d}: status {res.get('status')} appIDs {res.get('app_ids')} wildcard {bool(res.get('wildcard_paths'))}")
            time.sleep(0.5)

    if args.run:
        if not args.active_approved:
            sys.exit("refusing: --run needs --active-approved (approval for these deep link checks)")
        import ios_device  # noqa: E402
        dev_args = argparse.Namespace(test_device=args.test_device, via=args.via, ssh=args.ssh, ssh_port=args.ssh_port)
        ios_device.require_device(dev_args)
        todo = [c for c in report["cases"] if (not args.category or c["category"] in args.category) and c["category"] != "dos"][:args.limit]
        for c in todo:
            print(f"[{c['id']}] {c['category']}: {c['note']}")
            ios_device.open_url(dev_args, c["url"])
            c["opened_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            time.sleep(args.delay)
        report["run"] = {"opened": len(todo), "note": "record what the app did for each case (screen, crash, WebView load)"}

    report["findings"] = sort_findings(findings)
    out = args.out or os.path.join(outdir, "ios-deeplinks.json")
    write_json(out, report)
    print(f"findings: {len(findings)}  report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
