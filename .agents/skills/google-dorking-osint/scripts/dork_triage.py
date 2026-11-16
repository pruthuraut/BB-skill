#!/usr/bin/env python3
"""Rank URLs collected from dork results and optionally verify in-scope ones.

Input: a file of URLs (one per line) copied from search results.
Each URL is classified (secrets/env, database dump, VCS, logs, backups, config,
API docs, admin/login, debug, documents, staging/dev hosts, third-party leak) and
given a priority. With --verify, URLs on hosts that pass the program's scope gate
get one HEAD request (falling back to a GET of the first 2 KB): status, content
type, size, and a redacted first line for text. Third-party and out-of-scope URLs
are never requested.

Example:
  dork_triage.py --target example.com --urls found.txt --verify --out artifacts/example.com/dork_triage.json
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
RULES = [
    # (category, priority 1=highest, related GD rows, regex on URL)
    ("env/secrets file", 1, "GD-007/GD-029", r"\.env(\.\w+)?$|/\.aws/credentials|\.npmrc$|\.pgpass$|id_rsa|\.pem$|\.key$|\.p12$|\.pfx$"),
    ("database dump", 1, "GD-006", r"\.(sql|sql\.gz|db|sqlite3?|mdb|dump|bak\.sql)$"),
    ("vcs metadata", 1, "GD-028", r"/\.(git|svn|hg|bzr)(/|$)|\.DS_Store$"),
    ("logs", 2, "GD-005", r"\.log(\.\d+)?$|/logs?/|laravel\.log|debug\.log"),
    ("backup/archive", 2, "GD-013", r"\.(bak|old|orig|backup|swp|save|tmp|~)$|\.(zip|tar|tar\.gz|tgz|rar|7z)$"),
    ("config", 2, "GD-008/GD-011/GD-012/GD-021", r"\.(ya?ml|conf|cfg|ini|config|properties|toml)$|/config(/|\.|$)|web\.config|wp-config|settings\.py|appsettings"),
    ("debug/diagnostics", 2, "GD-024", r"/debug|/actuator|/server-status|/server-info|phpinfo|/_profiler|/trace\.axd|/elmah\.axd|/console"),
    ("api docs", 3, "GD-032/GD-033/GD-022", r"swagger|api-docs|openapi|graphi?ql|playground|redoc|/api(/|$|\?)"),
    ("admin/login", 3, "GD-016..GD-020/GD-030/GD-031", r"/admin|/login|/signin|/dashboard|wp-admin|wp-login|phpmyadmin|/manager/html|/cpanel"),
    ("directory listing", 3, "GD-014", r"://[^/]+/.+/$"),
    ("staging/dev host", 3, "GD-025..GD-027", r"://[^/]*(staging|stage|dev|test|qa|uat|preprod|sandbox)[\w-]*\."),
    ("upload", 3, "GD-023", r"/uploads?/"),
    ("data export", 2, "GD-002/GD-009", r"\.(csv|xlsx?|json)$"),
    ("documents", 4, "GD-001/GD-003/GD-004", r"\.(pdf|docx?|pptx?|odt|txt|rtf)$"),
]
THIRD_PARTY = {"pastebin.com": "GD-040", "github.com": "GD-041..GD-044", "gist.github.com": "GD-045", "stackoverflow.com": "GD-046",
               "trello.com": "GD-047", "slack.com": "GD-048", "notion.so": "GD-049", "notion.site": "GD-049", "paste.ee": "GD-040",
               "hastebin.com": "GD-040", "justpaste.it": "GD-040", "rentry.co": "GD-040", "atlassian.net": "X:atlassian",
               "docs.google.com": "X:google docs", "drive.google.com": "X:google docs", "postman.com": "X:postman"}
SENSITIVE_QUERY = re.compile(r"(?i)[?&](token|access_token|api_?key|key|secret|password|pass|session|sid|auth|code|signature)=")


def scope_ok(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    return res.returncode == 0


def check(url, timeout, insecure):
    p = urlsplit(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    out = {}
    for method in ("HEAD", "GET"):
        try:
            conn = (http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ctx) if p.scheme == "https"
                    else http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout))
            h = {"User-Agent": "Mozilla/5.0 osint-triage"}
            if method == "GET":
                h["Range"] = "bytes=0-2047"
            conn.request(method, path, headers=h)
            r = conn.getresponse()
            body = r.read(2048) if method == "GET" else b""
            out = {"method": method, "status": r.status, "type": r.getheader("Content-Type"),
                   "size": r.getheader("Content-Length") or r.getheader("Content-Range")}
            if body and out["type"] and re.search(r"text|json|xml|yaml|javascript", out["type"] or ""):
                first = body.decode("utf-8", errors="replace").strip().splitlines()[0][:80] if body.strip() else ""
                out["first_line"] = re.sub(r"(?i)(password|secret|token|key)([\"'=: ]+)\S+", r"\1\2<redacted>", first)
            conn.close()
            if method == "HEAD" and r.status in (405, 501, 403) or (method == "HEAD" and not out.get("type")):
                continue
            break
        except Exception as e:
            out = {"method": method, "error": str(e)[:100]}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="program name (folder of scope.txt)")
    ap.add_argument("--workspace")
    ap.add_argument("--urls", required=True)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    target = a.target.lower()
    urls = list(dict.fromkeys(l.strip() for l in open(a.urls, encoding="utf-8") if l.strip().startswith("http")))
    scope_cache: dict[str, bool] = {}
    rows = []
    for u in urls:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        tp = next((v for k, v in THIRD_PARTY.items() if host == k or host.endswith("." + k)), None)
        cats = [(c, pr, gd) for c, pr, gd, rx in RULES if re.search(rx, u, re.I)]
        if tp:
            cats.append(("third-party leak", 2, tp))
        if SENSITIVE_QUERY.search(u):
            cats.append(("secret in URL", 1, "GD-034..GD-037"))
        pr = min([c[1] for c in cats], default=5)
        in_scope = None
        if not tp:
            if host not in scope_cache:
                scope_cache[host] = scope_ok(host, a.workspace, target)
            in_scope = scope_cache[host]
        rows.append({"url": u, "host": host, "priority": pr, "categories": [c[0] for c in cats], "rows": sorted({c[2] for c in cats}),
                     "third_party": bool(tp), "in_scope": in_scope})
    rows.sort(key=lambda r: (r["priority"], r["url"]))
    if a.verify:
        n = 0
        for r in rows:
            if r["third_party"] or not r["in_scope"]:
                continue
            if n:
                time.sleep(a.delay)
            n += 1
            r["verify"] = check(r["url"], a.timeout, a.insecure)
        print(f"verified {n} in-scope URLs")
    for r in rows:
        v = r.get("verify") or {}
        scope = "3rd-party" if r["third_party"] else ("in-scope" if r["in_scope"] else "OUT-OF-SCOPE")
        status = f" -> {v.get('status')} {v.get('type') or ''} {v.get('size') or ''}".rstrip() if v else ""
        print(f"P{r['priority']} [{scope}] {', '.join(r['categories']) or 'uncategorized'}: {r['url']}{status}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump({"target": target, "results": rows}, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
