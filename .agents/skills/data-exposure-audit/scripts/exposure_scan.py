#!/usr/bin/env python3
"""Scan pages and well-known files for sensitive data exposure (DE rows).

Per page (--url/--urls, with your own --cookie if given):
  comments, secrets, internal IPs and emails, meta tags, hidden inputs, data-* attributes (DE-001, DE-003, DE-004)
  linked JS on in-scope hosts + sourceMappingURL / .map availability (DE-002, DE-003)
  response headers (DE-012), Set-Cookie flags and decoded values (DE-013)
  autocomplete on sensitive inputs (DE-019), Referrer-Policy + external resources (DE-020)
  links with sensitive parameters (DE-018)
With --files, per host: robots.txt and sitemap.xml (DE-007), debug endpoints (DE-006),
  config/.env (DE-008), backups (DE-009), VCS (DE-010), logs (DE-011) by content signature.
Only the first 64 KB of each file is read (Range header); only redacted excerpts are stored.

Safety: every host must pass scripts/scope_check.sh against the program (--target).
GET only, delay 0.3 s by default.

Example:
  exposure_scan.py --target example.com --workspace ~/Documents/bugbounty --urls pages.txt \
     --cookie 'session=OWN' --files --out artifacts/example.com/data_exposure.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import secrets as pysecrets
import ssl
import subprocess
import sys
import time
from html import unescape
from urllib.parse import parse_qsl, urljoin, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")

SECRET_RES = [(n, re.compile(p)) for n, p in [
    ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("aws-secret", r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("stripe-secret", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    ("github-token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("slack", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("private-key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("mailgun", r"\bkey-[0-9a-f]{32}\b"),
    ("twilio", r"\bSK[0-9a-f]{32}\b"),
    ("conn-string", r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^\s'\"<>:]+:[^\s'\"<>@]+@[^\s'\"<>]+"),
    ("env-secret", r"(?m)^[A-Z0-9_]*(PASSWORD|PASSWD|SECRET|_KEY|TOKEN|API_KEY|PRIVATE)[A-Z0-9_]*=([^\s#]{6,})$"),
    ("generic-secret", r"(?i)['\"]?(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
]]
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|changeme|your[_-]?\w*|example\w*|test\w*|dummy|null|undefined|true|false|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})$")
INTERNAL_IP = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_KEYS = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|todo|fixme|hack|debug|internal|admin|staging|dev\.|test|credential|\.env|root|sql|select |@")
META = re.compile(r"<meta\s+[^>]*>", re.I)
HIDDEN = re.compile(r"<input[^>]+type=['\"]?hidden['\"]?[^>]*>", re.I)
DATA_ATTR = re.compile(r"\sdata-([\w-]+)=['\"]([^'\"]{6,})['\"]", re.I)
ATTR = lambda name: re.compile(r"\s%s\s*=\s*['\"]([^'\"]*)['\"]" % name, re.I)
SENS_NAME = re.compile(r"(?i)token|secret|key|password|passwd|email|phone|ssn|role|admin|user_?id|account|internal|debug|session|auth")
CSRF_NAME = re.compile(r"(?i)csrf|xsrf|authenticity_token|__requestverificationtoken|_token$|nonce|viewstate|eventvalidation")
SENS_PARAM = re.compile(r"(?i)^(token|access_token|id_token|refresh_token|session|sessionid|sid|jsessionid|phpsessid|password|pass|pwd|email|api_?key|key|secret|auth|code|reset|otp|ssn)$")
SENS_HEADERS = ["x-backend-server", "x-upstream", "x-server", "x-host", "x-real-ip", "x-forwarded-server", "x-debug-token",
                "x-debug-token-link", "x-internal", "x-user-id", "x-userid", "x-account-id", "x-request-user", "x-powered-by",
                "server", "x-aspnet-version", "x-runtime", "x-envoy-upstream-service-time", "x-amz-cf-id", "x-cache-key"]
FILES = [
    # (row, path, signature regex on bytes)
    ("DE-008", "/.env", rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+"),
    ("DE-008", "/.env.local", rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+"),
    ("DE-008", "/.env.production", rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+"),
    ("DE-008", "/config.json", rb"(?i)\"(password|secret|apikey|api_key|connectionstring)\""),
    ("DE-008", "/appsettings.json", rb"(?i)\"ConnectionStrings\"|\"Password\""),
    ("DE-008", "/web.config", rb"(?i)<configuration|connectionString="),
    ("DE-008", "/wp-config.php.bak", rb"DB_PASSWORD"),
    ("DE-008", "/config.php.bak", rb"(?i)password"),
    ("DE-008", "/docker-compose.yml", rb"(?m)^services:|image:"),
    ("DE-008", "/.npmrc", rb"_authToken|//registry"),
    ("DE-008", "/.aws/credentials", rb"aws_access_key_id"),
    ("DE-008", "/application.yml", rb"(?m)^spring:|datasource:"),
    ("DE-009", "/backup.zip", rb"^PK\x03\x04"),
    ("DE-009", "/backup.tar.gz", rb"^\x1f\x8b"),
    ("DE-009", "/site.zip", rb"^PK\x03\x04"),
    ("DE-009", "/{host}.zip", rb"^PK\x03\x04"),
    ("DE-009", "/{host}.tar.gz", rb"^\x1f\x8b"),
    ("DE-009", "/db.sql", rb"(?i)CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"),
    ("DE-009", "/dump.sql", rb"(?i)CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"),
    ("DE-009", "/backup.sql", rb"(?i)CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"),
    ("DE-009", "/index.php.bak", rb"<\?php"),
    ("DE-009", "/index.php~", rb"<\?php"),
    ("DE-009", "/.index.php.swp", rb"^b0VIM"),
    ("DE-010", "/.git/HEAD", rb"^ref: refs/|^[0-9a-f]{40}\s*$"),
    ("DE-010", "/.git/config", rb"\[core\]"),
    ("DE-010", "/.svn/entries", rb"^\d+\s*$|^<\?xml"),
    ("DE-010", "/.svn/wc.db", rb"^SQLite format 3"),
    ("DE-010", "/.hg/hgrc", rb"\[paths\]|\[ui\]"),
    ("DE-010", "/.DS_Store", rb"^\x00\x00\x00\x01Bud1"),
    ("DE-011", "/error.log", rb"(?i)\[(error|warn|notice)\]|PHP (Fatal|Warning)|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}.{0,40}(ERROR|WARN|INFO|DEBUG)"),
    ("DE-011", "/access.log", rb"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}|\"(GET|POST) /"),
    ("DE-011", "/debug.log", rb"(?i)\d{4}-\d{2}-\d{2}.{0,40}(ERROR|WARN|INFO|DEBUG)|PHP (Fatal|Warning|Notice)"),
    ("DE-011", "/storage/logs/laravel.log", rb"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+\.(ERROR|INFO|DEBUG)"),
    ("DE-011", "/logs/error.log", rb"(?i)\[(error|warn)\]|\d{4}-\d{2}-\d{2}.{0,40}(ERROR|WARN)"),
    ("DE-011", "/npm-debug.log", rb"(?i)npm (ERR!|verb)"),
    ("DE-006", "/actuator/env", rb"\"propertySources\"|\"activeProfiles\""),
    ("DE-006", "/actuator/heapdump", rb"^JAVA PROFILE"),
    ("DE-006", "/server-status", rb"Apache Server Status"),
    ("DE-006", "/debug/vars", rb"\"memstats\""),
    ("DE-006", "/phpinfo.php", rb"<title>phpinfo\(\)</title>|PHP Version"),
    ("DE-006", "/info.php", rb"<title>phpinfo\(\)</title>|PHP Version"),
    ("DE-006", "/_profiler/phpinfo", rb"PHP Version"),
    ("DE-006", "/health", rb"(?i)\"(db|database|redis|disk|details)\""),
    ("DE-006", "/metrics", rb"(?m)^# (HELP|TYPE) "),
]


def scope_ok(host: str, workspace: str | None, program: str) -> bool:
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"[scope] {host}: {res.stderr.strip() or 'denied'}\n")
    return res.returncode == 0


def redact(s: str, keep: int = 4) -> str:
    s = s.strip()
    return s if len(s) <= keep * 2 + 2 else f"{s[:keep]}...{s[-keep:]} ({len(s)})"


class Fetcher:
    def __init__(self, args):
        self.args, self.n = args, 0

    def get(self, url: str, rng: bool = False) -> dict:
        if self.n:
            time.sleep(self.args.delay)
        self.n += 1
        p = urlsplit(url)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        try:
            if p.scheme == "https":
                ctx = ssl.create_default_context()
                if self.args.insecure:
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.args.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.args.timeout)
            h = {"User-Agent": "Mozilla/5.0 data-exposure-audit", "Accept": "*/*"}
            if self.args.cookie:
                h["Cookie"] = self.args.cookie
            if rng:
                h["Range"] = "bytes=0-65535"
            conn.request("GET", path, headers=h)
            r = conn.getresponse()
            body = r.read(65536 if rng else 3_000_000)
            hdrs = r.getheaders()
            conn.close()
            return {"status": r.status, "headers": hdrs, "body": body}
        except Exception as e:
            return {"status": None, "headers": [], "body": b"", "error": str(e)}


def find_secrets(text: str, where: str, out: list):
    for name, rx in SECRET_RES:
        for m in rx.finditer(text):
            val = m.group(m.lastindex) if name == "generic-secret" and m.lastindex else m.group(0)
            if name == "generic-secret" and PLACEHOLDER.match(val):
                continue
            out.append({"row": "DE-003", "type": name, "where": where, "value": redact(val)})


def scan_page(url: str, r: dict, in_scope_host, F: list, pages: list, fetcher: Fetcher, seen_js: set):
    text = r["body"].decode("utf-8", errors="replace")
    host = urlsplit(url).hostname
    rec: dict = {"url": url, "status": r["status"]}
    hdrs = r["headers"]
    # DE-001 comments
    cm = [unescape(c).strip() for c in COMMENT.findall(text)]
    interesting = [redact(c, 30) for c in cm if COMMENT_KEYS.search(c) and not c.lower().startswith(("[if", "<![endif"))]
    if interesting:
        rec["comments"] = interesting[:20]
        F.append(f"DE-001: {len(interesting)} interesting HTML comments on {url}")
    ips = sorted(set(INTERNAL_IP.findall(text)))
    if ips:
        rec["internal_ips"] = [i[0] if isinstance(i, tuple) else i for i in ips][:10]
        F.append(f"DE-001: internal IPs in page {url}: {rec['internal_ips'][:3]}")
    emails = sorted(set(e for e in EMAIL.findall(text) if not e.lower().endswith((".png", ".jpg", ".svg", ".gif"))))
    if emails:
        rec["emails"] = [redact(e, 3) for e in emails[:10]]
    found: list = []
    find_secrets(text, url, found)
    # DE-004 meta, hidden, data attrs
    metas = []
    for tag in META.findall(text):
        nm = (ATTR("name").search(tag) or ATTR("property").search(tag) or ATTR("http-equiv").search(tag))
        ct = ATTR("content").search(tag)
        if nm and ct and SENS_NAME.search(nm.group(1)) and not CSRF_NAME.search(nm.group(1)):
            metas.append(f"{nm.group(1)}={redact(ct.group(1))}")
    hidden = []
    for tag in HIDDEN.findall(text):
        nm, val = ATTR("name").search(tag), ATTR("value").search(tag)
        if nm and val and val.group(1) and not CSRF_NAME.search(nm.group(1)) and SENS_NAME.search(nm.group(1)):
            hidden.append(f"{nm.group(1)}={redact(val.group(1))}")
    datas = [f"data-{k}={redact(v)}" for k, v in DATA_ATTR.findall(text) if SENS_NAME.search(k)]
    for label, lst in (("meta", metas), ("hidden_inputs", hidden), ("data_attrs", datas)):
        if lst:
            rec[label] = lst[:15]
            F.append(f"DE-004: sensitive-looking {label} on {url}: {lst[:3]}")
    # DE-019 autocomplete
    ac = []
    for tag in re.findall(r"<input[^>]*>", text, re.I):
        tm, nm_, am = ATTR("type").search(tag), ATTR("name").search(tag), ATTR("autocomplete").search(tag)
        typ = tm.group(1) if tm else "text"
        name = nm_.group(1) if nm_ else ""
        auto = am.group(1).lower() if am else ""
        sens = typ.lower() == "password" or re.search(r"(?i)card|cc-?num|cvv|cvc|ssn|otp|pin\b", name)
        if sens and auto not in ("off", "new-password", "one-time-code", "current-password", "cc-number", "cc-csc"):
            ac.append(f"{name or typ} (autocomplete='{auto or 'unset'}')")
    if ac:
        rec["autocomplete"] = ac
        F.append(f"DE-019 info: sensitive inputs without explicit autocomplete on {url}: {ac[:3]}")
    # DE-012 headers
    hs = [(k, v) for k, v in hdrs if k.lower() in SENS_HEADERS or INTERNAL_IP.search(v)]
    if hs:
        rec["headers"] = [f"{k}: {v}" for k, v in hs]
        lowered = [(k.lower(), v) for k, v in hs]
        if any(INTERNAL_IP.search(v) for _, v in hs) or any(k in ("x-debug-token", "x-debug-token-link", "x-user-id", "x-backend-server", "x-upstream", "x-internal") for k, _ in lowered):
            F.append(f"DE-012: sensitive response headers on {url}: {rec['headers'][:4]}")
    # DE-013 cookies
    cks = []
    for k, v in hdrs:
        if k.lower() != "set-cookie":
            continue
        name, _, rest = v.partition("=")
        val = rest.split(";")[0]
        attrs = [a.strip().lower() for a in v.split(";")[1:]]
        flags = [f for f, ok in (("Secure", "secure" in attrs), ("HttpOnly", "httponly" in attrs),
                                  ("SameSite", any(a.startswith("samesite") for a in attrs))) if not ok]
        decoded = ""
        try:
            raw = base64.b64decode(val + "=" * (-len(val) % 4), altchars=b"-_")
            if sum(32 <= b < 127 for b in raw) / max(len(raw), 1) > 0.9:
                decoded = raw.decode(errors="replace")
        except Exception:
            pass
        pii = bool(EMAIL.search(val) or EMAIL.search(decoded) or re.search(r"(?i)role|admin|email|user", decoded))
        cks.append({"name": name.strip(), "missing": flags, "pii_in_value": pii})
        if pii:
            F.append(f"DE-013: cookie {name.strip()} carries readable user data")
        if flags and re.search(r"(?i)sess|auth|token|jwt|sid", name):
            F.append(f"DE-013: auth-looking cookie {name.strip()} missing {flags}")
    if cks:
        rec["cookies"] = cks
    # DE-018 links with sensitive params; DE-020 referrer policy + external resources
    links = set(re.findall(r"(?:href|src|action)=['\"]([^'\"]+)['\"]", text, re.I))
    sens_links = []
    for l in links:
        q = urlsplit(urljoin(url, l)).query
        bad = [k for k, _ in parse_qsl(q) if SENS_PARAM.match(k)]
        if bad:
            sens_links.append(f"{redact(urljoin(url, l), 40)} params={bad}")
    page_sensitive = any(SENS_PARAM.match(k) for k, _ in parse_qsl(urlsplit(url).query))
    if sens_links:
        rec["sensitive_links"] = sens_links[:10]
        F.append(f"DE-018: links with sensitive GET parameters on {url}: {sens_links[:2]}")
    rp = next((v for k, v in hdrs if k.lower() == "referrer-policy"), None)
    m = re.search(r"<meta[^>]+name=['\"]referrer['\"][^>]+content=['\"]([^'\"]+)", text, re.I)
    rp = rp or (m.group(1) if m else None)
    ext = sorted({urlsplit(urljoin(url, l)).hostname for l in re.findall(r"(?:src|href)=['\"](https?://[^'\"]+)", text, re.I)
                  if urlsplit(l).hostname and not in_scope_host(urlsplit(l).hostname)})
    rec["referrer_policy"], rec["external_hosts"] = rp, ext[:20]
    if (page_sensitive or sens_links) and ext and (not rp or rp.lower() in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin")):
        F.append(f"DE-020: page with sensitive URL data loads {len(ext)} external hosts with Referrer-Policy '{rp}' ({url})")
    # DE-002 linked JS and source maps
    scripts = [urljoin(url, s) for s in re.findall(r"<script[^>]+src=['\"]([^'\"]+)['\"]", text, re.I)]
    js_recs = []
    for js in scripts:
        jh = urlsplit(js).hostname
        if js in seen_js or not jh or not in_scope_host(jh):
            continue
        seen_js.add(js)
        jr = fetcher.get(js)
        jt = jr["body"].decode("utf-8", errors="replace")
        jf: list = []
        find_secrets(jt, js, jf)
        found += jf
        sm = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", jt[-3000:])
        map_url = urljoin(js, sm.group(1)) if sm and not sm.group(1).startswith("data:") else js + ".map"
        mr = fetcher.get(map_url, rng=True)
        map_ok = mr["status"] in (200, 206) and (b'"sources"' in mr["body"] or b'"mappings"' in mr["body"])
        if map_ok:
            n_src = mr["body"].count(b'",') if b'"sourcesContent"' in mr["body"] else 0
            F.append(f"DE-002: source map reachable {map_url}{' with sourcesContent' if b'sourcesContent' in mr['body'] else ''}")
        js_recs.append({"js": js, "status": jr["status"], "secrets": len(jf), "source_map": map_url if map_ok else None})
    if js_recs:
        rec["scripts"] = js_recs
    if found:
        rec["secrets"] = found
        for s in found:
            F.append(f"DE-003: {s['type']} in {s['where']}: {s['value']}")
    pages.append(rec)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--urls")
    ap.add_argument("--cookie", help="own session cookie")
    ap.add_argument("--files", action="store_true", help="check robots/sitemap and sensitive file paths per host")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    urls = list(args.url) + ([l.strip() for l in open(args.urls, encoding="utf-8") if l.strip() and not l.startswith("#")] if args.urls else [])
    urls = [u if "://" in u else "https://" + u for u in urls]
    if not urls:
        sys.exit("give --url or --urls")
    target = args.target.lower()
    allowed: dict[str, bool] = {}

    def in_scope_host(h: str) -> bool:
        h = h.lower()
        if h not in allowed:
            allowed[h] = (h == target or h.endswith("." + target)) and scope_ok(h, args.workspace, target)
        return allowed[h]

    urls = [u for u in urls if in_scope_host(urlsplit(u).hostname or "")]
    if not urls:
        sys.exit("no in-scope URLs")
    fetcher = Fetcher(args)
    F: list[str] = []
    pages: list = []
    seen_js: set = set()
    for u in urls:
        r = fetcher.get(u)
        if r.get("error"):
            print(f"[error] {u}: {r['error']}")
            continue
        scan_page(u, r, in_scope_host, F, pages, fetcher, seen_js)
        print(f"[page] {r['status']} {u}")

    files_out = []
    if args.files:
        bases = {}
        for u in urls:
            p = urlsplit(u)
            bases.setdefault(p.hostname, f"{p.scheme}://{p.netloc}")
        for host, base in bases.items():
            soft = fetcher.get(f"{base}/de-{pysecrets.token_hex(4)}.txt", rng=True)
            soft_hash = hashlib.sha1(soft["body"]).hexdigest() if soft["status"] == 200 else None
            rb = fetcher.get(base + "/robots.txt")
            if rb["status"] == 200:
                lines = [l.split(":", 1)[1].strip() for l in rb["body"].decode(errors="replace").splitlines() if l.lower().startswith(("disallow", "allow")) and ":" in l]
                sens = [l for l in lines if re.search(r"(?i)admin|backup|private|internal|staging|dev|test|secret|config|api|debug|old|tmp|log|\.sql|\.zip|token|key", l)]
                files_out.append({"row": "DE-007", "path": "/robots.txt", "entries": len(lines), "interesting": sens[:30]})
                if sens:
                    F.append(f"DE-007: robots.txt on {host} lists sensitive-looking paths: {sens[:5]}")
            sm = fetcher.get(base + "/sitemap.xml")
            if sm["status"] == 200:
                locs = re.findall(rb"<loc>\s*([^<]+)</loc>", sm["body"])
                bad = [l.decode(errors="replace") for l in locs if re.search(rb"(?i)[?&](token|key|session|email|password|code)=|/(admin|internal|staging|private)/", l)]
                files_out.append({"row": "DE-007", "path": "/sitemap.xml", "urls": len(locs), "interesting": bad[:20]})
                if bad:
                    F.append(f"DE-007: sitemap.xml on {host} has sensitive URLs: {[redact(b, 40) for b in bad[:3]]}")
            for row, path, sig in FILES:
                path = path.replace("{host}", host)
                r = fetcher.get(base + path, rng=True)
                if r["status"] not in (200, 206) or not r["body"]:
                    continue
                if soft_hash and hashlib.sha1(r["body"]).hexdigest() == soft_hash:
                    continue
                if not re.search(sig, r["body"][:65536]):
                    continue
                first = r["body"][:120].decode("utf-8", errors="replace").splitlines()[0] if r["body"] else ""
                sec: list = []
                find_secrets(r["body"].decode("utf-8", errors="replace"), base + path, sec)
                size = next((v for k, v in r["headers"] if k.lower() in ("content-range", "content-length")), "")
                files_out.append({"row": row, "path": path, "status": r["status"], "size": size,
                                  "first_line": redact(first, 25), "secrets": len(sec)})
                F.append(f"{row}: {base}{path} exposed (size {size}){' with ' + str(len(sec)) + ' secret patterns' if sec else ''}")

    F = list(dict.fromkeys(F))
    rep = {"target": target, "requests": fetcher.n, "findings": F, "pages": pages, "files": files_out}
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {fetcher.n}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
