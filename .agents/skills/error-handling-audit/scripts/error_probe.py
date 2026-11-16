#!/usr/bin/env python3
"""Crafted-input error handling probe (EH rows).

Modes:
  default   For each query/form/JSON parameter of --url (or the FUZZ marker), send a fixed
            set of malformed variants (~18) plus method, content-type, malformed-JSON, and
            random-path requests. Each response is fingerprinted for stack traces, DB errors
            (with query text), framework versions, internal IPs/paths/hosts, debug pages,
            default error pages, and status-code misuse (5xx for client faults, 2xx with errors).
  --enum    Compare a known-valid (your own) and a known-invalid value for the FUZZ
            parameter, N times each: status, length, normalized body, and median time (EH-006).
  --graphql Send malformed GraphQL documents and inspect errors[] (EH-010).
Signatures for stacks/debug/DB come from server-config-audit/scripts/misconfig_probe.py.

Safety: scope-gated (host checked against the program's scope.txt); bounded request counts; delay 0.3 s.

Examples:
  error_probe.py --target example.com --url 'https://api.example.com/v1/items?id=5' --cookie 'session=OWN'
  error_probe.py --target example.com --url https://api.example.com/v1/items --method POST --json-body '{"name":"x","qty":1}'
  error_probe.py --target example.com --url https://www.example.com/login --method POST \
     --form 'email=FUZZ&password=Wrong1!' --enum --valid me@example.test --invalid nobody123@example.test
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import ssl
import statistics
import subprocess
import sys
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

# Windows consoles (cp1252) cannot print every character in payloads; never crash on output.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
_spec = importlib.util.spec_from_file_location("misconfig_probe", os.path.join(REPO, ".agents", "skills", "server-config-audit", "scripts", "misconfig_probe.py"))
_mp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mp)
SIG_RE = dict(_mp.SIG_RE)
SIG_RE["db-query"] = re.compile(r"(?is)(SELECT\s+.{1,200}?\s+FROM\s+\w+|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET\s+|WHERE\s+\w+\s*=\s*'?)")
SIG_RE["internal-host"] = re.compile(r"\b[\w-]+\.(internal|local|lan|corp|intra|svc\.cluster\.local)\b", re.I)
DEBUG_KEYS = {"django-debug", "werkzeug-debugger", "laravel", "symfony", "rails"}
STACK_KEYS = {"python-traceback", "spring", "aspnet", "node", "php", "go-panic"}
VERSION_RE = re.compile(r"(?i)(Apache Tomcat/[\d.]+|Jetty[:/ (]+[\d.]+|nginx/[\d.]+|Apache/[\d.]+|Microsoft-IIS/[\d.]+|IIS [\d.]+ Detailed Error|"
                        r"PHP/[\d.]+|X-Powered-By: [^\r\n]+|Django [\d.]+|Laravel v?[\d.]+|Spring Boot v?[\d.]+|Express [\d.]+|"
                        r"Werkzeug/[\d.]+|Python/[\d.]+|ASP\.NET Version:[\d.]+|Microsoft \.NET Framework Version:[\d.]+|Ruby [\d.]+|Rails [\d.]+)")
DEFAULT_PAGES = {
    "apache": r"<address>Apache/[\d.]+", "nginx": r"<center>nginx(/[\d.]+)?</center>", "iis": r"HTTP Error \d{3}\.\d+ -|IIS \d+\.\d+ Detailed Error",
    "tomcat": r"Apache Tomcat/[\d.]+|<h1>HTTP Status \d{3}", "jetty": r"Powered by Jetty://", "express": r"<pre>Cannot (GET|POST|PUT|DELETE) /",
    "django": r"Page not found \(404\)|Using the URLconf", "werkzeug": r"The requested URL was not found on the server\. If you entered the URL manually",
    "spring": r"Whitelabel Error Page", "rails": r"The page you were looking for doesn't exist", "aspnet-core": r"Developer Exception Page|An unhandled exception occurred while processing the request",
}
DEFAULT_RE = {k: re.compile(v, re.I) for k, v in DEFAULT_PAGES.items()}
ERROR_WORDS = re.compile(r'(?i)"(error|errors|exception|fault)"\s*:|\berror\b.{0,40}\b(invalid|failed|exception)')
VARIANTS = [
    ("quote", "'"), ("dquote", '"'), ("backslash", "\\"), ("template", "{{${"), ("nullbyte", "\x00"),
    ("long", "A" * 5000), ("negative", "-1"), ("huge", "99999999999999999999999"), ("nonnumeric", "abc"),
    ("float", "1e309"), ("nan", "NaN"), ("unicode", "￿‮"), ("empty", ""), ("bool", "true"), ("nullword", "null"),
]


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class Client:
    def __init__(self, args):
        self.a, self.n = args, 0
        self.p = urlsplit(args.url)

    def send(self, method, path, body=None, ctype=None, raw_path=False):
        if self.n:
            time.sleep(self.a.delay)
        self.n += 1
        p = self.p
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.a.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.a.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.a.timeout)
        h = {"User-Agent": "Mozilla/5.0 error-handling-audit", "Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
        if self.a.cookie:
            h["Cookie"] = self.a.cookie
        for hv in self.a.header:
            k, _, v = hv.partition(":")
            h[k.strip()] = v.strip()
        if ctype:
            h["Content-Type"] = ctype
        data = body.encode("utf-8", errors="surrogatepass") if isinstance(body, str) else body
        t0 = time.perf_counter()
        try:
            conn.request(method, path, body=data, headers=h)
            r = conn.getresponse()
            text = r.read(600_000).decode("utf-8", errors="replace")
            hdrs = "\n".join(f"{k}: {v}" for k, v in r.getheaders())
            return {"status": r.status, "body": text, "headers": hdrs, "time": time.perf_counter() - t0}
        except Exception as e:
            return {"status": None, "body": "", "headers": "", "time": time.perf_counter() - t0, "error": str(e)}
        finally:
            conn.close()


def fingerprint(r) -> dict:
    blob = r["body"] + "\n" + r["headers"]
    sig = sorted(k for k, rx in SIG_RE.items() if rx.search(blob))
    versions = sorted(set(m.group(0)[:60] for m in VERSION_RE.finditer(blob)))
    defaults = sorted(k for k, rx in DEFAULT_RE.items() if rx.search(r["body"]))
    return {"signatures": sig, "versions": versions, "default_page": defaults}


def classify(label, r, fp, F, client_fault=True):
    st = r.get("status")
    rows = []
    if set(fp["signatures"]) & STACK_KEYS or "fs-path" in fp["signatures"]:
        rows.append("EH-001")
    if "sql-error" in fp["signatures"] or "db-query" in fp["signatures"]:
        rows.append("EH-002")
    if fp["versions"] and (st or 0) >= 400:
        rows.append("EH-003")
    if {"internal-ip", "internal-host", "fs-path"} & set(fp["signatures"]):
        rows.append("EH-004")
    if set(fp["signatures"]) & DEBUG_KEYS:
        rows.append("EH-008")
    if fp["default_page"]:
        rows.append("EH-007")
    if client_fault and st and st >= 500:
        rows.append("EH-009")
    if client_fault and st and 200 <= st < 300 and ERROR_WORDS.search(r["body"][:3000]):
        rows.append("EH-009")
    if rows:
        detail = ", ".join(x for x in fp["signatures"] + fp["versions"] + [f"default:{d}" for d in fp["default_page"]])
        F.append(f"{'/'.join(sorted(set(rows)))}: {label} -> {st} {detail}".strip())
    return sorted(set(rows))


def enum_mode(args, c, F):
    if "FUZZ" not in (args.form or "") + (args.json_body or "") + args.url:
        sys.exit("--enum needs FUZZ in --url, --form, or --json-body")
    p = urlsplit(args.url)
    stats = {}
    for label, val in (("valid", args.valid), ("invalid", args.invalid)):
        res = []
        for _ in range(args.repeat):
            path = (p.path or "/") + ("?" + p.query.replace("FUZZ", quote(val)) if p.query else "")
            body, ctype = None, None
            if args.form:
                body, ctype = args.form.replace("FUZZ", quote(val)), "application/x-www-form-urlencoded"
            elif args.json_body:
                body, ctype = args.json_body.replace("FUZZ", val), "application/json"
            r = c.send(args.method, path, body, ctype)
            norm = re.sub(r"[0-9a-f]{16,}|\d{6,}|" + re.escape(val), "", r["body"])
            res.append((r["status"], len(r["body"]), hashlib.sha1(norm.encode()).hexdigest()[:10], r["time"]))
        stats[label] = {"statuses": sorted({x[0] for x in res}), "lengths": sorted({x[1] for x in res}),
                        "bodies": sorted({x[2] for x in res}), "median_time": round(statistics.median(x[3] for x in res), 3)}
    v, i = stats["valid"], stats["invalid"]
    diffs = []
    if v["statuses"] != i["statuses"]:
        diffs.append(f"status {v['statuses']} vs {i['statuses']}")
    if set(v["bodies"]).isdisjoint(i["bodies"]):
        diffs.append(f"body differs (lengths {v['lengths']} vs {i['lengths']})")
    if abs(v["median_time"] - i["median_time"]) > max(0.15, 0.5 * min(v["median_time"], i["median_time"])):
        diffs.append(f"median time {v['median_time']}s vs {i['median_time']}s")
    if diffs:
        F.append(f"EH-006: valid and invalid inputs are distinguishable: {'; '.join(diffs)}")
    return stats


def graphql_mode(args, F):
    gp = urlsplit(args.graphql)
    g = Client(argparse.Namespace(**{**vars(args), "url": args.graphql}))
    docs = [("syntax", "{ __typename "), ("unknown-field", "{ thisFieldDoesNotExist_eh }"), ("bad-arg", "{ __type(name: 123) { name } }"),
            ("variables-type", None)]
    out = []
    for label, q in docs:
        body = json.dumps({"query": q}) if q is not None else json.dumps({"query": "query($a:Int){ __typename }", "variables": {"a": "notanint"}})
        r = g.send("POST", gp.path or "/", body, "application/json")
        blob = r["body"]
        notes = []
        if re.search(r'"stacktrace"|"exception"\s*:\s*\{|at [\w.$]+\(|Traceback|\.js:\d+:\d+', blob):
            notes.append("stack trace or exception class in errors[].extensions")
        if re.search(r"Did you mean", blob):
            notes.append("field suggestions enabled (graphql-audit GQL-009)")
        if SIG_RE["sql-error"].search(blob):
            notes.append("SQL error text")
        fp = fingerprint(r)
        if fp["signatures"]:
            notes.append(f"signatures {fp['signatures']}")
        out.append({"doc": label, "status": r["status"], "notes": notes})
        if notes:
            F.append(f"EH-010: GraphQL {label} -> {r['status']}: {'; '.join(notes)}")
    return out, g.n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--form", help="urlencoded body (FUZZ marks the enum parameter)")
    ap.add_argument("--json-body", help="JSON body (top-level keys are fuzzed)")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--enum", action="store_true")
    ap.add_argument("--valid")
    ap.add_argument("--invalid")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--graphql", help="GraphQL endpoint URL for EH-010")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    target = args.target.lower()
    for u in [args.url] + ([args.graphql] if args.graphql else []):
        h = (urlsplit(u).hostname or "").lower()
        if not (h == target or h.endswith("." + target)):
            sys.exit(f"{h} is not {target} or a subdomain of it")
        run_scope_check(h, args.workspace, target)

    c = Client(args)
    F: list[str] = []
    rep: dict = {"url": args.url, "tests": []}
    if args.enum:
        if not (args.valid and args.invalid):
            sys.exit("--enum needs --valid (your own) and --invalid")
        rep["enum"] = enum_mode(args, c, F)
    else:
        p = urlsplit(args.url)
        base_path = p.path or "/"
        qparams = parse_qsl(p.query, keep_blank_values=True)
        fparams = parse_qsl(args.form, keep_blank_values=True) if args.form else []
        jbody = json.loads(args.json_body) if args.json_body else None

        def run(label, method, path, body=None, ctype=None, client_fault=True):
            r = c.send(method, path, body, ctype)
            fp = fingerprint(r)
            rows = classify(label, r, fp, F, client_fault)
            rep["tests"].append({"test": label, "status": r.get("status"), "rows": rows, **fp})
            print(f"  {label[:60]:60} {r.get('status')} {rows or ''}")

        base_q = urlencode(qparams)
        run("baseline", args.method, base_path + ("?" + base_q if base_q else ""),
            urlencode(fparams) if fparams else (json.dumps(jbody) if jbody is not None else None),
            "application/x-www-form-urlencoded" if fparams else ("application/json" if jbody is not None else None), client_fault=False)
        for i, (k, v) in enumerate(qparams):
            for name, val in VARIANTS:
                q = list(qparams)
                q[i] = (k, val)
                run(f"query {k}={name}", args.method, base_path + "?" + urlencode(q, quote_via=quote, safe=""))
            for name, raw in (("array", f"{quote(k)}[]=1"), ("object", f"{quote(k)}[x]=1"), ("missing", ""), ("bad-encoding", f"{quote(k)}=%zz")):
                rest = "&".join(f"{quote(a)}={quote(b)}" for j, (a, b) in enumerate(qparams) if j != i)
                run(f"query {k}={name}", args.method, base_path + "?" + "&".join(x for x in (rest, raw) if x))
        for i, (k, v) in enumerate(fparams):
            for name, val in VARIANTS:
                f = list(fparams)
                f[i] = (k, val)
                run(f"form {k}={name}", args.method, base_path + ("?" + base_q if base_q else ""), urlencode(f), "application/x-www-form-urlencoded")
        if isinstance(jbody, dict):
            for k in list(jbody)[:10]:
                for name, val in VARIANTS + [("as-array", [1]), ("as-object", {"$gt": ""}), ("as-int", 1), ("as-null", None)]:
                    b = dict(jbody)
                    b[k] = val
                    run(f"json {k}={name}", args.method, base_path, json.dumps(b), "application/json")
            run("json malformed", args.method, base_path, '{"a":', "application/json")
            run("json wrong content-type", args.method, base_path, json.dumps(jbody), "text/xml")
        run("method FOO", "FOO", base_path)
        run("method PATCH", "PATCH", base_path, "", "application/json")
        run("random path", "GET", f"/eh-{secrets.token_hex(4)}", client_fault=False)
        run("bad percent path", "GET", "/%", client_fault=True)
    if args.graphql:
        rep["graphql"], gn = graphql_mode(args, F)
        c.n += gn
    F = list(dict.fromkeys(F))
    rep["findings"], rep["requests"] = F, c.n
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {c.n}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
