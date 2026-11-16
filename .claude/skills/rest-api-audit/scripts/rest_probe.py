#!/usr/bin/env python3
"""REST-specific probe (RST rows), scope-gated.

  --crud FILE   own-object lifecycle (RST-001, RST-005, RST-009):
                {"collection": "/v1/notes", "create_body": {...}, "update_body": {...},
                 "id_field": "id", "item_path": "/v1/notes/{id}"}
                A creates -> A GET/PUT/PATCH -> B GET/PUT/PATCH/DELETE -> anonymous GET/PUT/DELETE -> A DELETE (cleanup) -> A GET (expect 404)
  --endpoints F lines "GET /path" (fill {placeholders} with --param name=OWN_VALUE); per GET endpoint:
                HEAD vs GET with and without credentials (RST-003), OPTIONS with foreign Origin (RST-004),
                identity headers with --other-id (RST-008), status for random IDs and malformed bodies (RST-009/RST-010),
                HATEOAS links (RST-011), pagination edge values (RST-012), sort/filter markers (RST-013),
                version negotiation and Deprecation/Sunset headers (RST-014/RST-015).
Writes happen only inside --crud, on the object created by account A in this run.

Example:
  rest_probe.py --target example.com --base https://api.example.com --header 'Authorization: Bearer A' \
     --header-b 'Authorization: Bearer B' --crud crud.json --endpoints endpoints.txt --param id=1042 --other-id 2001
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
IDENTITY_HEADERS = ["X-User-Id", "X-UserId", "X-User", "X-Remote-User", "X-Auth-User", "X-Forwarded-User", "X-Account-Id", "X-Tenant-Id",
                    "X-Org-Id", "X-Role", "X-Roles", "X-Admin", "X-Original-User", "X-Impersonate-User"]
ERR_SIGS = re.compile(r"Traceback|at [\w.$]+\(|SQLSTATE|ORA-\d{5}|syntax error|Exception|/var/www|/home/\w+|\.java:\d+|\.js:\d+:\d+", re.I)
PAGE = ["limit", "per_page", "page_size", "pageSize", "size", "count", "top", "$top"]


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def hdrs_from(lst):
    out = {}
    for hv in lst:
        k, _, v = hv.partition(":")
        out[k.strip()] = v.strip()
    return out


class C:
    def __init__(self, a):
        self.a, self.n, self.p = a, 0, urlsplit(a.base)

    def req(self, method, path, who="A", headers=None, body=None, ctype="application/json"):
        if self.n:
            time.sleep(self.a.delay)
        self.n += 1
        p = self.p
        prefix = p.path.rstrip("/") if p.path not in ("", "/") and not path.startswith(p.path) else ""
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.a.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.a.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.a.timeout)
        h = {"User-Agent": "Mozilla/5.0 rest-api-audit", "Accept": "application/json"}
        if who == "A":
            h.update(hdrs_from(self.a.header))
            if self.a.cookie:
                h["Cookie"] = self.a.cookie
        elif who == "B":
            h.update(hdrs_from(self.a.header_b))
        if body is not None:
            h["Content-Type"] = ctype
        h.update(headers or {})
        try:
            conn.request(method, prefix + path, body=(json.dumps(body) if isinstance(body, (dict, list)) else body), headers=h)
            r = conn.getresponse()
            data = r.read(3_000_000)
            try:
                js = json.loads(data)
            except ValueError:
                js = None
            return {"status": r.status, "len": len(data), "sha": hashlib.sha1(data).hexdigest()[:12], "json": js,
                    "headers": {k.lower(): v for k, v in r.getheaders()}, "text": data[:2000].decode("utf-8", errors="replace")}
        except Exception as e:
            return {"status": None, "len": 0, "sha": "", "json": None, "headers": {}, "text": "", "error": str(e)}
        finally:
            conn.close()


def find_id(js, field):
    if isinstance(js, dict):
        if field in js:
            return js[field]
        for k in ("data", "result", "item", "object"):
            if isinstance(js.get(k), dict) and field in js[k]:
                return js[k][field]
    return None


def links(js, out, path=""):
    if isinstance(js, dict):
        for k, v in js.items():
            if isinstance(v, str) and (k in ("href", "url", "self", "next", "prev", "previous", "first", "last", "link") or k.endswith("_url")) and re.match(r"https?://|/", v):
                out.append((f"{path}.{k}", v))
            else:
                links(v, out, f"{path}.{k}")
    elif isinstance(js, list):
        for v in js[:50]:
            links(v, out, path + "[]")


def count(js):
    if isinstance(js, list):
        return len(js)
    if isinstance(js, dict):
        for k in ("data", "items", "results", "records", "content", "rows", "entries"):
            if isinstance(js.get(k), list):
                return len(js[k])
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--base", required=True)
    ap.add_argument("--header", action="append", default=[], help="account A auth header")
    ap.add_argument("--cookie", help="account A cookie")
    ap.add_argument("--header-b", action="append", default=[], help="account B auth header")
    ap.add_argument("--crud")
    ap.add_argument("--endpoints")
    ap.add_argument("--param", action="append", default=[])
    ap.add_argument("--other-id", help="account B's user/account ID for identity-header tests")
    ap.add_argument("--malformed-post", action="store_true", help="also POST an invalid JSON body to each GET path (only where a POST cannot create data)")
    ap.add_argument("--max-endpoints", type=int, default=40)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    target = a.target.lower()
    host = (urlsplit(a.base).hostname or "").lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, a.workspace, target)
    c = C(a)
    F: list[str] = []
    rep: dict = {"base": a.base}
    params = dict(p.split("=", 1) for p in a.param)

    if a.crud:
        spec = json.load(open(a.crud, encoding="utf-8"))
        col, item_t, idf = spec["collection"], spec["item_path"], spec.get("id_field", "id")
        life = []
        cr = c.req("POST", col, body=spec["create_body"])
        oid = find_id(cr["json"], idf)
        life.append({"step": "A create", "status": cr["status"], "id": oid})
        if cr["status"] not in (200, 201):
            F.append(f"RST-001: create on {col} returned {cr['status']}; CRUD lifecycle skipped")
        if cr["status"] == 200 and oid is not None:
            F.append(f"RST-009 info: create on {col} returns 200 instead of 201")
        if oid is not None:
            item = item_t.replace("{id}", str(oid))
            for who, m, body in (("A", "GET", None), ("A", "PATCH", spec["update_body"]), ("A", "PUT", {**spec["create_body"], **spec["update_body"]}),
                                 ("B", "GET", None), ("B", "PATCH", spec["update_body"]), ("B", "PUT", {**spec["create_body"], **spec["update_body"]}),
                                 ("anon", "GET", None), ("anon", "PATCH", spec["update_body"]), ("B", "DELETE", None), ("anon", "DELETE", None),
                                 ("B", "HEAD", None), ("anon", "HEAD", None)):
                if who == "B" and not a.header_b:
                    continue
                r = c.req(m, item, who=who, body=body)
                life.append({"step": f"{who} {m}", "status": r["status"]})
                if who != "A" and r["status"] and 200 <= r["status"] < 300:
                    row = "RST-005" if m in ("PUT", "PATCH", "DELETE") else ("RST-003" if m == "HEAD" else "RST-001")
                    F.append(f"{row}: {who} {m} on A's object {item} returned {r['status']}")
                if who != "A" and r["status"] == 403 and m == "GET":
                    F.append(f"RST-009 info: {who} GET on another account's object returns 403 (reveals existence; 404 preferred)")
            d = c.req("DELETE", item)
            g = c.req("GET", item)
            life.append({"step": "A DELETE (cleanup)", "status": d["status"]})
            life.append({"step": "A GET after delete", "status": g["status"]})
            if g["status"] == 200:
                F.append(f"RST-001: {item} still readable after DELETE (soft delete without access removal?) - verify cleanup manually")
            if d["status"] not in (200, 202, 204):
                F.append(f"RST-001: cleanup DELETE returned {d['status']}; remove object {oid} manually")
        rep["crud"] = life
        for s in life:
            print(f"  crud {s['step']:22} {s.get('status')}")

    eps = []
    if a.endpoints:
        for line in open(a.endpoints, encoding="utf-8"):
            parts = line.split()
            if len(parts) >= 2 and parts[0].upper() == "GET" and not line.startswith("#"):
                path = re.sub(r"\{([^}]+)\}", lambda m: params.get(m.group(1), m.group(0)), parts[1])
                if "{" not in path:
                    eps.append(path)
    eps = eps[: a.max_endpoints]
    status_matrix = []
    for path in eps:
        g = c.req("GET", path)
        gn = c.req("GET", path, who="anon")
        hn = c.req("HEAD", path, who="anon")
        rec = {"path": path, "GET": g["status"], "GET_anon": gn["status"], "HEAD_anon": hn["status"]}
        if gn["status"] in (401, 403) and hn["status"] and 200 <= hn["status"] < 300:
            F.append(f"RST-003: HEAD {path} returns {hn['status']} without credentials while GET is {gn['status']}")
        if hn["headers"].get("content-length") not in (None, "0") and gn["status"] in (401, 403) and hn["status"] == 200:
            F.append(f"RST-003: HEAD {path} discloses Content-Length {hn['headers']['content-length']} without credentials")
        o = c.req("OPTIONS", path, who="anon", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "DELETE"})
        rec["OPTIONS"] = {"status": o["status"], "allow": o["headers"].get("allow"), "acao": o["headers"].get("access-control-allow-origin"),
                          "acam": o["headers"].get("access-control-allow-methods")}
        if o["headers"].get("access-control-allow-origin") in ("*", "https://evil.example"):
            F.append(f"RST-004: OPTIONS {path} allows foreign origin ({o['headers'].get('access-control-allow-origin')}) methods {o['headers'].get('access-control-allow-methods')}")
        if g["status"] != 200:
            status_matrix.append(rec)
            continue
        if a.other_id:
            for hname in IDENTITY_HEADERS:
                val = "admin" if "role" in hname.lower() or "admin" in hname.lower() else a.other_id
                r = c.req("GET", path, headers={hname: val})
                if r["status"] == 200 and r["sha"] != g["sha"] and (a.other_id in r["text"] or "admin" in r["text"].lower()):
                    F.append(f"RST-008: {hname}: {val} changes the response of {path} (identity/role header trusted)")
        rid = re.sub(r"/\d+(?=/|$)", "/999999999", path) if re.search(r"/\d+(/|$)", path) else path.rstrip("/") + "/zz" + secrets.token_hex(4)
        r404 = c.req("GET", rid)
        checks = [("random id", r404)]
        if a.malformed_post:
            mal = c.req("POST", path, body='{"x":', ctype="application/json")
            rec["malformed_post"] = mal["status"]
            checks.append(("malformed body", mal))
        rec["random_id"] = r404["status"]
        for label, r in checks:
            if r["status"] and r["status"] >= 500:
                F.append(f"RST-009/RST-010: {label} on {path} returns {r['status']}")
            if ERR_SIGS.search(r["text"]):
                F.append(f"RST-010: {label} on {path} leaks internals ({ERR_SIGS.search(r['text']).group(0)})")
            if r["status"] == 200 and label == "random id":
                F.append(f"RST-009: non-existent ID on {rid} returns 200")
        lk: list = []
        links(g["json"], lk)
        bad = [(k, v) for k, v in lk if (urlsplit(v).hostname and urlsplit(v).hostname != host) or v.startswith("http://") or re.search(r"(?i)token=|key=|signature=", v)]
        if lk:
            rec["links"] = lk[:20]
        if bad:
            F.append(f"RST-011: HATEOAS links on {path} point to other hosts, plain http, or carry tokens: {bad[:3]}")
        x = c.req("GET", path, headers={"X-Forwarded-Host": "rst-canary.example"})
        if "rst-canary.example" in x["text"]:
            F.append(f"RST-011: links in {path} built from X-Forwarded-Host (cache/link poisoning)")
        n0 = count(g["json"])
        if n0 is not None:
            pg = {}
            for pn in PAGE[:4]:
                for v in ("1000", "0", "-1"):
                    sep = "&" if "?" in path else "?"
                    r = c.req("GET", f"{path}{sep}{pn}={v}")
                    pg[f"{pn}={v}"] = count(r["json"])
                if any(x_ and x_ > max(n0, 100) for x_ in pg.values()):
                    F.append(f"RST-012: {path} returns more items than the default ({n0}) with {pn} edge values: { {k: v for k, v in pg.items() if v} }")
                    break
            rec["pagination"] = pg
            for label, q in (("sort-sensitive", {"sort": "password"}), ("sort-quote", {"sort": "id'"}), ("order-quote", {"order_by": "id'"}),
                             ("filter-operator", {"filter[id][$ne]": "0"}), ("odata", {"$filter": "id ne 0"}), ("sort-desc", {"sort": "-id"})):
                sep = "&" if "?" in path else "?"
                r = c.req("GET", path + sep + urlencode(q))
                if ERR_SIGS.search(r["text"]) or (r["status"] and r["status"] >= 500):
                    F.append(f"RST-013: {label} on {path} -> {r['status']} {(ERR_SIGS.search(r['text']) or re.match('', '')).group(0)}")
                elif label == "sort-sensitive" and r["status"] == 200 and r["sha"] != g["sha"]:
                    F.append(f"RST-013 lead: sort=password changes ordering on {path} (sorting by a hidden field = oracle)")
        dep = {k: g["headers"].get(k) for k in ("deprecation", "sunset", "link") if g["headers"].get(k)}
        if dep:
            rec["deprecation_headers"] = dep
            F.append(f"RST-014 info: {path} is marked deprecated {dep}; check it keeps current controls")
        vres = {}
        for label, hd, q in (("Accept-Version: 1", {"Accept-Version": "1"}, None), ("X-API-Version: 1", {"X-API-Version": "1"}, None),
                             ("api-version=2015-01-01", {}, {"api-version": "2015-01-01"}), ("vnd v1", {"Accept": "application/vnd.api.v1+json"}, None),
                             ("version=1", {}, {"version": "1"})):
            pth = path + ("&" if "?" in path else "?") + urlencode(q) if q else path
            r = c.req("GET", pth, headers=hd)
            vres[label] = {"status": r["status"], "same": r["sha"] == g["sha"], "len": r["len"]}
            if r["status"] == 200 and r["sha"] != g["sha"] and r["len"] > g["len"] * 1.2:
                F.append(f"RST-015 lead: {label} returns a larger/different representation of {path}; compare fields and checks")
        rec["versions"] = vres
        status_matrix.append(rec)
    rep["endpoints"] = status_matrix
    F = list(dict.fromkeys(F))
    rep["findings"], rep["requests"] = F, c.n
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {c.n}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
