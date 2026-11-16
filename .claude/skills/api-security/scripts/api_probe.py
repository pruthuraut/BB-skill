#!/usr/bin/env python3
"""Spec-driven API auth/authz and manipulation probe (AA and AI rows).

Endpoints come from --spec (OpenAPI 3 / Swagger 2, JSON or YAML if PyYAML is present) or
--endpoints (lines like "GET /v1/users/{id}"). Path placeholders are filled from --param
(name=value, use your OWN object IDs) or, for method tests, with a random non-existent value.

Tests (--tests, comma list; default: docs,unauth,tokens,methods,override,versions,fields,pagination,gateway):
  docs        AA-015  common documentation paths
  unauth      AA-001  each GET with no credentials vs your credentials
  tokens      AA-004  tampered / truncated / empty / alg-none bearer tokens on endpoints that return 200
  keyinurl    AA-003  move --api-key-header value into query parameters
  methods     AA-007  OPTIONS/HEAD/GET/PUT/PATCH/DELETE on a RANDOM id (never real objects); collection paths get OPTIONS/HEAD only
  override    AA-017  POST + X-HTTP-Method-Override headers / _method on a random id
  versions    AA-008  swap /vN/ segments (v0..vN+1, beta, internal, legacy)
  fields      AA-011  fields=*, expand=all, include=all, select=*, $select=* growth
  pagination  AA-020  limit/per_page/size/page_size = 1, 1000, 0, -1 (item counts only)
  gateway     AA-024  path-normalization and internal-header variants on 401/403 endpoints
  hpp         AI-006  duplicate/array parameters on GETs that have query params
  ctype       AA-019/AI-012  --sample-request JSON body resent as form, text/plain, XML
  ratelimit   AA-006/AI-008  --rl-endpoint "METHOD /path" burst (<= 30) then with rotating X-Forwarded-For

Safety: scope-gated; GET-only except method tests on random IDs, override tests on random IDs,
and the explicit --sample-request / --rl-endpoint you provide (use own, harmless operations).

Example:
  api_probe.py --target example.com --base https://api.example.com --spec openapi.json \
     --header 'Authorization: Bearer OWN_A' --param id=1042 --param orgId=77 --out artifacts/example.com/api_probe.json
"""
from __future__ import annotations

import argparse
import base64
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
DOC_PATHS = ["/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html", "/api-docs",
             "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml", "/api/openapi.json", "/api/swagger.json", "/redoc",
             "/docs", "/api/docs", "/.well-known/openapi.json", "/postman_collection.json", "/api/v1/swagger.json", "/graphql/schema"]
OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]
FIELD_PARAMS = [{"fields": "*"}, {"expand": "all"}, {"include": "all"}, {"select": "*"}, {"$select": "*"}, {"_fields": "*"}, {"view": "full"}]
PAGE_PARAMS = ["limit", "per_page", "pageSize", "page_size", "size", "count", "max", "top", "$top", "first"]
BYPASS_IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP", "X-Originating-IP", "CF-Connecting-IP"]


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class C:
    def __init__(self, a):
        self.a, self.n = a, 0
        self.p = urlsplit(a.base)

    def auth(self):
        h = {}
        if self.a.cookie:
            h["Cookie"] = self.a.cookie
        for hv in self.a.header:
            k, _, v = hv.partition(":")
            h[k.strip()] = v.strip()
        return h

    def req(self, method, path, headers=None, body=None, ctype=None, auth=True):
        if self.n:
            time.sleep(self.a.delay)
        self.n += 1
        p = self.p
        full = (p.path.rstrip("/") + path) if not path.startswith(p.path or "/") or p.path in ("", "/") else path
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.a.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.a.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.a.timeout)
        h = {"User-Agent": "Mozilla/5.0 api-security", "Accept": "application/json"}
        if auth:
            h.update(self.auth())
        if ctype:
            h["Content-Type"] = ctype
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        try:
            conn.request(method, full, body=body.encode() if isinstance(body, str) else body, headers=h)
            r = conn.getresponse()
            data = r.read(3_000_000)
            hd = {k.lower(): v for k, v in r.getheaders()}
            try:
                js = json.loads(data)
            except ValueError:
                js = None
            return {"status": r.status, "len": len(data), "sha": hashlib.sha1(data).hexdigest()[:12], "json": js, "headers": hd,
                    "text": data[:300].decode("utf-8", errors="replace")}
        except Exception as e:
            return {"status": None, "len": 0, "sha": "", "json": None, "headers": {}, "text": "", "error": str(e)}
        finally:
            conn.close()


def load_endpoints(a):
    eps = []
    if a.spec:
        raw = open(a.spec, encoding="utf-8").read()
        try:
            spec = json.loads(raw)
        except ValueError:
            try:
                import yaml  # type: ignore
                spec = yaml.safe_load(raw)
            except Exception:
                sys.exit("spec is not JSON and PyYAML is unavailable; convert it to JSON")
        prefix = spec.get("basePath", "") if "swagger" in spec else ""
        if "servers" in spec and spec["servers"]:
            sp = urlsplit(spec["servers"][0].get("url", ""))
            prefix = sp.path.rstrip("/") if sp.path not in ("", "/") else ""
        for path, item in (spec.get("paths") or {}).items():
            for m, op in item.items():
                if m.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    params = [p.get("name") for p in (op.get("parameters") or []) + (item.get("parameters") or []) if isinstance(p, dict)]
                    eps.append({"method": m.upper(), "path": prefix + path, "params": params,
                                "secured": bool(op.get("security", spec.get("security")))})
    if a.endpoints:
        for line in open(a.endpoints, encoding="utf-8"):
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"):
                eps.append({"method": parts[0].upper(), "path": parts[1], "params": re.findall(r"[?&]([^=&]+)=", parts[1]), "secured": None})
    return eps[: a.max_endpoints]


def fill(path, params, random_ids=False):
    def rep(m):
        name = m.group(1)
        if not random_ids and name in params:
            return params[name]
        if random_ids:
            return "999999999" if re.search(r"(?i)id$|num|count", name) else "zz" + secrets.token_hex(6)
        return None
    out = re.sub(r"\{([^}]+)\}", lambda m: rep(m) or m.group(0), path)
    return out


def items_count(js):
    if isinstance(js, list):
        return len(js)
    if isinstance(js, dict):
        for k in ("data", "items", "results", "records", "content", "rows", "entries", "list", "users", "objects"):
            if isinstance(js.get(k), list):
                return len(js[k])
    return None


def jwt_none(token):
    try:
        h, p, _ = token.split(".")
        nh = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        return f"{nh}.{p}."
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--base", required=True)
    ap.add_argument("--spec")
    ap.add_argument("--endpoints")
    ap.add_argument("--header", action="append", default=[], help="own auth header 'Name: value'")
    ap.add_argument("--cookie")
    ap.add_argument("--param", action="append", default=[], help="placeholder value name=value (own objects)")
    ap.add_argument("--api-key-header", help="header name carrying your API key (for keyinurl)")
    ap.add_argument("--sample-request", help="JSON file {method, path, body} of an own harmless write for ctype tests")
    ap.add_argument("--rl-endpoint", help='"METHOD /path" for rate-limit test (own harmless request)')
    ap.add_argument("--rl-body", help="body for --rl-endpoint (JSON string)")
    ap.add_argument("--rl-count", type=int, default=20)
    ap.add_argument("--tests", default="docs,unauth,tokens,methods,override,versions,fields,pagination,gateway")
    ap.add_argument("--max-endpoints", type=int, default=150)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.rl_count > 30:
        sys.exit("--rl-count is capped at 30 (larger bursts are authorized-only)")
    target = a.target.lower()
    host = (urlsplit(a.base).hostname or "").lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, a.workspace, target)

    tests = set(a.tests.split(","))
    params = dict(p.split("=", 1) for p in a.param)
    eps = load_endpoints(a)
    c = C(a)
    F: list[str] = []
    rep: dict = {"base": a.base, "endpoints": len(eps)}
    print(f"{len(eps)} endpoints loaded")

    if "docs" in tests:
        found = []
        for dp in DOC_PATHS:
            r = c.req("GET", dp, auth=False)
            if r["status"] == 200 and re.search(r'(?i)"(swagger|openapi)"\s*:|swagger-ui|redoc|"info"\s*:\s*\{|postman', r["text"]):
                found.append(dp)
        rep["docs"] = found
        if found:
            F.append(f"AA-015: API documentation exposed without auth: {found}")

    gets = [e for e in eps if e["method"] == "GET"]
    ok_gets, enforced = [], []
    if "unauth" in tests:
        res = []
        for e in gets:
            path = fill(e["path"], params)
            if "{" in path:
                continue
            ra = c.req("GET", path)
            rn = c.req("GET", path, auth=False)
            rec = {"path": path, "auth": ra["status"], "noauth": rn["status"]}
            res.append(rec)
            if ra["status"] == 200:
                ok_gets.append(path)
                if rn["status"] in (401, 403):
                    enforced.append(path)
            if rn["status"] == 200 and ra["status"] == 200 and rn["sha"] == ra["sha"] and (e.get("secured") is not False):
                F.append(f"AA-001: {path} returns the same 200 response without credentials")
            elif rn["status"] == 200 and ra["status"] == 200 and e.get("secured"):
                F.append(f"AA-001 lead: {path} (declared secured) returns 200 without credentials (body differs)")
        rep["unauth"] = res

    if "tokens" in tests:
        authz = next((h.split(":", 1)[1].strip() for h in a.header if h.lower().startswith("authorization:")), None)
        if authz and enforced:
            scheme, _, tok = authz.partition(" ")
            variants = {"flip-last-char": f"{scheme} {tok[:-1]}{'A' if tok[-1:] != 'A' else 'B'}", "truncated": f"{scheme} {tok[: len(tok) // 2]}",
                        "empty": f"{scheme} ", "null": f"{scheme} null", "no-scheme": tok}
            nj = jwt_none(tok)
            if nj:
                variants["alg-none"] = f"{scheme} {nj}"
            tr = []
            for path in enforced[:5]:
                accepted = []
                for label, val in variants.items():
                    hdrs = {k.split(":", 1)[0].strip(): None for k in a.header if k.lower().startswith("authorization:")}
                    hdrs["Authorization"] = val
                    r = c.req("GET", path, headers=hdrs)
                    tr.append({"path": path, "variant": label, "status": r["status"]})
                    if r["status"] == 200:
                        accepted.append(label)
                if accepted:
                    F.append(f"AA-004: {path} (401/403 without credentials) accepts invalid bearer tokens: {accepted}")
            rep["tokens"] = tr
        else:
            rep["tokens"] = "skipped (needs --header 'Authorization: ...' and an endpoint that returns 401/403 without credentials)"

    if "keyinurl" in tests and a.api_key_header and ok_gets:
        val = next((h.split(":", 1)[1].strip() for h in a.header if h.split(":", 1)[0].strip().lower() == a.api_key_header.lower()), None)
        if val:
            for path in ok_gets[:3]:
                for qn in ("api_key", "apikey", "key", "token", "access_token"):
                    sep = "&" if "?" in path else "?"
                    r = c.req("GET", f"{path}{sep}{qn}={val}", headers={a.api_key_header: None})
                    if r["status"] == 200:
                        F.append(f"AA-003: API key accepted in URL parameter '{qn}' on {path}")
                        break

    if "methods" in tests:
        seen, mres = set(), []
        for e in eps:
            tpl = e["path"]
            if tpl in seen:
                continue
            seen.add(tpl)
            declared = {x["method"] for x in eps if x["path"] == tpl}
            has_id = tpl.rstrip("/").endswith("}")
            path = fill(tpl, params, random_ids=True)
            methods = ["OPTIONS", "HEAD", "GET", "PUT", "PATCH", "DELETE"] if has_id else ["OPTIONS", "HEAD"]
            row = {"path": tpl, "declared": sorted(declared)}
            for m in methods:
                r = c.req(m, path, body="{}" if m in ("PUT", "PATCH") else None, ctype="application/json" if m in ("PUT", "PATCH") else None)
                row[m] = r["status"]
                if m == "OPTIONS" and r["headers"].get("allow"):
                    row["allow"] = r["headers"]["allow"]
                if m in ("PUT", "PATCH", "DELETE") and m not in declared and r["status"] and 200 <= r["status"] < 300:
                    F.append(f"AA-007: undeclared {m} on {tpl} returns {r['status']} for a random ID")
            mres.append(row)
        rep["methods"] = mres

    if "override" in tests:
        ores = []
        for e in eps:
            if not e["path"].rstrip("/").endswith("}") or e["method"] != "GET":
                continue
            path = fill(e["path"], params, random_ids=True)
            d = c.req("DELETE", path)
            p_ = c.req("POST", path, body="{}", ctype="application/json")
            for hname in OVERRIDE_HEADERS:
                r = c.req("POST", path, headers={hname: "DELETE"}, body="{}", ctype="application/json")
                honored = r["status"] == d["status"] and r["status"] != p_["status"]
                ores.append({"path": e["path"], "header": hname, "status": r["status"], "direct_delete": d["status"], "post": p_["status"], "honored": honored})
                if honored:
                    F.append(f"AA-017: {hname} honored on {e['path']} (POST behaves like DELETE: {r['status']}); check method-based authz bypass")
            if len(ores) >= 15:
                break
        rep["override"] = ores

    if "versions" in tests:
        vres = []
        vpaths = sorted({fill(e["path"], params) for e in gets if re.search(r"/v\d+/", e["path"])})
        vpaths = [v for v in vpaths if "{" not in v][:10]
        for path in vpaths:
            n = int(re.search(r"/v(\d+)/", path).group(1))
            base_r = c.req("GET", path)
            for alt in [f"v{i}" for i in range(0, n + 2) if i != n] + ["beta", "internal", "legacy", "dev", "test"]:
                ap_ = re.sub(r"/v\d+/", f"/{alt}/", path, count=1)
                r = c.req("GET", ap_)
                rn = c.req("GET", ap_, auth=False) if r["status"] == 200 else None
                vres.append({"path": ap_, "status": r["status"], "noauth": rn["status"] if rn else None})
                if r["status"] == 200:
                    F.append(f"AA-008 lead: alternate version {ap_} responds 200 (baseline {base_r['status']}); compare authz with the current version")
                if rn and rn["status"] == 200:
                    F.append(f"AA-008: alternate version {ap_} responds 200 without credentials")
        rep["versions"] = vres

    if "fields" in tests:
        fres = []
        for path in ok_gets[:10]:
            base_r = c.req("GET", path)
            for fp in FIELD_PARAMS:
                sep = "&" if "?" in path else "?"
                r = c.req("GET", path + sep + urlencode(fp))
                grow = (r["len"] - base_r["len"]) / max(base_r["len"], 1)
                fres.append({"path": path, "param": fp, "status": r["status"], "growth": round(grow, 2)})
                if r["status"] == 200 and grow > 0.2:
                    F.append(f"AA-011 lead: {path} with {fp} returns {int(grow * 100)}% more data; inspect the extra fields")
        rep["fields"] = fres

    if "pagination" in tests:
        pres = []
        for e in gets:
            pn = next((p for p in e["params"] if p in PAGE_PARAMS), None)
            path = fill(e["path"], params)
            if not pn or "{" in path:
                continue
            counts = {}
            for v in ("1", "1000", "0", "-1"):
                sep = "&" if "?" in path else "?"
                r = c.req("GET", f"{path}{sep}{pn}={v}")
                counts[v] = {"status": r["status"], "items": items_count(r["json"])}
            pres.append({"path": path, "param": pn, "results": counts})
            big = counts["1000"]["items"]
            if big and big > 200:
                F.append(f"AA-020: {path} returns {big} items for {pn}=1000 (no server-side cap)")
            for v in ("0", "-1"):
                if counts[v]["items"] and counts["1"]["items"] is not None and counts[v]["items"] > max(counts["1"]["items"], 50):
                    F.append(f"AA-020: {path} {pn}={v} returns {counts[v]['items']} items (unbounded)")
            if len(pres) >= 10:
                break
        rep["pagination"] = pres

    if "gateway" in tests:
        gres = []
        blocked = []
        for e in gets:
            path = fill(e["path"], params)
            if "{" in path:
                continue
            r = c.req("GET", path, auth=False)
            if r["status"] in (401, 403):
                blocked.append(path)
            if len(blocked) >= 5:
                break
        for path in blocked:
            segs = path.rstrip("/").rsplit("/", 1)
            variants = [path + "/", path.upper(), "/" + path, path + ";.json", path + "%20", path + "..;/", path.replace("/", "/./", 1),
                        f"{segs[0]}/%2e/{segs[1]}" if len(segs) == 2 else path, path + "?", path + "#"]
            for v in variants:
                r = c.req("GET", v, auth=False)
                gres.append({"path": path, "variant": v, "status": r["status"]})
                if r["status"] == 200:
                    F.append(f"AA-024: {v} returns 200 without credentials (normal path {path} is 401/403)")
            for hdr in ({"X-Original-URL": path}, {"X-Rewrite-URL": path}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"}):
                target_path = "/" if "Original" in str(hdr) or "Rewrite" in str(hdr) else path
                r = c.req("GET", target_path, headers=hdr, auth=False)
                if r["status"] == 200 and target_path == path:
                    F.append(f"AA-024: {path} returns 200 without credentials with header {list(hdr)[0]}")
                gres.append({"path": path, "header": list(hdr)[0], "status": r["status"]})
        rep["gateway"] = gres

    if "hpp" in tests:
        hres = []
        for e in gets:
            path = fill(e["path"], params)
            if "?" not in path or "{" in path:
                continue
            qs = path.split("?", 1)[1]
            k, _, v = qs.split("&")[0].partition("=")
            base_r = c.req("GET", path)
            for label, q in (("dup-first", f"{k}=hpp{secrets.token_hex(2)}&{qs}"), ("dup-last", f"{qs}&{k}=hpp{secrets.token_hex(2)}"),
                             ("array", qs.replace(f"{k}=", f"{k}[]=", 1))):
                r = c.req("GET", path.split("?")[0] + "?" + q)
                diff = r["sha"] != base_r["sha"]
                hres.append({"path": path, "variant": label, "status": r["status"], "differs": diff})
            if len(hres) >= 15:
                break
        rep["hpp"] = hres
        if any(h["differs"] for h in hres):
            F.append("AI-006 lead: duplicate/array parameters change responses; check which value the backend uses vs any gateway/WAF check")

    if "ctype" in tests and a.sample_request:
        s = json.load(open(a.sample_request, encoding="utf-8"))
        body = s.get("body") or {}
        flat = {k: (v if not isinstance(v, (dict, list)) else json.dumps(v)) for k, v in body.items()} if isinstance(body, dict) else {}
        xml = "<root>" + "".join(f"<{k}>{v}</{k}>" for k, v in flat.items()) + "</root>"
        base_r = c.req(s["method"], s["path"], body=json.dumps(body), ctype="application/json")
        cres = [{"ctype": "application/json", "status": base_r["status"]}]
        for ct, b in (("application/x-www-form-urlencoded", urlencode(flat)), ("text/plain", json.dumps(body)), ("application/xml", xml),
                      ("multipart/form-data; boundary=x", "".join(f'--x\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in flat.items()) + "--x--\r\n")):
            r = c.req(s["method"], s["path"], body=b, ctype=ct)
            cres.append({"ctype": ct, "status": r["status"]})
            if r["status"] and 200 <= r["status"] < 300:
                F.append(f"AA-019/AI-012: {s['method']} {s['path']} accepts {ct.split(';')[0]} (2xx)" + (" - XML parser reachable, test XXE" if "xml" in ct else ""))
        rep["ctype"] = cres

    if "ratelimit" in tests and a.rl_endpoint:
        m, path = a.rl_endpoint.split(None, 1)
        statuses = []
        for _ in range(a.rl_count):
            r = c.req(m.upper(), path, body=a.rl_body, ctype="application/json" if a.rl_body else None)
            statuses.append(r["status"])
        limited = 429 in statuses
        bypass = []
        if limited:
            for i in range(min(10, a.rl_count)):
                hdrs = {h: f"10.{i}.{i}.{i + 1}" for h in BYPASS_IP_HEADERS}
                r = c.req(m.upper(), path, headers=hdrs, body=a.rl_body, ctype="application/json" if a.rl_body else None)
                bypass.append(r["status"])
            if bypass and 429 not in bypass:
                F.append(f"AI-008: rate limit on {a.rl_endpoint} reset by spoofed client-IP headers")
        else:
            F.append(f"AA-006: no 429 after {a.rl_count} requests to {a.rl_endpoint}")
        rep["ratelimit"] = {"statuses": statuses, "bypass_statuses": bypass}

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
