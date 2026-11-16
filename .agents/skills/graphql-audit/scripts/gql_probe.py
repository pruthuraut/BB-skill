#!/usr/bin/env python3
"""GraphQL security probe (GQL rows), bounded and scope-gated.

Recon (skip with --skip-recon):
  --discover          try common endpoint paths on the --url host
  transports          POST JSON, GET, form-urlencoded, text/plain (GQL-V-001)
  introspection       full IntrospectionQuery, then __type and newline bypass variants (GQL-001, GQL-V-004)
  schema summary      counts, sensitive fields, dangerous mutations, subscriptions, ID arguments (--schema-out)
  suggestions         typo fields -> "Did you mean" (GQL-009)
  errors              malformed documents / wrong variable types -> stack traces, SQL, paths (GQL-010)
  depth               nested __schema query at depths 3/6/9/12 (GQL-002, GQL-014)
  batching            array of 5 {__typename} (GQL-003)
  aliases             10 aliases (GQL-004)
  directives          unknown directive + 10 repeated @include (GQL-005)
  APQ                 hash-only, then register {__typename} and replay hash-only (GQL-015)
  federation/debug    _service{sdl}, extensions tracing (GQL-V-005, GQL-V-006)
Testing:
  --inject-query Q    Q contains FUZZ inside an argument; quote/boolean/NoSQL/template markers (GQL-008)
  --ops-file F        JSONL operations run as A (--header/--cookie), B (--auth-b), anonymous;
                      compares data to flag IDOR / field authz / mutation access (GQL-006, GQL-012, GQL-013).
                      Mutations run only with --allow-mutations.
Limits: depth ≤ 12, aliases 10, batch 5, directives 10 unless --approved raises them (still capped).

Example:
  gql_probe.py --target example.com --url https://api.example.com/graphql --header 'Authorization: Bearer A' \
     --schema-out artifacts/example.com/graphql_schema.json --out artifacts/example.com/graphql.json
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
DISCOVER = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphql/v1", "/query", "/gql", "/api/gql",
            "/graphiql", "/playground", "/altair", "/console", "/v1/explorer", "/graphql/console", "/api"]
INTROSPECTION = """query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name }
 types { ...FullType } directives { name locations args { ...InputValue } } } }
fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } isDeprecated }
 inputFields { ...InputValue } enumValues(includeDeprecated: true) { name } possibleTypes { name } }
fragment InputValue on __InputValue { name type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }"""
SENS_FIELD = re.compile(r"(?i)password|passwd|hash|salt|secret|token|api_?key|ssn|social|credit|card|cvv|iban|dob|birth|phone|email|address|"
                        r"role|admin|permission|internal|debug|private|mfa|otp|totp|session|ip_?address")
DANGER_MUT = re.compile(r"(?i)delete|remove|destroy|admin|role|permission|grant|impersonat|transfer|withdraw|refund|reset|password|"
                        r"invite|promote|ban|disable|config|setting|upload|import|execute|run|exec|eval|sql|migrate")
ERR_SIGS = re.compile(r'"stacktrace"|"exception"\s*:\s*\{|Traceback|at [\w.$]+\(|\.js:\d+:\d+|SQLSTATE|syntax error at or near|ORA-\d{5}|'
                      r"/var/www|/home/\w+|/usr/src|C:\\\\|java\.lang\.|System\.\w+Exception|psycopg2|Sequelize|Prisma|TypeORM")
ENGINE_HINTS = [("apollo", r"GRAPHQL_VALIDATION_FAILED|PERSISTED_QUERY_NOT_FOUND|apollo"), ("hasura", r"validation-failed|x-hasura|hasura"),
                ("graphql-java", r"FieldUndefined|InvalidSyntax|graphql\.java"), ("graphql-js", r"Syntax Error: Expected Name"),
                ("graphene", r"graphene|Cannot query field .+ on type"), ("hotchocolate", r"HC\d{4}|HotChocolate"),
                ("appsync", r"errorType|appsync"), ("gqlgen", r"gqlgen")]


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class G:
    def __init__(self, args, url):
        self.a, self.url, self.n = args, url, 0

    def raw(self, method, url, body=None, ctype="application/json", headers=None):
        if self.n:
            time.sleep(self.a.delay)
        self.n += 1
        p = urlsplit(url)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.a.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.a.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.a.timeout)
        h = {"User-Agent": "Mozilla/5.0 graphql-audit", "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = ctype
        h.update(headers if headers is not None else self.auth_a())
        t0 = time.perf_counter()
        try:
            conn.request(method, path, body=body.encode() if isinstance(body, str) else body, headers=h)
            r = conn.getresponse()
            txt = r.read(5_000_000).decode("utf-8", errors="replace")
            hd = {k.lower(): v for k, v in r.getheaders()}
            try:
                js = json.loads(txt)
            except ValueError:
                js = None
            return {"status": r.status, "text": txt, "json": js, "headers": hd, "time": round(time.perf_counter() - t0, 3)}
        except Exception as e:
            return {"status": None, "text": "", "json": None, "headers": {}, "error": str(e), "time": 0}
        finally:
            conn.close()

    def auth_a(self):
        h = {}
        if self.a.cookie:
            h["Cookie"] = self.a.cookie
        for hv in self.a.header:
            k, _, v = hv.partition(":")
            h[k.strip()] = v.strip()
        return h

    def auth_b(self):
        h = {}
        for hv in self.a.auth_b:
            k, _, v = hv.partition(":")
            h[k.strip()] = v.strip()
        return h

    def q(self, query, variables=None, headers=None, extra=None):
        body = {"query": query}
        if variables is not None:
            body["variables"] = variables
        if extra:
            body.update(extra)
        return self.raw("POST", self.url, json.dumps(body), headers=headers)


def has_data(r):
    j = r.get("json")
    return isinstance(j, dict) and isinstance(j.get("data"), dict) and any(v is not None for v in j["data"].values())


def errors_text(r):
    j = r.get("json")
    if isinstance(j, dict) and j.get("errors"):
        return json.dumps(j["errors"])[:2000]
    if isinstance(j, list):
        return json.dumps(j)[:2000]
    return r.get("text", "")[:2000]


def unwrap(t):
    while t and t.get("ofType"):
        t = t["ofType"]
    return (t or {}).get("name")


def summarize(schema):
    s = schema["__schema"]
    types = {t["name"]: t for t in s["types"] if t.get("name")}
    roots = {k: (s.get(k) or {}).get("name") for k in ("queryType", "mutationType", "subscriptionType")}
    out = {"types": len([t for t in types if not t.startswith("__")]), "roots": roots}
    for k, label in (("queryType", "queries"), ("mutationType", "mutations"), ("subscriptionType", "subscriptions")):
        n = roots.get(k)
        out[label] = [f["name"] for f in (types.get(n, {}).get("fields") or [])] if n else []
    out["dangerous_mutations"] = [m for m in out["mutations"] if DANGER_MUT.search(m)]
    sens = []
    idargs = []
    for tn, t in types.items():
        if tn.startswith("__"):
            continue
        for f in t.get("fields") or []:
            if SENS_FIELD.search(f["name"]):
                sens.append(f"{tn}.{f['name']}")
            for a in f.get("args") or []:
                if re.search(r"(?i)^(id|.*_id|.*Id|uuid|slug|handle|email|username)$", a["name"]):
                    idargs.append(f"{tn}.{f['name']}({a['name']}: {unwrap(a['type'])})")
    out["sensitive_fields"] = sens[:200]
    out["id_arguments"] = idargs[:200]
    out["deprecated_fields"] = [f"{tn}.{f['name']}" for tn, t in types.items() for f in (t.get("fields") or []) if f.get("isDeprecated")][:100]
    out["directives"] = [d["name"] for d in s.get("directives") or []]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="GraphQL endpoint (or any URL on the host with --discover)")
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--header", action="append", default=[], help="account A auth header")
    ap.add_argument("--cookie", help="account A cookie")
    ap.add_argument("--auth-b", action="append", default=[], help="account B auth header 'Name: value'")
    ap.add_argument("--skip-recon", action="store_true")
    ap.add_argument("--schema-out")
    ap.add_argument("--inject-query", help="query with FUZZ inside an argument")
    ap.add_argument("--ops-file", help="JSONL operations for authorization comparison")
    ap.add_argument("--allow-mutations", action="store_true")
    ap.add_argument("--approved", action="store_true", help="raise cost-test limits (depth 20, aliases 50, batch 20)")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    target = args.target.lower()
    host = (urlsplit(args.url).hostname or "").lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, target)
    max_depth, n_alias, n_batch, n_dir = (20, 50, 20, 30) if args.approved else (12, 10, 5, 10)

    F: list[str] = []
    rep: dict = {"url": args.url}
    url = args.url
    if args.discover:
        p = urlsplit(args.url)
        g0 = G(args, url)
        found = []
        for path in DISCOVER:
            u = f"{p.scheme}://{p.netloc}{path}"
            r = g0.raw("POST", u, json.dumps({"query": "{__typename}"}))
            ide = g0.raw("GET", u, None, headers={"Accept": "text/html"})
            gql = bool(r.get("json") and ("data" in r["json"] or "errors" in r["json"]))
            ui = bool(re.search(r"(?i)graphiql|graphql playground|altair|apollo sandbox|voyager|hasura console|banana cake pop", ide.get("text", "")))
            if gql or ui:
                found.append({"url": u, "graphql": gql, "ide": ui})
                if ui:
                    F.append(f"GQL-V-002: GraphQL IDE exposed at {u}")
        rep["discovered"] = found
        print(f"discovered: {found or 'none'}")
        gq = [f["url"] for f in found if f["graphql"]]
        if gq:
            url = gq[0]
        else:
            print("no GraphQL endpoint found")
    g = G(args, url)
    rep["endpoint"] = url

    if not args.skip_recon:
        base = g.q("{ __typename }")
        rep["baseline"] = {"status": base["status"], "body": base["text"][:200]}
        print(f"baseline {base['status']} {base['text'][:80]}")
        eng = [n for n, rx in ENGINE_HINTS if re.search(rx, base["text"] + json.dumps(base["headers"]), re.I)]
        bad = g.q("{ __typename ")
        eng += [n for n, rx in ENGINE_HINTS if re.search(rx, bad["text"] + json.dumps(bad["headers"]), re.I)]
        rep["engine_hints"] = sorted(set(eng))
        # transports
        tr = {}
        tr["GET"] = g.raw("GET", url + ("&" if "?" in url else "?") + "query=" + quote("{__typename}"))
        tr["form"] = g.raw("POST", url, "query=" + quote("{__typename}"), "application/x-www-form-urlencoded")
        tr["text/plain"] = g.raw("POST", url, json.dumps({"query": "{__typename}"}), "text/plain")
        ok = [k for k, r in tr.items() if has_data(r)]
        rep["transports"] = ok
        if ok:
            F.append(f"GQL-V-001: queries accepted via {ok} (CSRF risk for cookie-authenticated mutations; csrf-audit XSRF-019)")
        # introspection
        r = g.q(INTROSPECTION)
        schema = r["json"]["data"] if has_data(r) and r["json"]["data"].get("__schema") else None
        if not schema:
            for label, qq in (("newline", "query { __schema\n{ queryType { name } types { name } } }"), ("__type", '{ __type(name: "Query") { name fields { name } } }')):
                rr = g.q(qq)
                if has_data(rr):
                    F.append(f"GQL-001/GQL-V-004: introspection blocked for the full query but allowed via {label}")
                    rep.setdefault("introspection_bypass", []).append(label)
        if schema:
            summ = summarize(schema)
            rep["schema_summary"] = summ
            F.append(f"GQL-001: introspection enabled ({summ['types']} types, {len(summ['queries'])} queries, "
                     f"{len(summ['mutations'])} mutations, {len(summ['subscriptions'])} subscriptions)")
            if summ["dangerous_mutations"]:
                F.append(f"GQL-006 lead: sensitive mutations to test for access control: {summ['dangerous_mutations'][:8]}")
            if summ["subscriptions"]:
                F.append(f"GQL-007 lead: subscriptions to test over WebSocket: {summ['subscriptions'][:8]}")
            if summ["id_arguments"]:
                F.append(f"GQL-012 lead: {len(summ['id_arguments'])} ID arguments for IDOR testing, e.g. {summ['id_arguments'][:3]}")
            if summ["sensitive_fields"]:
                F.append(f"GQL-013 lead: sensitive fields to test for field-level authz: {summ['sensitive_fields'][:6]}")
            if args.schema_out:
                os.makedirs(os.path.dirname(os.path.abspath(args.schema_out)), exist_ok=True)
                json.dump({"data": schema}, open(args.schema_out, "w", encoding="utf-8"))
        # suggestions
        sug = []
        for qq in ("{ usr { id } }", "{ __typena }", "{ mee { id } }"):
            rr = g.q(qq)
            m = re.findall(r'Did you mean ([^?]+)\?', errors_text(rr))
            sug += [x.replace('\\"', '"').strip() for x in m]
        sug = list(dict.fromkeys(sug))
        if sug:
            rep["suggestions"] = sug[:10]
            F.append(f"GQL-009: field suggestions enabled: {sug[:3]}")
        # errors
        errs = []
        for label, qq, vars_ in (("syntax", "{ __typename ", None), ("bad-var-type", "query($a: Int){ __typename }", {"a": "x"}),
                                 ("unknown-type", "query($a: NoSuchType){ __typename }", {"a": 1}), ("deep-invalid", "{ __schema { types { name { x } } } }", None)):
            rr = g.q(qq, vars_)
            et = errors_text(rr)
            hits = sorted(set(m.group(0)[:40] for m in ERR_SIGS.finditer(et + rr.get("text", "")[:5000])))
            errs.append({"case": label, "status": rr["status"], "signatures": hits})
            if hits:
                F.append(f"GQL-010: {label} error discloses internals {hits[:4]}")
            if rr["status"] and rr["status"] >= 500:
                F.append(f"GQL-010: {label} returns HTTP {rr['status']}")
        rep["errors"] = errs
        # depth
        depth_res = []
        for d in [x for x in (3, 6, 9, 12, 16, 20) if x <= max_depth]:
            # each "fields { type { ... } }" wrap adds two levels below __schema.types
            inner = "name"
            for _ in range(max(1, (d - 2) // 2)):
                inner = "fields { type { " + inner + " } }"
            qq = "{ __schema { types { " + inner + " } } }"
            rr = g.q(qq)
            et = errors_text(rr).lower()
            limited = bool(re.search(r"depth|complex|cost|too (deep|large)|exceed", et))
            depth_res.append({"depth": d, "status": rr["status"], "data": has_data(rr), "limited": limited, "time": rr["time"]})
            if limited:
                break
        rep["depth"] = depth_res
        if depth_res and depth_res[-1]["data"] and not depth_res[-1]["limited"]:
            F.append(f"GQL-002/GQL-014: nested query accepted at depth {depth_res[-1]['depth']} without a depth/complexity error")
        # batching
        rr = g.raw("POST", url, json.dumps([{"query": "{ __typename }"}] * n_batch))
        batch_ok = isinstance(rr.get("json"), list) and len(rr["json"]) == n_batch
        rep["batching"] = {"sent": n_batch, "status": rr["status"], "supported": batch_ok}
        if batch_ok:
            F.append(f"GQL-003: array batching accepted ({n_batch} operations in one request; check rate limits on login/OTP)")
        # aliases
        qq = "{ " + " ".join(f"a{i}: __typename" for i in range(n_alias)) + " }"
        rr = g.q(qq)
        alias_ok = has_data(rr) and len(rr["json"]["data"]) == n_alias
        rep["aliases"] = {"sent": n_alias, "supported": alias_ok}
        if alias_ok:
            F.append(f"GQL-004: {n_alias} aliases accepted in one query (per-request rate limits can be bypassed)")
        # directives
        r1 = g.q("{ __typename @aaaa }")
        r2 = g.q("{ __typename " + " ".join(["@include(if: true)"] * n_dir) + " }")
        rep["directives"] = {"unknown_error": errors_text(r1)[:200], "repeated_accepted": has_data(r2)}
        if has_data(r2):
            F.append(f"GQL-005: {n_dir} repeated directives accepted (directive overloading; no directive limit)")
        if ERR_SIGS.search(errors_text(r1)):
            F.append("GQL-005/GQL-010: unknown directive error discloses internals")
        # APQ
        qtxt = "{ __typename }"
        h = hashlib.sha256(qtxt.encode()).hexdigest()
        ext = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": h}}}
        a1 = g.raw("POST", url, json.dumps(ext))
        apq = "persistedquerynotfound" in a1["text"].lower().replace("_", "") or "persisted" in a1["text"].lower()
        apq_info = {"enabled_hint": apq or has_data(a1)}
        if apq and not has_data(a1):
            g.raw("POST", url, json.dumps({"query": qtxt, **ext}))
            a3 = g.raw("POST", url, json.dumps(ext))
            apq_info["arbitrary_registration"] = has_data(a3)
            if has_data(a3):
                F.append("GQL-015: APQ lets clients register arbitrary queries (allowlist bypass if persisted queries are meant to restrict operations)")
        rep["apq"] = apq_info
        # federation / debug
        fed = g.q("{ _service { sdl } }")
        if has_data(fed):
            F.append("GQL-V-006: federation _service { sdl } exposed")
        if isinstance(base.get("json"), dict) and base["json"].get("extensions") and re.search(r"tracing|debug|cacheControl", json.dumps(base["json"]["extensions"])):
            F.append("GQL-V-005: debug/tracing extensions returned")
        print(f"recon done: engine={rep['engine_hints']} introspection={'yes' if schema else 'no'} batching={batch_ok} aliases={alias_ok}")

    if args.inject_query:
        if "FUZZ" not in args.inject_query:
            sys.exit("--inject-query needs FUZZ")
        inj = []
        base_r = g.q(args.inject_query.replace("FUZZ", "gqlbase"))
        for label, val in (("quote", "gql'"), ("dquote", 'gql\\"'), ("bool", "gql' OR '1'='1"), ("nosql", '{\\"$ne\\":null}'),
                           ("template", "{{7*7}}gql"), ("comment", "gql'--"), ("url", "http://127.0.0.1:80/")):
            rr = g.q(args.inject_query.replace("FUZZ", val))
            et = errors_text(rr) + rr.get("text", "")[:3000]
            sig = sorted(set(m.group(0)[:40] for m in ERR_SIGS.finditer(et)))
            diff = (rr["status"] != base_r["status"]) or (len(rr["text"]) != len(base_r["text"]))
            inj.append({"payload": label, "status": rr["status"], "signatures": sig, "differs": diff})
            if sig:
                F.append(f"GQL-008: payload {label} triggers backend error {sig[:3]}")
            if label == "template" and "49gql" in rr.get("text", ""):
                F.append("GQL-008: template expression evaluated in argument")
        rep["injection"] = inj

    if args.ops_file:
        ops = [json.loads(l) for l in open(args.ops_file, encoding="utf-8") if l.strip()]
        results = []
        for op in ops:
            is_mut = op.get("mutation") or op["query"].lstrip().startswith("mutation")
            if is_mut and not args.allow_mutations:
                results.append({"name": op.get("name"), "skipped": "mutation (use --allow-mutations for own harmless objects)"})
                continue
            ra = g.q(op["query"], op.get("variables"))
            rb = g.q(op["query"], op.get("variables"), headers=g.auth_b()) if args.auth_b else None
            rn = g.q(op["query"], op.get("variables"), headers={})
            rec = {"name": op.get("name") or op["query"][:60], "A": has_data(ra), "B": has_data(rb) if rb else None, "anon": has_data(rn),
                   "A_errors": errors_text(ra)[:150] if not has_data(ra) else ""}
            results.append(rec)
            nm = rec["name"]
            if rec["anon"]:
                F.append(f"{'GQL-006' if is_mut else 'GQL-012/GQL-013'}: '{nm}' returns data anonymously")
            if rec["A"]:
                F.append(f"{'GQL-006' if is_mut else 'GQL-012/GQL-013'} lead: '{nm}' (account B's object) returns data for account A; confirm the object belongs to B")
            print(f"op {nm[:50]:50} A={rec['A']} B={rec['B']} anon={rec['anon']}")
        rep["authz"] = results

    F = list(dict.fromkeys(F))
    rep["findings"], rep["requests"] = F, g.n
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {g.n}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
