#!/usr/bin/env python3
"""DBMS error-signature matcher (offline). Also imported by sqli_probe.py.

Usage:
  sqli_errors.py FILE_OR_DIR [...]        scan response bodies, saved pages, logs
  sqli_errors.py --har capture.har         scan every response in a HAR (prints request URL per hit)

Prints: dbms <TAB> pattern <TAB> source <TAB> first matching line (truncated).
Signatures follow sqlmap's errors.xml families plus ORM/driver exceptions.
"""
import argparse
import base64
import json
import os
import re
import sys

SIGNATURES = {
    "MySQL": [r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"MySQLSyntaxErrorException", r"valid MySQL result",
              r"check the manual that (corresponds|fits) to your (MySQL|MariaDB) server version", r"MySqlClient\.",
              r"com\.mysql\.jdbc", r"Unknown column '[^']+' in '(field list|where clause|order clause)'",
              r"XPATH syntax error:", r"pymysql\.err\.", r"MySQLdb\._exceptions", r"ER_PARSE_ERROR"],
    "PostgreSQL": [r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result", r"Npgsql\.",
                   r"PG::[A-Za-z]+Error", r"org\.postgresql\.util\.PSQLException", r"ERROR:\s+syntax error at or near",
                   r"unterminated quoted string at or near", r"invalid input syntax for (type )?integer",
                   r"psycopg2?\.errors?\.", r"current transaction is aborted"],
    "MSSQL": [r"Driver.*? SQL[\-_ ]*Server", r"OLE DB.*? SQL Server", r"\bSQL Server[^&<\"]+Driver",
              r"Warning.*?\W(mssql|sqlsrv)_", r"System\.Data\.SqlClient\.", r"Microsoft\.Data\.SqlClient",
              r"Unclosed quotation mark after the character string", r"Microsoft SQL Native Client error",
              r"com\.microsoft\.sqlserver\.jdbc", r"Incorrect syntax near", r"Conversion failed when converting"],
    "Oracle": [r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver", r"Warning.*?\W(oci|ora)_",
               r"quoted string not properly terminated", r"SQL command not properly ended", r"oracle\.jdbc"],
    "SQLite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
               r"Warning.*?\W(sqlite_|SQLite3::)", r"\[SQLITE_ERROR\]", r"SQLite error \d+:",
               r"sqlite3\.OperationalError", r"SQLITE_ERROR", r"unrecognized token:"],
    "MSAccess": [r"Microsoft Access (\d+ )?Driver", r"JET Database Engine", r"Access Database Engine",
                 r"ODBC Microsoft Access", r"Syntax error \(missing operator\) in query expression"],
    "DB2": [r"CLI Driver.*?DB2", r"DB2 SQL error", r"\bdb2_\w+\(", r"SQLSTATE.+SQLCODE", r"com\.ibm\.db2"],
    "Informix": [r"Exception.*?Informix", r"Informix ODBC Driver", r"com\.informix\.jdbc", r"weblogic\.jdbc\.informix"],
    "Sybase": [r"Warning.*?\Wsybase_", r"Sybase message", r"Sybase.*?Server message", r"SybSQLException"],
    "H2/HSQLDB": [r"org\.h2\.jdbc", r"\[42\d{3}-\d{3}\]", r"org\.hsqldb\.jdbc", r"Unexpected end of command in statement \["],
    "ClickHouse": [r"ClickHouse exception", r"DB::Exception:", r"Code: \d+\. DB::Exception"],
    "Generic/ORM": [r"SQLSTATE\[\w+\]", r"PDOException", r"java\.sql\.SQL\w*Exception", r"QuerySyntaxException",
                    r"SQLGrammarException", r"org\.hibernate\.(hql|query)", r"ActiveRecord::StatementInvalid",
                    r"SequelizeDatabaseError", r"django\.db\.utils\.", r"sqlalchemy\.exc\.", r"knex:",
                    r"Prisma(ClientKnownRequestError|.*Raw query failed)", r"ODBC SQL Server Driver",
                    r"Syntax error in string in query expression", r"unterminated (quoted )?string"],
}
COMPILED = [(dbms, p, re.compile(p, re.I)) for dbms, pats in SIGNATURES.items() for p in pats]


def match(text):
    """Return list of (dbms, pattern, line) for every signature found in text."""
    hits, seen = [], set()
    for dbms, p, rx in COMPILED:
        m = rx.search(text)
        if m and (dbms, p) not in seen:
            seen.add((dbms, p))
            s = text.rfind("\n", 0, m.start()) + 1
            e = text.find("\n", m.end())
            hits.append((dbms, p, text[s: e if e != -1 else None].strip()[:200]))
    return hits


def guess(text):
    """Most likely DBMS (first non-generic hit) or None."""
    hits = match(text)
    for d, _, _ in hits:
        if d != "Generic/ORM":
            return d
    return hits[0][0] if hits else None


def scan_har(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in har.get("log", {}).get("entries", []):
        c = ent.get("response", {}).get("content", {})
        t = c.get("text") or ""
        if c.get("encoding") == "base64":
            try:
                t = base64.b64decode(t).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
        for d, p, line in match(t):
            yield d, p, ent.get("request", {}).get("url", "?"), line


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--har")
    a = ap.parse_args()
    if not a.paths and not a.har:
        ap.error("give files/directories or --har")
    n = 0
    print("dbms\tpattern\tsource\tline")
    if a.har:
        for d, p, src, line in scan_har(a.har):
            print(f"{d}\t{p}\t{src}\t{line}")
            n += 1
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                files += [os.path.join(root, f) for f in fs]
        else:
            files.append(p)
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                t = fh.read(5_000_000)
        except OSError:
            continue
        for d, p, line in match(t):
            print(f"{d}\t{p}\t{f}\t{line}")
            n += 1
    print(f"[+] {n} signature hits", file=sys.stderr)


if __name__ == "__main__":
    main()
