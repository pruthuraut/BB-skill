---
name: sqli
description: Audit authorized applications for SQL injection across 50 checks — quote/break-repair probing of every input, URL parameters, Cookie/User-Agent/Referer/X-Forwarded-For and other headers, UNION column-count, error-based markers, blind boolean and time-based (SLEEP/WAITFOR/pg_sleep/DBMS_PIPE), out-of-band DNS/HTTP, ORDER BY / LIMIT / LIKE / IN / identifier contexts, INSERT/UPDATE/DELETE write sinks with balanced-only payloads, second-order and async sinks, stacked queries, stored procedures, JSON, GraphQL, XML/SOAP, arrays/HPP, path segments and parameter names, encoded and signed values, ORM/HQL raw fragments, OData/filter DSLs, WAF bypass (comments, versioned keywords, case, URL/double/Unicode/HTML-entity encoding, wide-byte), MySQL/PostgreSQL/MSSQL/Oracle/SQLite/Access/DB2/H2 specifics, and impact mapping without data extraction. Built on PortSwigger SQL injection labs and cheat sheet, OWASP WSTG-INPV-05 and the SQL Injection Prevention cheat sheet, PayloadsAllTheThings, pentestmonkey and sqlmap documentation.
---

# SQL Injection

Find where user input reaches a SQL query unparameterised, prove it with the least intrusive signal (D), optionally read one scalar fingerprint (P), and describe — rather than perform — data access and server-side escalation unless the program explicitly allows it.

Primary methodology sources:

- PortSwigger Web Security Academy — *SQL injection*, *Blind SQL injection*, *UNION attacks*, *Examining the database*, *SQL injection cheat sheet*; labs: hidden data in WHERE, login bypass, UNION column count / text column, conditional responses, conditional errors, visible error-based, time delays, out-of-band interaction / exfiltration, filter bypass via XML encoding, querying version on Oracle / MySQL / MSSQL
- OWASP WSTG v4.2 **WSTG-INPV-05** Testing for SQL Injection and 05.1–05.7 (Oracle, MySQL, SQL Server, PostgreSQL, MS Access, NoSQL, ORM); OWASP *SQL Injection Prevention* and *Query Parameterization* cheat sheets
- PayloadsAllTheThings *SQL Injection*; pentestmonkey cheat sheets (MySQL, MSSQL, Oracle, Postgres, DB2, Informix, Ingres); nibblesec MS Access cheat sheet; Reiners' MySQL filter-evasion cheat sheet; sqlmap usage wiki, `errors.xml` and tamper scripts; nav1n0x manual SQLi guide; rails-sqli.org; Claroty Team82 JSON-based WAF bypass
- Public HackerOne reports supplied with this skill (User-Agent, cookie, GraphQL, `countryFilter[]`, signature-bypassed `TransID`, `period-hour` reporting params, blind/time-based on login and search)
- CWE-89, CWE-564 (Hibernate), CWE-943

## Execution classes and safety boundary

Pass the scope gate before any request. Every check states the classes it may use:

| Class | Allowed actions | Requirement |
|---|---|---|
| **D** detect | break/repair, AND-based boolean pairs, arithmetic/concatenation inference, computed error markers (`bbsq49`), bounded time delays (≤ 5 s), OOB ping to your own collaborator without data | Default for in-scope targets |
| **P** proof | Read **one scalar**: DBMS version, current user, current database name, privilege flag | Default once D is confirmed; stop there unless permitted further |
| **S** data | Schema/table names, row counts, any row content | Explicit permission; prefer your own account's row; redact; never bulk-dump |
| **W** write | Anything that can change data beyond your own record — mutating stacked statements, OR-based payloads in UPDATE/DELETE, extra INSERT tuples | Explicit permission (rarely granted). Default write-sink testing is limited to balanced payloads against your own record |
| **X** server reach | File read (`LOAD_FILE`, `pg_read_file`, `OPENROWSET`), DB-initiated network carrying data, command execution (`xp_cmdshell`, `COPY … FROM PROGRAM`), file write (`INTO OUTFILE`, `ATTACH`) | File read of a benign file only with explicit permission. Command execution, web shells, UDFs, enabling `xp_cmdshell`/`sp_configure` are out of scope — report them as the escalation path |

Hard rules:
- **No `OR 1=1` in any sink that might be UPDATE/DELETE** — it rewrites every row. Use AND pairs, arithmetic, concatenation, or time.
- **Write sinks** (non-GET, profile/settings/registration/delete): balanced payloads only — no comment terminators (they cut off the WHERE clause), no stacked queries. `sqli_probe.py` enforces this with `--context write` (default for non-GET) and refuses DELETE.
- Time payloads ≤ 5 s, uncorrelated (evaluated once), one request at a time; heavy `BENCHMARK`/`RANDOMBLOB` only as a last resort with small N.
- Rate ≤ 2 req/s; sqlmap/ghauri only through `sqlmap_safe.sh`, after a manual signal, pinned to one parameter.
- Do not rotate IPs (proxychains, Tor, rotating proxies) to evade rate limits, WAF bans or program restrictions. Check whether the program forbids WAF-evasion testing before SQ-D.
- Use your own collaborator for OOB. Never reuse payload URLs or collector IDs from public notes.
- If real data appears by accident (UNION/error output), stop, do not store it, and redact evidence to column names.

## Inputs

1. `artifacts/discovered_parameters.json`, `artifacts/discovered_endpoints.txt`, HARs, `artifacts/flows/*.har` — candidates; prioritise names in [references/sqli_param_names.txt](references/sqli_param_names.txt) and features: login, signup, forgot/reset password, recovery, ticket creation, search, filters/sort/pagination, reports/exports, cart/checkout, order lookup, payment callbacks, profile update, comments/reviews, admin/CMS panels
2. `artifacts/technology_profile.json` — DBMS hints (stack, ORM, error pages), WAF/CDN
3. Two self-owned accounts for write sinks and second-order tests; your own collaborator domain
4. [references/dbms_cheatsheet.md](references/dbms_cheatsheet.md) for DBMS syntax; [references/checklist_50.md](references/checklist_50.md) for the ledger
5. Wordlists for Burp Intruder: `wordlists/sqltesting.txt` (break/detection strings), `wordlists/sqlbypass.txt` (filter-bypass operators); `wordlists/OR-Payloads.txt` contains OR tautologies, so use it only on a confirmed read-only SELECT sink and never on login, update or delete forms

## Workflow

1. **Map sinks.** For each candidate record: location (query, path, body, JSON, GraphQL variable, header, cookie, WebSocket, file import), legitimate value, HTTP method, probable statement (SELECT / INSERT / UPDATE / DELETE / ORDER BY / LIMIT / LIKE / IN / identifier), whether output is reflected, and async consumers. Write `artifacts/sqli/sink_map.md`.
2. **Passive first.** Scan existing responses and HARs for DBMS errors (`sqli_errors.py`) to pick DBMS families.
3. **Detect** each sink with `sqli_probe.py` (break/repair → boolean → arithmetic/concat → error marker → time; replace-mode families for ORDER BY / LIMIT / LIKE / IN). Write sinks use `--context write`.
4. **Confirm** (SQ-49): second true/false pair, linear time scaling, clean-session reproduction. Optionally `sqlmap_safe.sh` with `--technique=BT` pinned to the parameter.
5. **Prove** (P): version / current user via `--proof` or one UNION/error query. Map impact with P-class queries only (SQ-50).
6. **Bypass** (SQ-D) only where a filter/WAF blocked a confirmed-looking signal, and only if the program allows it.
7. **Report** with exact requests, the D/P evidence, the gated escalation path, and `[ N / 50 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **SQ-A** Injection Point Discovery | all fields, URL params, headers, INSERT/UPDATE/DELETE sinks, JSON, GraphQL, path/filename/param-name, XML/SOAP/multipart/import, arrays/HPP, extended headers, encoded values, signed params, WebSockets | 01, 02, 03, 11, 12, 13, 24, 25, 32, 33, 34, 35, 36, 37, 43 |
| **SQ-B** Detection Techniques | UNION, error-based, boolean, time, OOB, stacked, arithmetic/concat inference, error fingerprinting, false-positive elimination | 04, 05, 06, 07, 08, 15, 31, 45, 49 |
| **SQ-C** Query-Context Injection | ORDER BY, LIMIT/OFFSET, second-order, stored procedures, LIKE, IN, identifiers, OData/filter DSLs, ORM/HQL, login bypass, reports/exports, async second-order | 09, 10, 14, 21, 22, 23, 38, 39, 40, 41, 44, 48 |
| **SQ-D** Filter & WAF Bypass | comments/versioned keywords, case, URL/double/Unicode/HTML-entity encoding, wide-byte/escaping, tool-assisted confirmation | 16, 17, 18, 19, 20, 42, 47 |
| **SQ-E** DBMS-Specific & Impact | MySQL, PostgreSQL, MSSQL, Oracle, SQLite, other engines, impact mapping | 26, 27, 28, 29, 30, 46, 50 |

## Status values

- `PASS` — sink tested with the families relevant to its context and DBMS, no signal; evidence saved.
- `FINDING` — injection confirmed (D) with reproducible evidence, optionally P proof.
- `INFO` — verbose DB errors, unescaped LIKE wildcards, or a signal that could not be confirmed.
- `GATED` — escalation (S/W/X) not attempted for lack of permission; expected impact described.
- `NOT_APPLICABLE` — the feature, context or DBMS is absent; evidence cited.
- `BLOCKED` — WAF, rate limit, scope or tooling prevented testing.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Unauthenticated SQLi with stacked queries / DBA / sysadmin (RCE path), or reading other users' data across tenants | Critical |
| Any confirmed SQLi on a production DB reachable by a normal user (boolean/time/error/UNION) | High–Critical (data reachable by the DB account) |
| SQLi limited to a low-privilege, isolated or read-only schema; authenticated-only with narrow reach | Medium–High |
| Login bypass as your own account via SQLi | Critical (auth logic broken for all accounts) |
| Verbose SQL errors without injection, unescaped LIKE wildcards | Low / Informational |

## Helper scripts

```bash
S=.agents/skills/sqli/scripts

# Offline: DBMS error signatures in saved responses or a HAR
python3 -I $S/sqli_errors.py artifacts/sqli/responses/
python3 -I $S/sqli_errors.py --har artifacts/flows/all.har

# Offline: payload generator (TSV family/context/dbms/variant/class/payload) with WAF transforms
python3 -I $S/sqli_payloads.py --dbms mysql --contexts sq,num --families break,boolean,error,time --sleep 3
python3 -I $S/sqli_payloads.py --dbms mysql,postgres --contexts sq --write-context          # balanced only
python3 -I $S/sqli_payloads.py --contexts sq --families union --columns 4 --transform versioned,case
python3 -I $S/sqli_payloads.py --dbms mssql,oracle,postgres --contexts num --families oob --collab "$COLLAB"

# Scope-gated detector for one injection point (FUZZ in --url / --data / --json / one --header)
python3 -I $S/sqli_probe.py --target example.com --url 'https://app.example.com/item?id=FUZZ' --value 39
python3 -I $S/sqli_probe.py --target example.com --url 'https://app.example.com/list?sort=FUZZ' --value name --families orderby
python3 -I $S/sqli_probe.py --target example.com --url 'https://app.example.com/api/profile' \
  --data 'displayName=FUZZ' --value myname --context write --families break,time
python3 -I $S/sqli_probe.py --target example.com --url 'https://app.example.com/' --value abc \
  --header 'Cookie: TrackingId=FUZZ' --families time --dbms postgres,mysql
python3 -I $S/sqli_probe.py ... --families error --proof          # class P: version/current user via error channel

# Scope-gated sqlmap/ghauri wrapper (refuses shells/file write; gates data flags, --file-read, --risk=3)
bash $S/sqlmap_safe.sh example.com -r artifacts/sqli/req_item.txt -p id --technique=BT --level 3 -b --current-user
SQLMAP=ghauri bash $S/sqlmap_safe.sh example.com -r artifacts/sqli/req_item.txt -p id --level 3
```

Probe verdicts: `ERROR` (break error cleared by repair), `ERROR?` (DBMS error without a clean repair, typical of numeric contexts), `BOOLEAN`, `ARITH`, `CONCAT`, `ERROR_MARKER`, `TIME`, `PROOF(P)`. Outputs: `probe.tsv` (every request) and `probe_verdicts.json`.

Related tools: Burp Scanner and Repeater, Burp extensions Agartha (payload generation) and SQLiPy; `sqlmap` / `ghauri` (through the wrapper); `gf sqli` patterns over URL archives to shortlist candidates; Arjun / x8 for hidden parameters; `nuclei` error-based templates for triage only (confirm manually); Atlas for tamper suggestions.

## Required artifacts

- `artifacts/sqli/sink_map.md`
- `artifacts/sqli/probe_*.tsv` and `probe_*_verdicts.json`
- `artifacts/sqli/evidence/SQ-XX_<short>.txt` — exact request/response pairs, timings; data redacted
- `artifacts/sqli/sqli_checklist_50.tsv` — `check_id  status  class_performed  class_untested  severity  finding_id  evidence_path  notes`
- `artifacts/sqli_report.md` — findings, DBMS/version (P), impact mapping, gated escalation paths, `[ N / 50 ]`

## Related skills

- `linkparamdiscovery` / `contentdiscovery` — candidate parameters and endpoints; `techfingerprint` — DBMS/ORM/WAF hints
- `authbypass` — login SQLi/NoSQLi/LDAP bypass (AB checks) and SQL truncation; this skill owns the injection itself
- `api-security` — GraphQL/REST surfaces (SQ-24/25/39); `idor` — ID parameters reused here
- `session-management` — JWT/cookie values used in lookups (SQ-36); `ssrf-audit` — DB-initiated egress (SQ-08)
- `resource-exhaustion` — heavy time payloads and rate limits

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, sqlmap/ghauri runs, OOB payloads, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- Classes S, W and X need explicit permission in addition to the scope gate; record it in the report. The wrapper flags `BB_SQLI_ALLOW_DATA`, `BB_SQLI_ALLOW_FILE` and `BB_SQLI_ALLOW_RISK3` are set only when that permission exists.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` (or a TARGET argument) run the same gate and refuse to start otherwise.
