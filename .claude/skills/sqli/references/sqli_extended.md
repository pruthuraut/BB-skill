# SQL Injection Extension (extension)

Detection only. Use balanced quotes and harmless arithmetic or delay values on your own test inputs. Never extract data beyond a row count you have approval for. Time-based probes need an approved delay and must be single requests.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SQLI-X-001 | All inputs | Quote break and repair (`'` vs `''`) response difference | bounded | Two requests, compare status and body length |
| SQLI-X-002 | Headers | Cookie, User-Agent, Referer, X-Forwarded-For injection | bounded | Benign arithmetic in one header at a time |
| SQLI-X-003 | UNION | Column count via ORDER BY on own input | bounded | ORDER BY 1..N differential |
| SQLI-X-004 | Error-based | Error signature on malformed input (MySQL, MSSQL, Oracle, PostgreSQL) | bounded | Single quote; grep signature only |
| SQLI-X-005 | Boolean blind | AND 1=1 versus AND 1=2 response difference | bounded | Two requests |
| SQLI-X-006 | Time blind | Delay with approved SLEEP/pg_sleep/WAITFOR (single request) | bounded | One request with 5 second delay vs baseline |
| SQLI-X-007 | Out-of-band | DNS or HTTP callback from DB | bounded | OOB host in the parameter (approved) |
| SQLI-X-008 | Clauses | ORDER BY, LIMIT, LIKE, IN, identifier contexts | bounded | Benign marker per context |
| SQLI-X-009 | Writes | INSERT, UPDATE, DELETE sinks | authorized-only | Balanced-only payloads on test records; approval required |
| SQLI-X-010 | Second order | Stored value executed later in async job | bounded | Own marker stored, observe job output |
| SQLI-X-011 | Stacked queries | Stacked statements accepted | authorized-only | Approved lab only |
| SQLI-X-012 | Stored procedures | Procedure name or parameter injection | authorized-only | Approved lab only |
| SQLI-X-013 | JSON | Injection through JSON string values | bounded | Own JSON body marker |
| SQLI-X-014 | GraphQL | Injection through arguments | bounded | See api-security API-X-006 |
| SQLI-X-015 | XML and SOAP | Injection through XML text nodes | bounded | Own XML marker |
| SQLI-X-016 | Arrays and HPP | Array or duplicate parameters interpreted as SQL | bounded | Duplicate param marker |
| SQLI-X-017 | Path segments | Injection in path ID (`/items/1'`) | bounded | Own path marker |
| SQLI-X-018 | Encoded values | Base64, hex, or signed value wrapping SQL | bounded | Decode own value, mutate marker |
| SQLI-X-019 | ORM | Raw fragments in HQL, ActiveRecord where, or Sequelize literal | passive | Code review |
| SQLI-X-020 | OData and filter DSLs | Filter expression injection | bounded | Own filter with marker |
| SQLI-X-021 | WAF bypass | Comment, versioned keyword, case, encoding variants | bounded | Benign marker variants only |
| SQLI-X-022 | DB specifics | MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Access, DB2, H2 fingerprint | bounded | Version string via error text or arithmetic |
| SQLI-X-023 | Impact | Impact mapping by privilege, not data extraction | passive | Report DB user role if disclosed; no extraction |
