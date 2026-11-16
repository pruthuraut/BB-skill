# NoSQL Injection Checklist

Class key: `passive` = source, errors, documentation. `bounded` = differential tests on your own account, at most 30 requests per field. `authorized-only` = timing, data-reading or writing operators, aggregation, map-reduce, and Redis EVAL.

## Syntax and conditional tests

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-SYN-001 | MongoDB | Quote breaks syntax (`'`) and error text appears | bounded | `nosql_probe.py` syntax probe; grep error signatures |
| NOSQL-SYN-002 | MongoDB | Fuzz characters (`'"{;$Foo}$Foo \xYZ`) change the response | bounded | Syntax probe on own field |
| NOSQL-SYN-003 | JavaScript-where | False condition (`' && 0 && 'x`) differs from true (`' && 1 && 'x`) | bounded | Probe pair; compare responses |
| NOSQL-SYN-004 | JavaScript-where | Always-true override (`'||1||'`, URL-encoded) matches all records | bounded | Own test field; differential only |
| NOSQL-SYN-005 | Generic | Individual characters identify syntax interpretation | bounded | Single-character probes, compare |
| NOSQL-SYN-006 | Mongoose / PyMongo | Cast or BSON error text names the driver | passive | Grep error text |

## Operator injection

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-OP-001 | MongoDB | `$ne` with a non-matching value changes the response | bounded | `nosql_probe.py`; control `$eq` must match baseline |
| NOSQL-OP-002 | MongoDB | `$gt` empty string matches all | bounded | Probe |
| NOSQL-OP-003 | MongoDB | `$exists: true` matches records | bounded | Probe |
| NOSQL-OP-004 | MongoDB | `$regex` any-match (`^.*`) vs impossible regex control | bounded | Probe pair |
| NOSQL-OP-005 | MongoDB | `$in` with common names (admin, root, administrator) | bounded | Own test field; differential only |
| NOSQL-OP-006 | MongoDB | `$nin` with random value | bounded | Probe |
| NOSQL-OP-007 | MongoDB | `$lt` or `$gt` comparison changes results | bounded | Two probes at different thresholds; differential only |
| NOSQL-OP-008 | MongoDB | `$regex` used to read values character by character | authorized-only | Not run by this skill; report the oracle exists |
| NOSQL-OP-009 | MongoDB | Operator in array form (`param[]=value`, `param[$ne]=x`) | bounded | Form-encoded bracket probe (omit `--json-body`) |
| NOSQL-OP-010 | MongoDB | Operator in JSON body (`{"username":{"$ne":null}}`) | bounded | JSON mode probe |
| NOSQL-OP-011 | MongoDB | `$where` tautology `1 == 1` vs contradiction `1 == 0` | bounded | Probe pair |
| NOSQL-OP-012 | MongoDB | `$where` timing with `sleep` | authorized-only | `--allow-timing` only with approval; repeat with a control |
| NOSQL-OP-013 | MongoDB | Type confusion: number where a string is expected | bounded | `type confusion` probe |
| NOSQL-OP-014 | MongoDB | ObjectId parameter accepts operators or strings | bounded | Own ObjectId with operator wrapper; differential |

## Authentication bypass shapes (own account only)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-AUTH-001 | Login | `username[$ne]` with `password[$ne]` returns a session | bounded | Own login flow with wrong password only; do not use real accounts |
| NOSQL-AUTH-002 | Login | `username[$regex]=.*` with `password[$regex]=.*` | bounded | Same restriction |
| NOSQL-AUTH-003 | Login | `username[$exists]=true` with `password[$exists]=true` | bounded | Same restriction |
| NOSQL-AUTH-004 | Login | JSON null or undefined operator (`{"$ne": null}`, `{"$gt": undefined}`) | bounded | Same restriction |
| NOSQL-AUTH-005 | Login | `$in` list of common admin names | bounded | Same restriction |
| NOSQL-AUTH-006 | Login | Boolean pair via `$where` with `this.password.match` | authorized-only | Lab only; not run against production |

## Other stores and features

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-OTH-001 | CouchDB | Injection through view functions or key parameters | passive | Review design docs for user-controlled map code |
| NOSQL-OTH-002 | Cassandra | CQL query manipulation through string concatenation | bounded | Quote break on own record; error text only |
| NOSQL-OTH-003 | Redis | `EVAL` reachable from user input | authorized-only | Do not send EVAL. Report the reachability from code review or the port banner |
| NOSQL-OTH-004 | Mongo Express | Query evaluation in the query box (CVE-2019-10758) | passive | Version check only |
| NOSQL-OTH-005 | Elasticsearch | Query DSL built from user input | bounded | Own record with a benign query term |

## Aggregation, map-reduce, and data access

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-AGG-001 | MongoDB | `$expr` operator injected into aggregation | passive | Review code that passes request data into aggregation |
| NOSQL-AGG-002 | MongoDB | Aggregate pipeline stage from user input (`$lookup`, `$out`) | authorized-only | Review only; do not run `$lookup` or `$out` against data |
| NOSQL-AGG-003 | MongoDB | Map-reduce function from user input | authorized-only | Review only; map-reduce writes are never run |
| NOSQL-AGG-004 | MongoDB | BSON type confusion in filters | bounded | Type probe on own field |

## Source review

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-SRC-001 | Node.js and Mongoose | Query built from `req.body` or `req.query` without type checks | passive | Grep for `find(req.body`, `findOne({ ... req.`, and `$where` concatenation |
| NOSQL-SRC-002 | Python and PyMongo | Filter dict built from `request.json` or form values | passive | Grep for `find(request.` and `json` merged into filters |
| NOSQL-SRC-003 | Any | `$where` with string concatenation | passive | Grep for `$where` and `where:` |

## Reporting

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| NOSQL-RPT-001 | Evidence | Request, operator, control result, and status or length difference | passive | Include in the report |
| NOSQL-RPT-002 | Fix | Reject objects where a scalar is expected; validate types with schema tools | passive | Recommendation |
| NOSQL-RPT-003 | Fix | Build queries from explicit fields, never from request objects | passive | Recommendation |
| NOSQL-RPT-004 | Fix | Disable server-side JavaScript (`$where`) and map-reduce where the app does not need them | passive | Recommendation |
