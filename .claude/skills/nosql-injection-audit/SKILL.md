---
name: nosql-injection-audit
description: Audit authorized applications for NoSQL injection, mainly MongoDB and similar document stores (CouchDB, Cassandra, Redis, BSON). Covers operator injection ($ne, $gt, $regex, $exists, $in, $nin, $where), JSON and form bracket syntax (param[$ne]=x), syntax and quote breaks, boolean and timing tests, authentication bypass shapes on your own accounts, ObjectId and type confusion, and aggregation or map-reduce sinks reviewed in source. Differential probe with a control. Triggers on "NoSQL injection", "MongoDB", "$ne", "$regex", "$where", "operator injection", "mongoose", "BSON", "CouchDB view", "Cassandra CQL", "Redis EVAL", or when route_target.py routes filter, where, username, or password parameters.
---

# NoSQL Injection Audit

Find where request data reaches a NoSQL query as an object or as JavaScript instead of as a plain value. The probe is differential: an operator is reported only when it changes the response and a control operator that can never match does not. Data is never extracted.

Checklist: `references/nosql_checklist.md`. Tool: `scripts/nosql_probe.py`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Identify query fields: login (username, password), filters, search, ids, sort, and any JSON body that maps to a query. Route with `route_target.py --params`.
3. Run the differential probe on your own account or a test field:

   ```
   python3 .agents/skills/nosql-injection-audit/scripts/nosql_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --url https://example.com/api/login --param username \
     --json-body --other password=<your-test-password> --out artifacts/example.com/nosql.json
   ```

   Use `--method GET` and omit `--json-body` for bracket-style query strings. The probe sends at most 30 requests.
4. Read `verdict` and `control_matches_baseline`. Confirm with one more operator pair (for example `$exists` against a second field) before reporting.
5. Timing (optional, needs approval): add `--allow-timing --sleep 3`. Repeat and compare with the control.
6. Source review (if in scope): search for query objects built from `req.body`, `request.json`, or `params` without a type check, and for `$where` with string concatenation.
7. Save evidence to `artifacts/<target>/nosql.json`.

## Classes

- `passive`: source review, error text, and documentation of the query layer.
- `bounded`: operator and syntax differential tests on your own account, the tautology and contradiction checks.
- `authorized-only`: timing, data-reading operators (`$lookup`, `$regex` extraction loops), aggregation and map-reduce sinks, any write (`insert`, `update`, `remove`), and Redis `EVAL`.

## Rules

- Stop at the differential evidence. Do not extract records, do not iterate `$regex` to read values, and do not write to any collection.
- Use your own accounts. For an authentication bypass shape, use your own account and a wrong password.
- Never run map-reduce or aggregation payloads that insert data.
- Redact any credential or record content that appears in responses.
- Report the field, the operator that changed the response, the control result, and the fix: reject objects where a scalar is expected, use schema validation, and avoid building queries from request objects.
