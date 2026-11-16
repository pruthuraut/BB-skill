---
name: rest-api-audit
description: Audit authorized REST APIs across 15 checks — full CRUD coverage with cross-account authorization on your own disposable objects, improper HTTP method handling, HEAD information disclosure and HEAD-based auth bypass, OPTIONS/CORS disclosure, PUT/DELETE without authorization, URL/body/header parameter manipulation and injection (identity headers like X-User-Id, X-Role), HTTP status-code correctness, inconsistent error handling across endpoints, HATEOAS link manipulation and leakage, pagination bypass for data extraction, filter/sort injection (sort by sensitive fields, OData $filter, operator injection), deprecated-version security, and backward-compatibility issues (Accept-Version, api-version, vendor media types). Includes a scope-gated probe with an own-object CRUD lifecycle (A creates, B and anonymous try GET/PUT/PATCH/DELETE, A cleans up), HEAD/OPTIONS checks, identity-header tests, status-code matrix, HATEOAS link review, pagination and sort/filter probes, and version negotiation. Triggers on "REST API", "CRUD", "PUT", "DELETE", "PATCH", "HEAD method", "OPTIONS", "HATEOAS", "_links", "pagination", "sort parameter", "filter parameter", "$filter", "OData", "API version", "deprecated API", "Sunset header", or when an API follows resource-oriented URLs.
---

# REST API Audit (15 checks)

REST APIs expose resources through URLs and HTTP methods. Authorization must hold for every method on every resource, every input location (path, query, body, headers) must be validated, and older versions or alternative representations must not bypass current controls. This skill focuses on REST-specific behavior; generic API checks (tokens, keys, gateway bypass, mass assignment) live in `api-security` (AA/AI rows).

- Checklist: `references/rest_checklist.md` (RST-001 to RST-015, method/status expectations, sort/filter payloads, version negotiation list).
- Tracker: `references/rest_tracker.md`.
- `scripts/rest_probe.py`: scope-gated probe.
  - `--crud crud.json`: own-object lifecycle. A creates a disposable object, then B and anonymous try GET/PUT/PATCH/DELETE on it, then A deletes it.
  - Per endpoint: HEAD vs GET auth comparison, OPTIONS Allow/CORS, identity-header injection (`X-User-Id`, `X-Role`, ...), status codes for bad IDs and malformed bodies, HATEOAS link review, pagination edge values, sort/filter markers, and version negotiation (`Accept-Version`, `api-version`, vendor media types, `Deprecation`/`Sunset` headers).
- Related: `api-security` (`api_probe.py`, AA-007/AA-008/AA-017/AA-020), `idor`, `access-control`, `sqli`, `nosql-injection-audit`, `error-handling-audit`, `cors-audit`, `data-exposure-audit`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Map resources: from the OpenAPI spec, JS, and proxy history, list collections and item routes with their methods and ID formats. Run `api-security/../api-security/scripts/api_probe.py` first for the generic AA checks.
3. CRUD authorization (RST-001, RST-005): pick a resource type you can create harmlessly (note, draft, address, test item) and write `crud.json`:

   ```json
   {"collection": "/v1/notes", "create_body": {"title": "rest-audit"}, "update_body": {"title": "rest-audit-b"},
    "id_field": "id", "item_path": "/v1/notes/{id}"}
   ```

   ```bash
   python3 .agents/skills/rest-api-audit/scripts/rest_probe.py --target example.com --base https://api.example.com \
     --header 'Authorization: Bearer OWN_A' --header-b 'Authorization: Bearer OWN_B' --crud crud.json \
     --endpoints endpoints.txt --other-id B_USER_ID --out artifacts/example.com/rest.json
   ```

   `endpoints.txt` lists `GET /v1/notes`, `GET /v1/notes/{id}`, and so on, with your own IDs filled via `--param id=...`.
4. Review HEAD/OPTIONS (RST-003, RST-004), identity headers (RST-008), status codes and error consistency (RST-009, RST-010), HATEOAS links (RST-011), pagination (RST-012), sort/filter (RST-013), and versions (RST-014, RST-015) in the probe output.
5. Injection depth (RST-006, RST-007, RST-008, RST-013): follow up markers with sqli, nosql-injection-audit, command-injection-audit, and ssrf-audit on the same parameters.
6. Save findings to `artifacts/<target>/rest_api.json` and the tracker to `artifacts/<target>/rest_tracker.md`.

## Classes

- `passive`: spec and traffic review, HATEOAS link review.
- `bounded`: GET/HEAD/OPTIONS on own resources, the own-object CRUD lifecycle, marker payloads, edge-value pagination (counts only).
- `authorized-only`: PUT/PATCH/DELETE on objects you do not own, bulk data extraction through pagination bypass, and injection beyond detection.

## Rules

- Write methods only on objects created by your own account in the same run; the probe deletes them at the end (verify cleanup).
- Pagination bypass is proven with item counts, not by downloading other users' data.
- Identity-header tests use your second account's ID, never real users'.

## Mitigation guidance for reports

- Enforce object- and function-level authorization for every method (GET/HEAD/PUT/PATCH/DELETE) in one place; HEAD must follow GET's authorization.
- Return 405 with an accurate `Allow` header for unsupported methods; never route unexpected methods to handlers.
- Never trust identity headers from clients (`X-User-Id`, `X-Role`); strip them at the edge.
- Consistent status codes and error format across endpoints; no stack traces.
- Server-side caps on page size; signed or opaque cursors; allowlisted sort and filter fields.
- Retire old versions; if they must stay, keep current security controls; send `Deprecation`/`Sunset` and monitor usage.
- HATEOAS links built from server config (not Host headers), without tokens or internal hosts.

## Sources

RFC 9110 (HTTP semantics, methods, status codes), OWASP REST Security Cheat Sheet, OWASP API Security Top 10 (API1, API3, API5, API9), OWASP WSTG-CONF-06 (HTTP methods), RFC 8594 (Sunset header), CWE-285, CWE-650.
