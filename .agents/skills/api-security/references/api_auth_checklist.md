# API Authentication and Authorization Checklist (AA, 25 checks)

Class key: `passive` = JS, specs, traffic review. `bounded` = requests with your own credentials, random non-existent IDs for method tests, small bursts (≤ 30) for rate limits. `authorized-only` = brute force, real users' data, destructive methods on real objects, key revocation on shared keys.

Probe: `scripts/api_probe.py` (spec- or endpoint-list driven; see SKILL.md "API probe").

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| AA-001 | Auth | Broken authentication on API endpoints: endpoints answer without credentials, with a malformed/expired token, or with another app's token | bounded | api_probe.py `unauth` and `tokens` on every GET from the spec |
| AA-002 | Keys | API keys exposed in client-side JavaScript (secret keys, admin keys, server-to-server keys) | passive | data-exposure-audit DE-003, saas-third-party-exposure classification |
| AA-003 | Keys | API key accepted in URL parameters (`?api_key=`, `?key=`, `?token=`) instead of headers (logs, Referer, history) | bounded | api_probe.py `keyinurl` moves your own key from header to query |
| AA-004 | Bearer | Bearer token validation: signature not checked, `alg:none`, expired tokens accepted, tokens of other audiences accepted, token not bound to user | bounded | api_probe.py `tokens` (tampered, truncated, empty, `none`); session-management and crypto-audit CRY-014 for JWT depth |
| AA-005 | OAuth | OAuth 2.0 token security in APIs: scopes not enforced, tokens from other clients accepted, refresh tokens reusable, tokens in URLs | bounded | oauth-sso rows; AA-023 for scopes |
| AA-006 | Rate limit | API rate limiting and throttling missing on sensitive endpoints (login, OTP, search, export, password reset) | bounded | api_probe.py `ratelimit` burst of ≤ 30 on an own endpoint; record 429/headers |
| AA-007 | Methods | Proper HTTP methods per endpoint (unexpected PUT/DELETE/PATCH routed; GET with side effects) | bounded | api_probe.py `methods` on a random non-existent ID (405 vs 401/403/404 routing map) |
| AA-008 | Versions | API versioning security: older versions (`/v1`, `/v0`, `/beta`, `/internal`) reachable with weaker auth or fewer checks | bounded | api_probe.py `versions` swaps version segments on own requests |
| AA-009 | Mass assignment | Mass assignment in request bodies (`role`, `isAdmin`, `owner_id`, `balance`, `verified`, `plan`) | bounded | Own account update with extra fields; access-control and authbypass rows |
| AA-010 | Validation | Input validation on API requests (types, ranges, lengths, formats, unknown fields, nested objects) | bounded | error-handling-audit `error_probe.py --json-body` |
| AA-011 | Filtering | Response field filtering: client-side filtering only, `fields=`/`select=`/`include=`/`expand=` parameters reveal hidden fields | bounded | api_probe.py `fields` adds `fields=*`, `expand=all`, `include=` variants to own GETs |
| AA-012 | Excess data | Excessive data exposure in responses (hashes, tokens, internal flags, other users' PII) | passive | data-exposure-audit `api_pii_scan.py` on own HAR |
| AA-013 | Tampering | Parameter tampering: IDs, prices, roles, tenant IDs, booleans changed in requests | bounded | idor, access-control, business-logic-vulns |
| AA-014 | Enumeration | API endpoint enumeration via brute force (kiterunner, ffuf with API wordlists) | bounded | contentdiscovery with `wordlists/` API lists at program rate limits |
| AA-015 | Docs | API documentation exposure (Swagger UI, OpenAPI JSON/YAML, Postman collections, `/api-docs`, `/swagger.json`, `/openapi.yaml`, `/redoc`) | bounded | api_probe.py `docs` |
| AA-016 | GraphQL | GraphQL introspection access | bounded | graphql-audit GQL-001 |
| AA-017 | Verb tampering | REST verb tampering and method override (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `_method`) bypassing method-based authorization | bounded | api_probe.py `override` (POST + override header to random-ID path) |
| AA-018 | CORS | API CORS configuration and origin validation | bounded | cors-audit `cors_probe.py` |
| AA-019 | Content type | Request/response content-type validation (JSON endpoint accepts form/XML/text; XML parser reachable → XXE; responses without proper type) | bounded | api_probe.py `ctype` on own POST; xml-xxe-audit if XML is parsed |
| AA-020 | Pagination | Pagination security: `limit`/`per_page`/`size` caps missing, negative or zero values, cursor tampering leaking other tenants | bounded | api_probe.py `pagination` (counts only, own scope) |
| AA-021 | Key lifecycle | API key rotation and revocation: revoked or rotated keys still work, no expiry, keys survive user deletion or password change | bounded | Own keys: create, revoke, retry; own account only |
| AA-022 | Token lifecycle | Token expiration and refresh flow: long-lived access tokens, refresh tokens not rotated or reusable after use, tokens valid after logout | bounded | Own tokens over time; session-management refresh rows |
| AA-023 | Scopes | API scope limitation and permission boundaries: read-only key can write, scoped token reaches other resources, tenant scoping missing | bounded | Own key with limited scope; try write/admin operations on own objects only |
| AA-024 | Gateway | API gateway authentication bypass: direct backend/origin access, path normalization (`/api/v1/../admin`, `%2f`, case, trailing slash, `;`), internal headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`) | bounded | api_probe.py `gateway` variants on own requests; origin access per cloud-supplychain CLD-ALB-001 |
| AA-025 | Referer | API key or token leaked in Referer to third parties (key in page URL + external resources) | passive | data-exposure-audit DE-020 |

## Cross-references

| AA row | Related rows |
|---|---|
| AA-001, AA-004 | API-X-020, session-management, crypto-audit CRY-014 |
| AA-002, AA-025 | data-exposure-audit DE-003, DE-020 |
| AA-005, AA-023 | oauth-sso |
| AA-006 | resource-exhaustion, race-conditions RC-013 |
| AA-008 | API-X-018 |
| AA-009 | API-X-016, access-control |
| AA-011, AA-012 | API-X-017, data-exposure-audit DE-016/DE-017 |
| AA-015 | API-X-013 to API-X-015 |
| AA-016 | graphql-audit |
| AA-017 | rest-api-audit RST-002 |
| AA-018 | cors-audit |
| AA-019 | API-X-019 |
| AA-020 | rest-api-audit RST-012 |
| AA-024 | API-X-020 |
