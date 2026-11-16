# REST API Checklist

Class key: `passive` = spec, traffic, link review. `bounded` = GET/HEAD/OPTIONS on own resources, own-object CRUD lifecycle, markers, edge-value pagination counts. `authorized-only` = writes on objects you do not own, bulk extraction, injection beyond detection.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RST-001 | CRUD | All CRUD operations (GET, POST, PUT, PATCH, DELETE) exercised for each resource with owner, other account, and anonymous | bounded | rest_probe.py `--crud` lifecycle on an own disposable object |
| RST-002 | Methods | Improper HTTP method handling: unsupported methods routed, method-specific checks only on some verbs, GET with side effects, `Allow` header inaccurate | bounded | rest_probe.py method statuses vs `Allow`; api-security AA-007/AA-017 |
| RST-003 | HEAD | HEAD information disclosure or auth bypass (HEAD 200 where GET is 401/403; headers reveal length, ETag, internal info) | bounded | rest_probe.py HEAD vs GET without credentials |
| RST-004 | OPTIONS | OPTIONS discloses methods, CORS policy, or internal details; preflight allows any origin | bounded | rest_probe.py OPTIONS with a foreign Origin; cors-audit |
| RST-005 | Authz | PUT/DELETE (and PATCH) without proper authorization (other account or anonymous can modify/delete) | bounded | rest_probe.py `--crud` B/anonymous write attempts on A's object |
| RST-006 | URL params | URL path and query parameter manipulation and injection (IDs, path traversal, type confusion, markers) | bounded | rest_probe.py markers; idor, path-traversal, sqli |
| RST-007 | Body params | Body parameter manipulation and injection (extra fields, nested objects, arrays, type confusion) | bounded | Own create/update with extra fields; api-security AA-009, nosql-injection-audit |
| RST-008 | Header params | Header parameter manipulation and injection: identity/role headers trusted (`X-User-Id`, `X-Role`, `X-Remote-User`, `X-Tenant-Id`), `X-Forwarded-*`, custom headers reaching queries | bounded | rest_probe.py identity headers with your second account's ID |
| RST-009 | Status codes | Proper HTTP status codes (404 vs 403 for others' objects, 400/422 for bad input, 201/204 for writes, no 200-with-error) | bounded | rest_probe.py status matrix |
| RST-010 | Errors | Inconsistent error handling across endpoints (some leak stack traces, some return 500, different formats) | bounded | rest_probe.py status matrix; error-handling-audit |
| RST-011 | HATEOAS | HATEOAS link manipulation: links built from Host/X-Forwarded-Host, links to internal hosts or other tenants, tokens in links, links exposing hidden actions | bounded | rest_probe.py link review; Host header variants per server-config-audit SMC-012 |
| RST-012 | Pagination | Pagination bypass for data extraction (no cap, negative/zero values, offset beyond range, cursor tampering, `page_size` aliases) | bounded | rest_probe.py edge values (counts only); api-security AA-020 |
| RST-013 | Sort / filter | Filtering and sorting injection (sort by hidden/sensitive fields as an oracle, SQL in `sort`/`order`, OData `$filter`, operator injection `filter[role][$ne]`, RSQL/FIQL) | bounded | rest_probe.py sort/filter markers; sqli ORDER BY rows, nosql-injection-audit |
| RST-014 | Deprecation | API version deprecation security: deprecated versions still live with weaker controls, missing `Deprecation`/`Sunset`, no auth on old versions | bounded | rest_probe.py version headers; api-security AA-008 |
| RST-015 | Compatibility | Backward compatibility issues: old request formats, version headers (`Accept-Version`, `api-version`, `X-API-Version`, vendor media types `application/vnd.x.v1+json`) restore removed fields or skip new checks | bounded | rest_probe.py version negotiation variants on own GETs |

## Expected method and status behavior

| Case | Expected |
|---|---|
| Unsupported method | 405 + accurate `Allow` |
| HEAD | Same status and headers as GET, no body, same authorization |
| Other user's object | 404 (preferred) or 403, never 200 |
| Anonymous on protected route | 401 |
| Created | 201 + `Location` |
| Deleted / updated without body | 204 |
| Malformed body | 400 / 415 / 422 |

## Sort and filter payloads (markers only)

| Payload | Purpose |
|---|---|
| `sort=password`, `sort=password_hash`, `sort=email`, `order_by=secret` | Sorting by hidden fields leaks ordering (oracle) |
| `sort=id'`, `sort=id,(select 1)`, `sort=1 desc--` | SQL in ORDER BY (sqli skill for confirmation) |
| `sort=-id`, `sort[]=id`, `sort={"$natural":1}` | Parser and type behavior |
| `filter[role]=admin`, `filter[owner_id]=OTHER_OWN_ID`, `filter[email][$ne]=x` | Filter on fields not exposed; operator injection |
| `$filter=role eq 'admin'`, `$filter=startswith(email,'a')`, `$select=*`, `$expand=*` | OData |
| `q=role==admin`, `search=email=like=a*` | RSQL/FIQL |

## Version negotiation variants

`/v1/` `/v0/` `/v2/` path segments; `?version=1`, `?api-version=2019-01-01`, `?v=1`; headers `Accept-Version: 1`, `X-API-Version: 1`, `Api-Version: 1`; `Accept: application/vnd.<vendor>.v1+json`; response headers `Deprecation`, `Sunset`, `Link: <...>; rel="deprecation"`.

## Cross-references

| RST row | Related rows |
|---|---|
| RST-002 | api-security AA-007, AA-017 |
| RST-004 | cors-audit |
| RST-005 | access-control, idor |
| RST-007 | api-security AA-009 |
| RST-009, RST-010 | error-handling-audit EH-009 |
| RST-011 | server-config-audit SMC-012 |
| RST-012 | api-security AA-020 |
| RST-013 | sqli, nosql-injection-audit |
| RST-014, RST-015 | api-security AA-008 |
