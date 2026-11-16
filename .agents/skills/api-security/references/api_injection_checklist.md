# API Injection and Manipulation Checklist (AI, 15 checks)

Class key: `passive` = specs and traffic review. `bounded` = marker payloads on own requests, small bursts, single requests per variant. `authorized-only` = compression bombs, timeout exhaustion, IP rotation at scale, smuggling confirmation, and anything affecting other users.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| AI-001 | SQLi | SQL injection in API query and body parameters (JSON values, nested fields, arrays, sort/filter params) | bounded | sqli skill on own requests; error_probe.py for error signatures |
| AI-002 | NoSQLi | NoSQL injection in JSON bodies (`{"$ne":null}`, `{"$gt":""}`, `$where`, `$regex`) | bounded | nosql-injection-audit `nosql_probe.py` |
| AI-003 | Command injection | Command injection via API parameters (hostnames, filenames, conversion options) | bounded | command-injection-audit `cmdi_probe.py` |
| AI-004 | SSRF | SSRF via URL parameters and webhook URLs (callbacks, avatars, imports, integrations) | bounded | ssrf-audit with own OOB host |
| AI-005 | IDOR | IDOR in resource identifiers and references (path, query, body, nested, headers) | bounded | idor skill with two own accounts; graphql-audit for GraphQL |
| AI-006 | HPP | Parameter pollution (duplicate query params, JSON duplicate keys, array vs scalar, query vs body precedence) | bounded | api_probe.py `hpp` on own requests |
| AI-007 | Batch | Batch endpoint abuse for bulk operations (`/batch`, `/bulk`, JSON arrays, GraphQL batching) bypassing per-request authz or limits | bounded | Own objects only; small batches (≤ 5) to show the behavior |
| AI-008 | Rate limit headers | Rate limit bypass via headers (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `X-Originating-IP`, `Forwarded`, case/whitespace in path, extra params) | bounded | api_probe.py `ratelimit --bypass-headers` (≤ 30 requests) |
| AI-009 | IP rotation | Rate limit bypass via IP rotation (cloud functions, proxies, IPv6 ranges) | authorized-only | Report the per-IP design weakness with AI-008 evidence; do not run rotation infrastructure without approval |
| AI-010 | Smuggling | Request smuggling between API gateway and backend | bounded | request-smuggling-audit (timing detection only) |
| AI-011 | Response manipulation | Response manipulation and data injection: client trusts response fields (`"success":true`, role flags) or injected data reaches other clients | bounded | Intercept own responses (authbypass response-manipulation rows); stored injection via API fields (xss) |
| AI-012 | Content-type switching | Content-type switching attacks (JSON→XML for XXE, JSON→form for CSRF/WAF bypass, multipart parsing differences) | bounded | api_probe.py `ctype`; xml-xxe-audit, csrf-audit |
| AI-013 | Compression bomb | Compression bombs (gzip/deflate request bodies, zip uploads) exhausting resources | authorized-only | Check whether `Content-Encoding: gzip` request bodies are accepted with a tiny body only; bombs need approval |
| AI-014 | Timeouts | Timeout exploitation (slow requests, long-running exports/reports, regex DoS) for resource exhaustion | authorized-only | Report missing limits from bounded observations; resource-exhaustion rules |
| AI-015 | Errors | API error message information disclosure | bounded | error-handling-audit EH-001 to EH-009 |

## Cross-references

| AI row | Related skill |
|---|---|
| AI-001 | sqli |
| AI-002 | nosql-injection-audit |
| AI-003 | command-injection-audit |
| AI-004 | ssrf-audit |
| AI-005 | idor, API-X-005 |
| AI-007 | graphql-audit GQL-003 |
| AI-008, AI-009, AI-014 | resource-exhaustion |
| AI-010 | request-smuggling-audit |
| AI-012 | xml-xxe-audit, csrf-audit, API-X-019 |
| AI-015 | error-handling-audit |
