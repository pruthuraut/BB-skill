# GraphQL, CORS, and API Documentation Checks (extension)

Class key: `passive` = docs and headers. `bounded` = introspection and single requests with your own token. `authorized-only` = mutations or anything that changes data.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| API-X-001 | GraphQL | Introspection enabled in production | bounded | `{"query":"{__schema{types{name}}}"}` anonymous |
| API-X-002 | GraphQL | Field suggestions leak schema when introspection is off | bounded | Misspelled field name, check suggestion text |
| API-X-003 | GraphQL | Batching allows brute force of credentials | bounded | 5 batched login attempts on own account (see resource-exhaustion) |
| API-X-004 | GraphQL | Query depth and complexity unlimited | bounded | Nested query depth 8 on own data, check error |
| API-X-005 | GraphQL | Object-level authorization missing (IDOR by ID argument) | bounded | Own two accounts: query other ID |
| API-X-006 | GraphQL | SQL or NoSQL injection through arguments | bounded | Benign marker; see server-side-injection |
| API-X-007 | GraphQL | Mutation exposed without auth | authorized-only | Review schema first; mutations only on own test object |
| API-X-008 | CORS | Origin reflected with credentials allowed | bounded | `Origin: https://evil.example`; check ACAO and ACAC |
| API-X-009 | CORS | Null origin trusted | bounded | `Origin: null` |
| API-X-010 | CORS | Suffix or prefix match bypass (`target.com.evil`) | bounded | Two Origin variants |
| API-X-011 | CORS | Wildcard with credentials on API paths | bounded | Origin probe and preflight |
| API-X-012 | CORS | Express or FastAPI default CORS (wildcard origins) | bounded | Origin probe |
| API-X-013 | API docs | Swagger UI and OpenAPI JSON exposed | passive | GET /swagger, /api-docs, /openapi.json, /v2/api-docs |
| API-X-014 | API docs | Interactive Swagger allows calling authenticated endpoints | bounded | Anonymous "try it" on GET endpoints only |
| API-X-015 | API docs | Pre-filled bearer or API key in docs | passive | Grep docs HTML and JSON for token patterns |
| API-X-016 | API | Mass assignment (role or isAdmin in JSON body) | bounded | Own account PUT with extra field, check stored value |
| API-X-017 | API | Excessive data exposure (fields not shown in UI) | bounded | Compare own API response with UI |
| API-X-018 | API | Versioned legacy endpoints (v1, v0) without same controls | bounded | Own token against older version path |
| API-X-019 | API | Content-type switch bypass of validation | bounded | Same body as JSON and form-encoded |
| API-X-020 | API | Gateway vs backend auth inconsistency | bounded | Same endpoint through gateway and direct origin (in scope only) |
