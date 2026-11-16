# API Security & Documentation Audit Checklist

This checklist guides systematic auditing against OWASP API Security Top 10 flaws, Swagger/OpenAPI exposure, GraphQL vulnerabilities, BOLA/BFLA, and schema desynchronization based on TBHM and repository materials (`Swagger API/`, `API Exploitation/`).

**Progress:** `[ 0 / 25 Complete ]`

---

## Audit Matrix

| # | Check Description | Subagent | Focus / Verification Criteria | Status |
|---|-------------------|----------|-------------------------------|--------|
| **01** | Audit interactive Swagger UI and OpenAPI schemas | Subagent 01 | Probe `/swagger-ui.html`, `/openapi.json`, `/v2/api-docs` for exposed specs | `[ ]` |
| **02** | Audit Postman collection & environment leaks | Subagent 01 | Search for exposed `.postman_collection.json` or `.postman_environment.json` | `[ ]` |
| **03** | Audit SOAP WSDL and XML Schema definitions | Subagent 01 | Probe `?wsdl` and `?xsd` to map legacy enterprise RPC functions | `[ ]` |
| **04** | Audit undocumented / shadow API endpoints | Subagent 01 | Fuzz API paths using `wordlists/api.txt` and `API-FUZZ.txt` | `[ ]` |
| **05** | Audit deprecated API versions (`/v1/` vs `/v2/`) | Subagent 01 | Verify older API versions do not remain active with unpatched vulnerabilities | `[ ]` |
| **06** | Audit GraphQL introspection query exposure | Subagent 02 | Send `query { __schema { queryType { name } } }` to check if schema is leaked | `[ ]` |
| **07** | Audit GraphQL query depth and complexity limits | Subagent 02 | Send deeply nested queries (`{ user { friends { friends { friends ... } } } }`) | `[ ]` |
| **08** | Audit GraphQL query batching / resource exhaustion | Subagent 02 | Send single HTTP POST with an array of 500 GraphQL operations | `[ ]` |
| **09** | Audit GraphQL field suggestion information leaks | Subagent 02 | Test malformed field query; check if server responds "Did you mean ...?" | `[ ]` |
| **10** | Audit GraphQL mutation authorization controls | Subagent 02 | Verify mutations enforce strict user-level authorization checks | `[ ]` |
| **11** | Audit Broken Object Level Authorization (BOLA) | Subagent 03 | Test substituting user/tenant IDs across REST endpoints (`/api/v1/users/{id}`) | `[ ]` |
| **12** | Audit Broken Function Level Authorization (BFLA) | Subagent 03 | Test regular user tokens against administrative API actions (`/api/v1/admin/users`) | `[ ]` |
| **13** | Audit Mass Assignment in JSON payloads | Subagent 03 | Inject sensitive object fields: `role`, `isAdmin`, `verified`, `balance` | `[ ]` |
| **14** | Audit HTTP method override & verb tampering | Subagent 03 | Test `X-HTTP-Method-Override: PUT` or `_method=DELETE` on GET/POST | `[ ]` |
| **15** | Audit Content-Type negotiation & XML parsing | Subagent 03 | Change `Content-Type: application/json` to `application/xml` to test XXE | `[ ]` |
| **16** | Audit lack of resource and rate limiting on APIs | Subagent 03 | Send high-frequency queries to pagination endpoints without rate limits | `[ ]` |
| **17** | Audit API response data filtering (Excessive Data Exposure) | Subagent 03 | Check if API returns complete DB objects with PII, relying on UI to filter | `[ ]` |
| **18** | Audit API key validation and scope enforcement | Subagent 04 | Verify API keys enforce read vs write scopes and reject revoked keys | `[ ]` |
| **19** | Audit JWT signature verification & algorithm confusion | Subagent 04 | Test `alg: none` or HMAC with RSA public key verification | `[ ]` |
| **20** | Audit CORS policy on API gateways | Subagent 04 | Verify API rejects untrusted `Origin: evil.com` with `Allow-Credentials: true` | `[ ]` |
| **21** | Audit strict request schema validation | Subagent 04 | Ensure API gateway rejects unexpected fields or invalid data types | `[ ]` |
| **22** | Audit centralized API gateway authentication enforcement | Subagent 04 | Ensure backend microservices cannot be reached bypassing the gateway | `[ ]` |
| **23** | Audit rate limiting headers (`X-RateLimit-Remaining`) | Subagent 04 | Verify standard rate limiting headers are returned and enforced | `[ ]` |
| **24** | Audit SSL/TLS cipher suites on API endpoints | Subagent 04 | Ensure modern TLS 1.2/1.3 cipher suites without deprecated SSLv3/TLS 1.0 | `[ ]` |
| **25** | Audit security logging and monitoring of API abuse | Subagent 04 | Ensure failed auth, BOLA attempts, and schema errors are alerted | `[ ]` |
