# API Auth/Authz (AA) and Injection (AI) Tracker

Target: `<target>`  Date: `<date>`  Spec: `<openapi file or none>`  Accounts/keys: `A=<id>`, `B=<id>`

**Progress:** `[ 0 / 40 Complete ]` (AA 25 + AI 15)

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding, `[-]` not applicable, `[A]` waiting for approval.

## Authentication and authorization

| # | ID | Check | Status | Endpoint | Evidence |
|---|---|---|---|---|---|
| 01 | AA-001 | Broken authentication | `[ ]` | | |
| 02 | AA-002 | API keys in client JS | `[ ]` | | |
| 03 | AA-003 | API key in URL | `[ ]` | | |
| 04 | AA-004 | Bearer token validation | `[ ]` | | |
| 05 | AA-005 | OAuth token security | `[ ]` | | |
| 06 | AA-006 | Rate limiting | `[ ]` | | |
| 07 | AA-007 | HTTP methods | `[ ]` | | |
| 08 | AA-008 | Versioning access control | `[ ]` | | |
| 09 | AA-009 | Mass assignment | `[ ]` | | |
| 10 | AA-010 | Input validation | `[ ]` | | |
| 11 | AA-011 | Response field filtering | `[ ]` | | |
| 12 | AA-012 | Excessive data exposure | `[ ]` | | |
| 13 | AA-013 | Parameter tampering | `[ ]` | | |
| 14 | AA-014 | Endpoint enumeration | `[ ]` | | |
| 15 | AA-015 | Documentation exposure | `[ ]` | | |
| 16 | AA-016 | GraphQL introspection | `[ ]` | | |
| 17 | AA-017 | Verb tampering / override | `[ ]` | | |
| 18 | AA-018 | CORS | `[ ]` | | |
| 19 | AA-019 | Content-type validation | `[ ]` | | |
| 20 | AA-020 | Pagination | `[ ]` | | |
| 21 | AA-021 | Key rotation/revocation | `[ ]` | | |
| 22 | AA-022 | Token expiry/refresh | `[ ]` | | |
| 23 | AA-023 | Scope boundaries | `[ ]` | | |
| 24 | AA-024 | Gateway bypass | `[ ]` | | |
| 25 | AA-025 | Key leakage via Referer | `[ ]` | | |

## Injection and manipulation

| # | ID | Check | Status | Endpoint | Evidence |
|---|---|---|---|---|---|
| 26 | AI-001 | SQL injection | `[ ]` | | |
| 27 | AI-002 | NoSQL injection | `[ ]` | | |
| 28 | AI-003 | Command injection | `[ ]` | | |
| 29 | AI-004 | SSRF | `[ ]` | | |
| 30 | AI-005 | IDOR | `[ ]` | | |
| 31 | AI-006 | Parameter pollution | `[ ]` | | |
| 32 | AI-007 | Batch abuse | `[ ]` | | |
| 33 | AI-008 | Rate limit bypass via headers | `[ ]` | | |
| 34 | AI-009 | Rate limit bypass via IP rotation | `[ ]` | | |
| 35 | AI-010 | Request smuggling | `[ ]` | | |
| 36 | AI-011 | Response manipulation | `[ ]` | | |
| 37 | AI-012 | Content-type switching | `[ ]` | | |
| 38 | AI-013 | Compression bombs | `[ ]` | | |
| 39 | AI-014 | Timeout exploitation | `[ ]` | | |
| 40 | AI-015 | Error disclosure | `[ ]` | | |
