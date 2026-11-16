# CORS Tracker

Target: `<target>`  Date: `<date>`  Own victim account: `<id>`  Browser(s): `<name version>`  Session cookie SameSite: `<value>`

**Progress:** `[ 0 / 15 Complete ]`

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding (PoC reads data), `[-]` not applicable, `[A]` waiting for approval.

## Core checks

| # | ID | Check | Status | Endpoint(s) | Origin(s) accepted | ACAC | Evidence |
|---|---|---|---|---|---|---|---|
| 01 | CORS-001 | Arbitrary Origin reflection | `[ ]` | | | | |
| 02 | CORS-002 | null origin | `[ ]` | | | | |
| 03 | CORS-003 | Subdomain origin trust | `[ ]` | | | | |
| 04 | CORS-004 | Target-domain trust (scheme, port) | `[ ]` | | | | |
| 05 | CORS-005 | Credentials with wildcard or reflection | `[ ]` | | | | |
| 06 | CORS-006 | Suffix matching | `[ ]` | | | | |
| 07 | CORS-007 | Prefix matching | `[ ]` | | | | |
| 08 | CORS-008 | Regex bypass | `[ ]` | | | | |
| 09 | CORS-009 | Methods and headers | `[ ]` | | | | |
| 10 | CORS-010 | Preflight bypass | `[ ]` | | | | |
| 11 | CORS-011 | Arbitrary subdomains | `[ ]` | | | | |
| 12 | CORS-012 | Third-party whitelisting | `[ ]` | | | | |
| 13 | CORS-013 | Unvalidated reflection | `[ ]` | | | | |
| 14 | CORS-014 | Encoding and parser tricks | `[ ]` | | | | |
| 15 | CORS-015 | WebSocket upgrade | `[ ]` | | | | |

## Endpoint inventory

| Endpoint | Sensitive data | ACAO without Origin | ACAO with evil Origin | ACAC | Vary: Origin | Tested |
|---|---|---|---|---|---|---|
| | | | | | | `[ ]` |
