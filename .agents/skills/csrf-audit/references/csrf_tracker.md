# CSRF Tracker

Target: `<target>`  Date: `<date>`  Attacker account: `<own A>`  Victim account: `<own V>`  Browser(s): `<name version>`

**Progress:** `[ 0 / 20 Complete ]`

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding (PoC works), `[-]` not applicable, `[A]` waiting for approval.

## Core checks

| # | ID | Check | Status | Endpoint(s) | Evidence / PoC file |
|---|---|---|---|---|---|
| 01 | XSRF-001 | CSRF in all state-changing requests | `[ ]` | | |
| 02 | XSRF-002 | Token presence and validation in forms | `[ ]` | | |
| 03 | XSRF-003 | Token removed entirely | `[ ]` | | |
| 04 | XSRF-004 | Token reuse across sessions | `[ ]` | | |
| 05 | XSRF-005 | Token predictability and entropy | `[ ]` | | |
| 06 | XSRF-006 | Token tied to session | `[ ]` | | |
| 07 | XSRF-007 | JSON content type with CORS | `[ ]` | | |
| 08 | XSRF-008 | XML content type | `[ ]` | | |
| 09 | XSRF-009 | multipart/form-data | `[ ]` | | |
| 10 | XSRF-010 | AJAX X-Requested-With | `[ ]` | | |
| 11 | XSRF-011 | WebSocket handshake | `[ ]` | | |
| 12 | XSRF-012 | SameSite on session cookies | `[ ]` | | |
| 13 | XSRF-013 | Login CSRF | `[ ]` | | |
| 14 | XSRF-014 | Password change | `[ ]` | | |
| 15 | XSRF-015 | Email change | `[ ]` | | |
| 16 | XSRF-016 | X-Forwarded-* bypass | `[ ]` | | |
| 17 | XSRF-017 | `_method` override | `[ ]` | | |
| 18 | XSRF-018 | Origin/Referer validation | `[ ]` | | |
| 19 | XSRF-019 | GraphQL mutations | `[ ]` | | |
| 20 | XSRF-020 | API endpoints with weak CORS | `[ ]` | | |

## State-changing request inventory

| Action | Method | Path | Content type | Auth (cookie/header) | Token location | SameSite | Tested |
|---|---|---|---|---|---|---|---|
| | | | | | | | `[ ]` |

## Bypasses tried (XSRF-B-*)

| Endpoint | Bypass IDs tried | Accepted? | Notes |
|---|---|---|---|
| | | | |
