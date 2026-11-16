# Request Smuggling Tracker

Target: `<target>`  Date: `<date>`  Approval for confirmation: `<none / ref>`

**Progress:** `[ 0 / 10 Complete ]`

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding, `[-]` not applicable, `[A]` waiting for approval.

| # | ID | Check | Status | Endpoint | Evidence (timings, responses) |
|---|---|---|---|---|---|
| 01 | RS-001 | CL.TE | `[ ]` | | |
| 02 | RS-002 | TE.CL | `[ ]` | | |
| 03 | RS-003 | TE.TE obfuscation | `[ ]` | | |
| 04 | RS-004 | H2.CL | `[ ]` | | |
| 05 | RS-005 | H2.TE | `[ ]` | | |
| 06 | RS-006 | Header manipulation techniques | `[ ]` | | |
| 07 | RS-007 | Proxy to backend | `[ ]` | | |
| 08 | RS-008 | Load balancer | `[ ]` | | |
| 09 | RS-009 | WAF bypass | `[ ]` | | |
| 10 | RS-010 | Cache poisoning via smuggling | `[ ]` | | |

## Chain map

| Host | Hop 1 (CDN/WAF) | Hop 2 (LB/proxy) | Origin server | HTTP/2 front | HTTP/2 back | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |
