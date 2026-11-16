# Race Conditions Tracker

Target: `<target>`  Date: `<date>`  Tester accounts: `A=<id>`, `B=<id>`

**Progress:** `[ 0 / 15 Complete ]`

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding, `[-]` not applicable, `[A]` waiting for approval (authorized-only).

## Core checks

| # | ID | Check | Class | Status | Burst size / spread ms | Before → after state |
|---|---|---|---|---|---|---|
| 01 | RC-001 | Balance transfer | authorized-only | `[ ]` | | |
| 02 | RC-002 | Coupon / discount redemption | authorized-only | `[ ]` | | |
| 03 | RC-003 | Voting / liking | bounded | `[ ]` | | |
| 04 | RC-004 | File upload duplicates | bounded | `[ ]` | | |
| 05 | RC-005 | Duplicate account creation | bounded | `[ ]` | | |
| 06 | RC-006 | Password reset token usage | bounded | `[ ]` | | |
| 07 | RC-007 | Gift card redemption | authorized-only | `[ ]` | | |
| 08 | RC-008 | Inventory reservation | authorized-only | `[ ]` | | |
| 09 | RC-009 | Concurrent burst technique (Turbo Intruder) | bounded | `[ ]` | | |
| 10 | RC-010 | Email verification flow | bounded | `[ ]` | | |
| 11 | RC-011 | 2FA code usage | bounded | `[ ]` | | |
| 12 | RC-012 | Session creation / authentication | bounded | `[ ]` | | |
| 13 | RC-013 | Rate limiting bypass | bounded | `[ ]` | | |
| 14 | RC-014 | Database read-modify-write | bounded | `[ ]` | | |
| 15 | RC-015 | Distributed consistency | authorized-only | `[ ]` | | |

## Limits found (limit sweep)

| Feature | Endpoint | Stated limit | Burst sent | Successes | Status |
|---|---|---|---|---|---|
| Resend OTP | | | | | `[ ]` |
| Reset password | | | | | `[ ]` |
| Invite | | | | | `[ ]` |
| Coupon code | | | | | `[ ]` |
| Likes | | | | | `[ ]` |
| Feedback | | | | | `[ ]` |
| Comments | | | | | `[ ]` |
| Poll vote | | | | | `[ ]` |
| Create team / workspace | | | | | `[ ]` |
