# Business Logic Vulnerabilities Tracker

Target: `<target>`  Date: `<date>`  Tester accounts: `A=<id>`, `B=<id>`

**Progress:** `[ 0 / 20 Complete ]`

Status: `[ ]` not started, `[~]` in progress, `[x]` done (no issue), `[!]` finding, `[-]` not applicable, `[A]` waiting for approval (authorized-only).

| # | ID | Check | Class | Status | Evidence / notes |
|---|---|---|---|---|---|
| 01 | BLV-001 | Price manipulation in checkout | bounded | `[ ]` | |
| 02 | BLV-002 | Quantity manipulation (negative, zero) | bounded | `[ ]` | |
| 03 | BLV-003 | Currency manipulation (USD to IDR) | bounded | `[ ]` | |
| 04 | BLV-004 | Discount code reuse and stacking | bounded | `[ ]` | |
| 05 | BLV-005 | Referral code abuse | bounded | `[ ]` | |
| 06 | BLV-006 | Coupon race condition | authorized-only | `[ ]` | |
| 07 | BLV-007 | Double spending of virtual currency | authorized-only | `[ ]` | |
| 08 | BLV-008 | Payment step bypass | bounded | `[ ]` | |
| 09 | BLV-009 | Interest rate manipulation | bounded | `[ ]` | |
| 10 | BLV-010 | Transfer amount manipulation | authorized-only | `[ ]` | |
| 11 | BLV-011 | Negative amount balance bypass | bounded | `[ ]` | |
| 12 | BLV-012 | Unlimited resource creation | bounded | `[ ]` | |
| 13 | BLV-013 | Upload limit and storage quota bypass | bounded | `[ ]` | |
| 14 | BLV-014 | Workflow step skipping | bounded | `[ ]` | |
| 15 | BLV-015 | State machine manipulation | bounded | `[ ]` | |
| 16 | BLV-016 | Refund exploitation | authorized-only | `[ ]` | |
| 17 | BLV-017 | Trial period date manipulation | bounded | `[ ]` | |
| 18 | BLV-018 | Feature flag bypass | bounded | `[ ]` | |
| 19 | BLV-019 | Subscription tier bypass via role | bounded | `[ ]` | |
| 20 | BLV-020 | Email/phone verification bypass | bounded | `[ ]` | |
