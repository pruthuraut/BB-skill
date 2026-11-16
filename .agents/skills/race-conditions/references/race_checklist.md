# Race Conditions Checklist (15 checks + limit sweep)

Class key: `passive` = source and config review. `bounded` = one burst of at most 5 requests (or limit + 2) on your own account, reversible and non-financial. `authorized-only` = monetary or shared value, bursts above 5, or distributed-consistency tests; explicit approval for that check.

## Core checks

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RC-001 | Balance | Race in balance transfer: concurrent transfers exceed the balance | authorized-only | Sandbox, own two accounts, balance of one unit, 2 to 5 parallel transfers of that unit; record balances |
| RC-002 | Coupon | Race in coupon or discount code redemption: single-use code applied more than once | authorized-only | Own single-use coupon in sandbox, 2 to 5 parallel apply or checkout requests; check discount count |
| RC-003 | Voting | Race in voting or liking: one user records several votes or likes | bounded | Own account, own or test post, 5 parallel like or vote requests; check the count, then unlike |
| RC-004 | Upload | Race in file upload creating duplicates or bypassing the file-count quota | bounded | Own account, 5 parallel uploads of one small file at the quota edge; delete extras |
| RC-005 | Signup | Race in account creation with duplicate data (same email, username, or phone) | bounded | 2 to 5 parallel signups with one own email address; check for two accounts sharing it |
| RC-006 | Password reset | Race in password reset token usage: one token used twice or two valid tokens issued | bounded | Own account, 2 to 5 parallel requests using one reset token (or issuing tokens); check how many succeed |
| RC-007 | Gift card | Race in gift card redemption: one card credited more than once | authorized-only | Own low-value or test gift card in sandbox, 2 to 5 parallel redeems |
| RC-008 | Inventory | Race in inventory reservation: oversell or reserve more than stock | authorized-only | Sandbox or approved test with a test product; never hold real shared stock |
| RC-009 | Technique | Concurrent HTTP burst works (Turbo Intruder, single-packet, last-byte sync) | bounded | Confirm burst timing on a harmless own-account endpoint first; record release spread |
| RC-010 | Email verification | Race in email verification: verify one address while changing to another, or reuse one token | bounded | Own two addresses, parallel change-email and verify requests; check which address is marked verified |
| RC-011 | 2FA | Race in 2FA code usage: one code accepted on several sessions, or attempt counter bypassed | bounded | Own account, one valid code in 2 to 5 parallel requests; check how many sessions authenticate |
| RC-012 | Session | Race in session creation and authentication (login plus password change, logout plus refresh) | bounded | Own account, parallel login and password-change or logout and refresh-token requests; check surviving sessions |
| RC-013 | Rate limit | Rate limit bypassed by parallel requests (limit N, burst gets more than N through) | bounded | Own account, burst of limit + 2 on a stated limit (for example OTP resend 3 times, send 5); count accepted |
| RC-014 | Database | Read-modify-write lost update (counters, credits, profile fields) | bounded | Own object, 5 parallel increments; compare the final value with the expected value |
| RC-015 | Distributed | Distributed system consistency: different nodes or regions enforce the limit separately | authorized-only | Approved test only; compare results across nodes or regions with small bursts |

## Limit sweep (find any "only N times" rule)

If the app says an action is limited (for example "you can resend the OTP only 3 times"), it is a race candidate. Record the limit, send a burst of limit + 2, and count successes.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RC-L-001 | Resend OTP | Resend limit exceeded by parallel requests | bounded | Own phone or email, burst of limit + 2, count messages received |
| RC-L-002 | Reset password | Reset-email limit or token count exceeded | bounded | Own account, burst of limit + 2, count emails or valid tokens |
| RC-L-003 | Invite | Invite or seat limit exceeded | bounded | Own workspace, own addresses, burst at the limit edge; revoke extras |
| RC-L-004 | Coupon code | Per-account coupon limit exceeded | authorized-only | Own coupon in sandbox, see RC-002 |
| RC-L-005 | Likes | One-like-per-user rule broken | bounded | See RC-003 |
| RC-L-006 | Feedback | One feedback or review per order or user exceeded | bounded | Own order, burst of 3 to 5; delete extras |
| RC-L-007 | Comments | Comment rate or count limit exceeded | bounded | Own post, burst of limit + 2; delete extras |
| RC-L-008 | Poll vote | One vote per poll broken | bounded | Own or test poll, burst of 5 |
| RC-L-009 | Team / workspace | Free-plan team or workspace count exceeded | bounded | Own account, burst at the limit edge; delete extras |

## Signs to look for

- Response text such as "limit", "remaining", "already used", "only N", "attempts left", "quota".
- Counters in responses (`remaining_attempts`, `uses_left`, `votes`) that can be compared before and after.
- Multi-step flows where the check and the action are separate requests (apply coupon, then pay).
- Missing unique constraints shown by duplicate rows in lists after a burst.

## Public HackerOne reports to study

Study these for patterns and report wording. Read each report for its specific details.

- https://hackerone.com/reports/165570
- https://hackerone.com/reports/1285538
- https://hackerone.com/reports/488985
- https://hackerone.com/reports/429026
- https://hackerone.com/reports/454949
- https://hackerone.com/reports/801743
- https://hackerone.com/reports/152717
- https://hackerone.com/reports/1913309
- https://hackerone.com/reports/146845
- https://hackerone.com/reports/927384
- https://hackerone.com/reports/3104355

## Cross-references

| RC row | Related rows |
|---|---|
| RC-001 | business-logic-vulns BLV-007, BLV-010 |
| RC-002, RC-L-004 | BLV-006, business-logic BL-X-006 |
| RC-007 | BLV-007, BL-X-016 |
| RC-008 | BL-X-015 |
| RC-006, RC-011, RC-L-001, RC-L-002 | credentialattacks, authbypass |
| RC-013 | resource-exhaustion |
