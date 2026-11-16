---
name: business-logic-vulns
description: Audit authorized applications for 20 business logic vulnerabilities — checkout price tampering, negative/zero quantity, currency switching (e.g. USD to IDR), discount reuse and stacking, referral abuse, coupon race conditions, virtual-currency double spending, payment-step bypass, interest-rate and transfer-amount tampering, negative-amount balance bypass, unlimited resource creation, upload and storage quota bypass, workflow step skipping, state machine manipulation, refund exploitation, trial date manipulation, feature-flag parameters, subscription tier bypass via role, and email/phone verification bypass. Triggers on "business logic", "logic flaw", "price manipulation", "negative quantity", "currency manipulation", "coupon reuse", "referral abuse", "double spend", "skip payment", "refund abuse", "trial bypass", "feature flag", "subscription bypass", "quota bypass", or when route_target.py routes price, amount, qty, currency, coupon, referral, balance, plan, trial, or feature parameters.
---

# Business Logic Vulnerabilities (20 checks)

Find places where the server trusts the client to describe value, sequence, limits, or entitlement. Every check compares what the server *should* enforce against what it *does* enforce, using your own accounts, your own carts, and sandbox or test payment modes.

- Checklist: `references/logic_vuln_checklist.md` (BLV-001 to BLV-020, with class and safe verification per row, plus per-check test steps).
- Tracker: `references/logic_vuln_tracker.md` (copy to `artifacts/<target>/` and update from 0/20 to 20/20).
- Related: `business-logic-vulns` (15 race checks, limit sweep, and `race_probe.py` for BLV-006 and BLV-007), `business-logic-vulns` (25-check umbrella skill, `BL-X-*` rows in `../business-logic-vulns/references/merged/business-logic/references/payment_checkout_extended.md`), `access-control` (role and plan claims), `authbypass` (verification and OTP flows), `resource-exhaustion` (velocity limits), `file-upload-audit` (upload handling).

## Subagents

| Subagent | Checks | Focus |
|---|---|---|
| 01 Pricing and payment | BLV-001, 002, 003, 004, 008 | Price, quantity, currency, discount stacking, payment-step bypass |
| 02 Money movement | BLV-009, 010, 011, 016 | Interest rate, transfer amount, negative balance, refunds |
| 03 Concurrency and rewards | BLV-005, 006, 007 | Referral abuse, coupon races, double spending |
| 04 Limits and quotas | BLV-012, 013 | Resource creation caps, upload and storage quotas |
| 05 Workflow and state | BLV-014, 015, 020 | Step skipping, invalid state transitions, verification bypass |
| 06 Entitlements | BLV-017, 018, 019 | Trial dates, feature flags, subscription tier and role |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. Read the program policy for payment, referral, and race-condition rules; many programs forbid real-money testing.
2. Set up: two self-owned accounts (A and B), sandbox or test payment mode, test coupons you were issued, and a proxy capturing all traffic.
3. Map value flows: cart, checkout, wallet, transfers, referrals, subscriptions, trials, quotas, invites, verification. Use `scripts/route_target.py --params` to find routed parameters.
4. For each flow, record the normal request sequence and the server-computed values (total, balance, limit, plan, state). This is the baseline.
5. Run the checks in `references/logic_vuln_checklist.md`. Change one value or one step at a time and compare against the baseline.
6. Confirm a finding twice, then show impact with the smallest possible values (one item, one cent, one extra resource). Undo what you can: cancel orders, delete extra resources, remove test coupons.
7. Save findings to `artifacts/<target>/business_logic_vulns.json` and the tracker to `artifacts/<target>/logic_vuln_tracker.md`.

## Classes

- `passive`: reading JS, API docs, responses, and feature-flag configs.
- `bounded`: single, own-account requests in sandbox or test mode, at most limit+1 for quota checks, and smallest values for money checks.
- `authorized-only`: parallel/race requests, anything that moves real money, refunds, or affects other users or shared inventory. Needs explicit approval for that specific check.

## Rules

- Never complete a real-money purchase, transfer, withdrawal, or refund to prove a bug. Stop at the server-computed total or the accepted-but-unpaid state, and report.
- Race tests (BLV-006, BLV-007) are limited to 2 to 5 parallel requests with your own coupon or balance, and only when approved.
- Referral tests use only your own accounts, at most one or two referrals, and never cash out rewards.
- Quota tests go one past the limit, using small files and few objects, then clean up.
- Never touch other customers' accounts, balances, or orders.
- Report the root cause: which value the server trusted, which step it did not check, or which transition it allowed.

## Mitigation guidance for reports

- Compute price, discount, currency, rate, and totals on the server from authoritative records; ignore client-sent values.
- Validate numeric ranges (positive, nonzero, upper bound) and use decimal types.
- Enforce workflow and state transitions in a server-side state machine.
- Use database transactions with row locks or atomic conditional updates, and idempotency keys for payments and redemptions.
- Derive plan, role, flags, and trial dates from the server-side subscription record, never from request parameters or client time.
- Bind verification status to the specific email or phone and require it at every sensitive step.

## Sources

PortSwigger Web Security Academy (business logic vulnerabilities, race conditions), OWASP WSTG-BUSL-01 to 09, OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows), CWE-840, CWE-362, and public HackerOne business-logic reports.

## Merged skills (content preserved)

These skills covered the same topic and were merged here. Nothing was removed: each original SKILL.md, reference file, and Cursor rule is kept under `references/merged/<name>/`, and each script is in `scripts/` (a prefix marks name collisions).

- `business-logic`: full content in `references/merged/business-logic/` (SKILL.md, references, rule); scripts in `scripts/`
- `race-conditions`: full content in `references/merged/race-conditions/` (SKILL.md, references, rule); scripts in `scripts/`
