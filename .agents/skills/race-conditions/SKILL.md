---
name: race-conditions
description: Audit authorized applications for race conditions (TOCTOU, limit overrun) across 15 checks — balance transfers, coupon and discount redemption, voting and liking, duplicate file uploads, duplicate account creation, password reset token reuse, gift card redemption, inventory reservation, Turbo Intruder / single-packet bursts, email verification, 2FA code reuse, session creation, rate-limit bypass, database read-modify-write, and distributed consistency — plus a limit-hunting sweep for any "only N times" rule (resend OTP, reset password, invites, coupons, likes, feedback, comments, poll votes, team/workspace creation). Triggers on "race condition", "TOCTOU", "limit overrun", "concurrent requests", "parallel requests", "single-packet attack", "Turbo Intruder", "double redeem", "double spend", "resend OTP limit", "only 3 times", "vote twice", or when a feature enforces a count, balance, or single-use rule.
---

# Race Conditions (15 checks + limit sweep)

A race condition exists when the server checks a rule (balance, single use, count limit) and then acts on it in two separate steps, so parallel requests all pass the check before any of them records the action. The goal is to show that a limit of N can be exceeded, with the smallest burst that proves it.

- Checklist: `references/race_checklist.md` (RC-001 to RC-015 plus the limit sweep rows RC-L-*, with class and safe verification per row).
- Tracker: `references/race_tracker.md` (copy to `artifacts/<target>/`, update 0/15 to 15/15).
- Probe: `scripts/race_probe.py` (last-byte synchronized HTTP/1.1 burst, scope-gated, 5 requests by default, hard cap 20).
- Related: `business-logic-vulns` (BLV-006, BLV-007), `business-logic` (BL-X-006, BL-X-015), `credentialattacks` and `authbypass` (OTP and reset flows), `resource-exhaustion` (rate limits).

## Subagents

| Subagent | Checks | Focus |
|---|---|---|
| 01 Value and money | RC-001, 002, 007, 008 | Balance transfer, coupons, gift cards, inventory |
| 02 Counters and content | RC-003, 004, 005, 014 | Votes and likes, duplicate uploads, duplicate accounts, read-modify-write |
| 03 Auth and tokens | RC-006, 010, 011, 012 | Reset tokens, email verification, 2FA codes, sessions |
| 04 Limits and infrastructure | RC-009, 013, 015, RC-L-* | Burst technique, rate-limit bypass, distributed consistency, limit sweep |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. Read the program policy; some programs forbid race testing or cap request rates.
2. **Limit sweep first.** Walk the app and list every place a count or single-use rule appears: "resend OTP up to 3 times", one coupon per account, one vote per poll, N invites, N teams on the free plan, one feedback per order. Record the limit and the endpoint in the tracker (RC-L-* rows).
3. Baseline: perform the action once normally and record the server state (balance, vote count, coupon status, remaining attempts).
4. Capture the request in Burp and save it to a file. Make sure it uses a fresh, valid state (an unused coupon, a balance of exactly one unit).
5. Burst: send the same request in parallel.
   - Preferred: Burp Repeater, duplicate the tab N times, group them, "Send group in parallel" (single-packet attack on HTTP/2, last-byte sync on HTTP/1.1).
   - Turbo Intruder: `race-single-packet-attack.py` template with a small count.
   - CLI: `python3 .agents/skills/race-conditions/scripts/race_probe.py --target example.com --request req.txt --count 5 --out artifacts/example.com/race_<check>.json`
6. Re-read server state. A finding means the limit was exceeded: two successes for a single-use item, a balance below zero, a vote count above one, more OTP sends than allowed.
7. Repeat once to confirm. If the first burst failed, try warming the connection (send a harmless GET first), multi-endpoint races (for example apply coupon plus checkout), and timing the burst right after the state is created.
8. Clean up: cancel orders, delete duplicates, remove votes where possible.
9. Save findings to `artifacts/<target>/race_conditions.json` and the tracker to `artifacts/<target>/race_tracker.md`.

## Classes

- `passive`: reading code for check-then-act patterns, missing locks, missing unique constraints, and missing idempotency keys.
- `bounded`: a burst of at most 5 requests (or limit + 2 for a stated limit) against your own account, on reversible, non-financial actions (likes, votes, comments, own OTP resend, own team creation, own uploads, own reset or verification tokens).
- `authorized-only`: anything with monetary or shared value (balances, coupons, gift cards, inventory), bursts above 5 requests, and distributed-system consistency tests. Requires explicit approval for that specific check.

## Rules

- One burst per attempt and a small count. Never loop bursts or use them as load tests.
- Own accounts, own coupons, own gift cards, and sandbox payment mode only. Never spend another user's value or reserve shared stock in production.
- Do not cash out, withdraw, or keep value gained from a race. Report it and ask the program to reverse it.
- Record exact before and after state and the burst timing (`release_spread_ms` from `race_probe.py`) as evidence.

## Mitigation guidance for reports

- Make the check and the update one atomic operation: `UPDATE ... SET used = 1 WHERE id = ? AND used = 0` and check affected rows, or `SELECT ... FOR UPDATE` inside a transaction.
- Add database unique constraints (one vote per user per poll, one redemption per coupon).
- Use idempotency keys for payments, transfers, and redemptions.
- Use atomic counters (Redis `INCR`, database counters) for rate limits instead of read-then-write.
- Invalidate tokens and OTP codes atomically on first use.
- In distributed systems, use a single source of truth or a distributed lock for limit enforcement.

## Sources

PortSwigger Web Security Academy (race conditions, single-packet attack research "Smashing the state machine"), OWASP WSTG-BUSL-07 and API6:2023, CWE-362 and CWE-367, and the public HackerOne reports listed in `references/race_checklist.md`.
