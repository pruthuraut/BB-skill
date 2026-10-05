# Business Logic & Workflow Security Audit Checklist

This checklist guides systematic auditing against Business Logic flaws, financial/price manipulation, race conditions, workflow circumvention, and state machine integrity based on TBHM Module 10/11 and repository materials (`Business Logics/`, `Reference POC_s[Public]/Logical Issues/`).

**Progress:** `[ 0 / 25 Complete ]`

---

## Audit Matrix

| # | Check Description | Subagent | Focus / Verification Criteria | Status |
|---|-------------------|----------|-------------------------------|--------|
| **01** | Audit client-side price parameter tampering | Subagent 01 | Verify server calculates final price from database, rejecting `price`, `amount` in request | `[ ]` |
| **02** | Audit negative quantity and integer overflow | Subagent 01 | Test submitting negative numbers (`quantity: -1`) to lower cart totals | `[ ]` |
| **03** | Audit extreme value numeric truncation / overflow | Subagent 01 | Test integer wrapping limits (`2147483647`, `9223372036854775807`) | `[ ]` |
| **04** | Audit multi-currency exchange rate rounding | Subagent 01 | Test switching currency mid-transaction or exploiting fractional cent roundups | `[ ]` |
| **05** | Audit fee / tax / shipping cost parameter manipulation | Subagent 01 | Verify tax or shipping fees cannot be zeroed or overridden in checkout payloads | `[ ]` |
| **06** | Audit multi-step checkout workflow sequencing | Subagent 02 | Verify step 3 (Payment) cannot be bypassed by navigating directly to step 4 (Order Complete) | `[ ]` |
| **07** | Audit payment callback and webhook integrity | Subagent 02 | Verify payment provider webhooks enforce HMAC signature validation and timestamp checks | `[ ]` |
| **08** | Audit state machine transition constraints | Subagent 02 | Verify order status cannot transition from `cancelled` to `shipped` or `refunded` to `active` | `[ ]` |
| **09** | Audit order item substitution after payment authorization | Subagent 02 | Test adding high-value items to cart after payment gateway approval | `[ ]` |
| **10** | Audit cancellation and refund workflow logic | Subagent 02 | Test canceling order after digital goods download or requesting duplicate refunds | `[ ]` |
| **11** | Audit coupon code single-use concurrency (Race Condition) | Subagent 03 | Send 20 parallel requests applying the same one-time coupon via Turbo Intruder | `[ ]` |
| **12** | Audit gift card and wallet balance concurrency | Subagent 03 | Send simultaneous checkout requests spending a single gift card balance | `[ ]` |
| **13** | Audit multi-discount stacking logic | Subagent 03 | Test applying conflicting promotional discounts or combining incompatible promo codes | `[ ]` |
| **14** | Audit referral reward duplication | Subagent 03 | Test claiming referral credit multiple times using self-referrals or race conditions | `[ ]` |
| **15** | Audit rate limit / quota reset timing boundaries | Subagent 03 | Test actions right at the reset boundary (midnight, 00:00 UTC) for double allocations | `[ ]` |
| **16** | Audit trial period and subscription renewal bypasses | Subagent 03 | Test canceling subscription while retaining enterprise features, or re-initiating trials | `[ ]` |
| **17** | Audit voting, rating, or review ballot stuffing | Subagent 03 | Verify voting systems enforce persistent user identity and prevent unconstrained re-votes | `[ ]` |
| **18** | Audit file upload quota and storage exhaustion | Subagent 03 | Verify account tier storage quotas are strictly enforced at the server layer | `[ ]` |
| **19** | Audit user invitation and license seat allocation | Subagent 03 | Verify organization cannot invite more users than paid plan license capacity | `[ ]` |
| **20** | Audit 2FA / Password reset cancellation state retention | Subagent 02 | Verify cancelling a flow resets all partial authorization flags | `[ ]` |
| **21** | Audit server-side authoritative state validation | Subagent 04 | Ensure no business logic relies on cookies, localStorage, or hidden inputs | `[ ]` |
| **22** | Audit atomic database transactions (ACID compliance) | Subagent 04 | Verify financial state updates use row-level locks (`SELECT FOR UPDATE`) | `[ ]` |
| **23** | Audit idempotency key enforcement on payments | Subagent 04 | Ensure payment and balance endpoints require unique `Idempotency-Key` headers | `[ ]` |
| **24** | Audit distributed lock mechanisms (Redis Redlock) | Subagent 04 | Ensure critical shared state transitions acquire atomic distributed locks | `[ ]` |
| **25** | Audit business event audit logging and anomaly detection | Subagent 04 | Ensure abnormal transaction volumes, rapid orders, or negative totals trigger alerts | `[ ]` |
