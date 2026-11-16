# Business Logic Vulnerabilities Checklist (20 checks)

Class key: `passive` = reading code, JS, docs, and responses. `bounded` = single requests on your own accounts in sandbox or test mode, smallest values, at most limit+1 for quotas. `authorized-only` = parallel/race requests, real money, refunds, or anything that affects other users or shared stock.

## Matrix

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| BLV-001 | Price | Price manipulation in e-commerce checkout (client-sent price, unit_price, total, subtotal) | bounded | Own cart in sandbox: change price to a test value, read the server-computed total; do not pay |
| BLV-002 | Quantity | Negative or zero quantity accepted (qty -1, 0, 0.5, huge values) | bounded | Own cart with qty -1 next to a qty 2 item; check whether the total drops; do not pay |
| BLV-003 | Currency | Currency switched in payment flow (USD to IDR, VND, JPY) without converting the amount | bounded | Own cart in sandbox: change currency field or header, compare charged amount vs USD baseline |
| BLV-004 | Discount | Discount code reused or stacked (same code twice, two exclusive codes, code after cart change) | bounded | Own coupons only; apply 2 to 3 times, read the total; remove coupon afterward |
| BLV-005 | Referral | Referral code manipulated for unlimited rewards (self-referral, aliases, replay, parameter change) | bounded | Own two accounts, at most 1 to 2 referrals, never redeem or cash out rewards |
| BLV-006 | Coupon race | Single-use coupon applied more than once via parallel requests | authorized-only | Approved test with own coupon in sandbox; 2 to 5 parallel requests max |
| BLV-007 | Virtual currency | Double spending of credits, points, wallet, or gift card via parallel requests | authorized-only | Approved test with own small balance; 2 to 5 parallel requests; report balance before and after |
| BLV-008 | Workflow | Payment step bypassed (direct POST to confirm/complete/success) | bounded | Own sandbox order: call the final step without paying, check order status; cancel the order |
| BLV-009 | Fintech | Interest rate, APR, or term manipulated in loan, savings, or deposit requests | bounded | Test or sandbox account only: change the rate field, check the quoted value; never submit a real application |
| BLV-010 | Banking | Transfer amount manipulated (decimal precision, rounding, amount vs display_amount mismatch, fee field) | authorized-only | Sandbox between own accounts only; on production report request acceptance without completing |
| BLV-011 | Balance | Account balance check bypassed with negative amounts (withdraw -100, transfer -50) | bounded | Sandbox between own accounts, smallest negative value, expect rejection; real funds are authorized-only |
| BLV-012 | Limits | Unlimited resource creation (accounts, projects, invites, API keys, seats) past plan limit | bounded | Own account: create limit+1, record response, then delete the extras |
| BLV-013 | Quota | Upload limit or storage quota bypassed (size, count, chunked upload, plan-limit parameter) | bounded | Own account: one small file past the limit, or a size-field mismatch; delete afterward |
| BLV-014 | Workflow | Required steps skipped (onboarding, KYC, agreement, MFA setup, shipping, approval) | bounded | Own account: call step N+2 directly, check whether the server accepts it |
| BLV-015 | State machine | State manipulated to reach invalid states (cancelled to shipped, refunded to active, draft to approved) | bounded | Own order or object: send a status field or out-of-order transition; revert afterward |
| BLV-016 | Refund | Post-payment manipulation and refund exploitation (refund after use, double refund, refund to different method, partial refund math) | authorized-only | Review only on production; sandbox test with explicit approval |
| BLV-017 | Trial | Trial period bypassed via date manipulation (trial_end, start_date, client time, timezone) | bounded | Own trial account: change date fields, check the server-side expiry and entitlements |
| BLV-018 | Feature flag | Feature flag bypassed via request parameters (feature=, beta=true, flags[], X-Feature header, cookie) | bounded | Own account: add or flip the flag, check whether a gated feature becomes usable |
| BLV-019 | Subscription | Subscription tier bypassed via role or plan manipulation (plan=enterprise, role=premium, JWT claim) | bounded | Own free account: change the plan or role field, check premium endpoints; see access-control |
| BLV-020 | Verification | Email or phone verification bypassed in critical flows (verified=true, skip step, swap address after verification, reuse code) | bounded | Own email and phone only; see authbypass for OTP depth |

## Per-check test steps

### BLV-001 Price manipulation
- Look for `price`, `unit_price`, `amount`, `total`, `subtotal`, `shipping`, `tax`, `fee`, `discount` in cart, checkout, and order-create requests, including hidden form fields and JSON bodies.
- Change one field to a smaller test value (for example `1` or `0.01`). Check the server response total, the order summary page, and the payment gateway amount.
- Also try: `price` sent as a string, array, or object; price on a different product ID; price in a later step (update cart, apply shipping).
- Finding = the server-computed amount follows the client value. Stop before payment.

### BLV-002 Quantity manipulation
- Values: `-1`, `0`, `0.5`, `1e2`, `-0`, `2147483648`, `"1"`, `[1]`.
- Combine a positive item with a negative item to see if the total drops below the real price.
- Check inventory, shipping, and loyalty-point calculations for the same values.

### BLV-003 Currency manipulation
- Find currency in body, query (`?currency=`), cookie, header (`X-Currency`), or locale path (`/id-id/`).
- Switch from USD to a low-value currency such as IDR, VND, or JPY. Finding = the numeric amount is kept but the currency changes (100 USD becomes 100 IDR).
- Also check rounding between currencies with small amounts and mismatches between the display currency and the charge currency.

### BLV-004 Discount reuse and stacking
- Apply the same code twice in one request (array, repeated parameter), in separate requests, and after removing then re-adding it.
- Combine codes marked non-combinable; combine a coupon with a sale price or gift card.
- Apply the code, then change the cart (remove the qualifying item, lower qty under the minimum) and check whether the discount stays.
- Change case or add whitespace (`SAVE10`, `save10`, ` SAVE10`) to bypass a "used" check.

### BLV-005 Referral abuse
- Self-referral with an email alias (`me+1@`), the same device, or the same payment method.
- Change `referrer_id` or `referral_code` in the signup request after the UI sets it; replay the reward-claim request.
- Check whether the reward is granted before the referee completes the qualifying action (purchase, verification).
- Stop after one or two referrals and never redeem rewards.

### BLV-006 Coupon race condition (authorized-only)
- Only with approval. Send 2 to 5 identical apply or redeem requests in one burst (Burp Repeater group "send in parallel", single-packet attack, or Turbo Intruder with a small gate).
- Finding = the discount is applied more than once or the single-use code is accepted on two orders.

### BLV-007 Double spending (authorized-only)
- Only with approval. With a small own balance, send 2 to 5 parallel spend, transfer, or redeem requests that each use the full balance.
- Finding = the total spent exceeds the balance or the balance goes negative. Record balances before and after.

### BLV-008 Payment step bypass
- Record the full sequence: cart, then shipping, then payment, then confirm. Replay the confirm or complete request with a new unpaid order ID.
- Try the gateway return URL directly (`/payment/success?order=`), `status=paid` in the callback, and parameters such as `payment_method=free`, `skip_payment=true`, or `gateway=test`.
- Finding = the order moves to paid or fulfilled without a gateway confirmation. Cancel the test order.

### BLV-009 Interest rate manipulation
- Find `rate`, `apr`, `interest`, `term`, `tenure`, or `promo_rate` in quote, application, or deposit requests.
- Change the value in a test or sandbox environment and check whether the quoted repayment or yield follows it.
- Never submit a real credit application with altered values.

### BLV-010 Transfer amount manipulation (authorized-only on real funds)
- Check precision (`0.001`, `1.005`), rounding direction, very small amounts that round to zero fee, and mismatched fields (`amount` vs `display_amount` vs `debit_amount`).
- Check whether the fee or exchange rate is taken from the request.
- On production, report acceptance of a tampered request without completing the transfer.

### BLV-011 Negative amount balance bypass
- Send `-1` (or the smallest negative value) to withdraw, transfer, pay, or tip endpoints between your own accounts in sandbox.
- Finding = a negative transfer credits the sender, or a negative withdrawal increases the balance.
- Also try `amount` larger than the balance with a negative fee.

### BLV-012 Unlimited resource creation
- Read the plan limit (projects, invites, seats, API keys, workspaces). Create up to the limit, then one more through the API, through a different endpoint (import, duplicate, template), and with a changed `org_id` or plan parameter.
- Check whether invites to the same email repeat without limit (email abuse) and whether account signup has no limits (see resource-exhaustion).
- Delete the extra resources after the test.

### BLV-013 Upload and storage quota bypass
- Compare the declared size (`Content-Length`, `size` field in a presigned-URL request) with the real file size.
- Try chunked or multipart uploads, a `max_size` or `plan` parameter, uploading through a different feature (avatar vs attachment), and uploading after a downgrade.
- Use one small file past the limit. Never upload large volumes.

### BLV-014 Workflow step skipping
- Map multi-step flows: onboarding, KYC, terms acceptance, MFA enrollment, approval chains, shipping address.
- Call a later step's endpoint directly, or remove the `step` or `stage` parameter. Check whether server-side gates (KYC required, terms accepted) still apply.

### BLV-015 State machine manipulation
- List the valid states for orders, tickets, invoices, and documents. Send transitions the UI never offers: `cancelled` to `shipped`, `refunded` to `active`, `draft` to `approved`, `rejected` to `pending`.
- Try a `status` field in update requests (mass assignment) and replay old transition requests after the state changed.
- Revert the object after the test.

### BLV-016 Refund exploitation (authorized-only)
- Review only unless approved: refund after a digital download or after the service is consumed, a refund request replayed or sent in parallel, a refund to a different payment method or wallet, a partial refund whose sum exceeds the paid amount, and a refund that keeps the discount or reward.
- In an approved sandbox, record order and refund IDs and amounts.

### BLV-017 Trial date manipulation
- Find `trial_end`, `start_date`, `expires_at`, `days`, or `timezone` in signup, plan, or settings requests, plus client-side time checks in JS.
- Change the date or days value and check the server-side expiry (account page, billing API).
- Also check trial re-activation: cancel and restart, or a new workspace in the same account.

### BLV-018 Feature flag bypass
- Collect flags from JS bundles, `/api/features`, LaunchDarkly or Optimizely configs, and HTML data attributes (passive).
- Add or flip parameters: `beta=true`, `feature=x`, `flags[x]=1`, `enable_x=true`, `X-Feature-Flag` header, or a flag cookie.
- Finding = a gated feature works server-side, not just a UI element showing.

### BLV-019 Subscription tier bypass via role
- On a free account, change `plan`, `tier`, `subscription`, `role`, or `is_premium` in profile update, signup, or token-refresh requests, and inspect JWT or cookie claims.
- Call premium API endpoints directly with a free-account token.
- Check whether features remain after a downgrade or cancellation (see BL-X-017).

### BLV-020 Verification bypass in critical flows
- Look for `verified`, `email_verified`, `phone_verified`, or `skip_verification` in requests and responses; change them.
- Verify one address, then change it to another without re-verifying. Reuse an old code, or use a code issued for another address you own.
- Call the critical action (payout, transfer, profile change) before verification completes.
- Use only your own email and phone. For OTP brute-force and response manipulation, use authbypass.

## Cross-references

| BLV row | Related rows |
|---|---|
| BLV-001, 002, 003 | business-logic BL-X-001, 002, 003, 012, 013 |
| BLV-004 | BL-X-004, BL-X-005 |
| BLV-006 | BL-X-006 |
| BLV-008 | BL-X-007, 008, 009, 010 |
| BLV-011 | BL-X-016 |
| BLV-016 | BL-X-014 |
| BLV-017 | BL-X-018 |
| BLV-019 | BL-X-017, access-control skill |
| BLV-020 | authbypass skill |
