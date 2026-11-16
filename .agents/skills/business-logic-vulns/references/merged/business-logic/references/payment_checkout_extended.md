# Business Logic: Price, Checkout, Coupons, Races, and Payment Flows (extension)

Class key: `bounded` checks use your own test cart, test coupon, and test payment mode or sandbox. `authorized-only` = anything that could create real charges or affects other customers.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| BL-X-001 | Price | Client-sent price accepted by checkout | bounded | Own cart, modify price in request to a test value, check total on server response (sandbox only) |
| BL-X-002 | Price | Negative quantity or zero price accepted | bounded | Own cart with qty -1, expect rejection |
| BL-X-003 | Price | Currency code switch to cheaper currency | bounded | Own cart, change currency field, compare totals |
| BL-X-004 | Discount | Discount code reapplied repeatedly | bounded | Own coupon applied 3 times, check total |
| BL-X-005 | Discount | Coupon persists after removing item | bounded | Own cart: add, coupon, remove, check |
| BL-X-006 | Coupon | Single-use coupon redeemed by parallel requests (race) | authorized-only | Approved test with own coupon and sandbox; 2 to 5 parallel requests max |
| BL-X-007 | Workflow | Checkout step skipped (direct POST to confirm) | bounded | Own cart, call final step without payment step, in sandbox |
| BL-X-008 | Payment | Order marked paid without gateway confirmation | bounded | Sandbox order, inspect status transitions |
| BL-X-009 | Payment | Gateway ID or skipGateway parameter accepted | bounded | Sandbox order, invalid gateway ID expect rejection |
| BL-X-010 | Payment | Webhook accepted without signature (Shopify and Stripe style) | bounded | Own webhook test with bad signature, expect rejection |
| BL-X-011 | Shopify apps | Webhook HMAC not validated | bounded | Same as BL-X-010 on own dev app |
| BL-X-012 | Craft Commerce | cart update accepts price field | bounded | Same as BL-X-001 on own cart |
| BL-X-013 | Drupal Commerce | cart add accepts price parameter | bounded | Same as BL-X-001 on own cart |
| BL-X-014 | Ecommerce | Refund or cancel without payment reversal | authorized-only | Review only |
| BL-X-015 | Ecommerce | Inventory oversell through parallel checkouts | authorized-only | Approved sandbox test |
| BL-X-016 | Gift cards | Balance manipulation through negative amount | bounded | Own gift card, negative amount, expect rejection |
| BL-X-017 | Subscriptions | Plan downgrade keeps premium features | bounded | Own account plan change, check entitlements |
| BL-X-018 | Account | Trial re-activation with new email | bounded | Own two addresses |
| BL-X-019 | Payments | Card or account data shown in plaintext in responses | passive | Review own checkout responses (no card data entered beyond sandbox numbers) |
| BL-X-020 | Payments | Secret keys in checkout JS (Stripe sk_, Braintree private_key) | passive | See saas-third-party-exposure SAAS-004, SAAS-008, SAAS-074 |
| BL-X-021 | Fintech | Plaid client secret in JS | passive | See saas file |
| BL-X-022 | Remittance | Transaction amount rounding abuse | authorized-only | Review only |
| BL-X-023 | Sandbox | Production payment endpoints reachable from test accounts | authorized-only | Do not charge real cards; report status codes only |
