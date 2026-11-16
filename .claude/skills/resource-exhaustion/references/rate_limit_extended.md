# Rate Limits, Form Flooding, and Velocity (extension)

All checks here are bounded by design: at most 20 requests per endpoint per session, on your own account, rate limited. Flood or denial-of-service tests are not part of this skill. A source checklist item that loops 100 concurrent requests is replaced by the bounded check below.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RATE-X-001 | Login | Rate limit on login endpoint | bounded | 20 sequential failed attempts on own account; look for 429 or lockout |
| RATE-X-002 | Login | Rate limit bypass via X-Forwarded-For rotation | bounded | 10 attempts with varying XFF on own account; compare throttling |
| RATE-X-003 | Login | Rate limit keyed on username, bypassed with case or trailing space | bounded | 5 attempts per variant on own account |
| RATE-X-004 | Login | Rate limit bypass via duplicate parameters | bounded | Duplicate param on own account, 5 attempts |
| RATE-X-005 | OTP | OTP attempts unlimited | bounded | 10 attempts on own OTP flow |
| RATE-X-006 | Password reset | Reset emails unlimited (email bombing) | bounded | 5 resets to own address, check throttling |
| RATE-X-007 | SMS | Financial exhaustion via SMS endpoints | bounded | Own phone number, 3 sends, check throttle |
| RATE-X-008 | Forms | Contact or signup form without rate limit | bounded | 10 submissions with own test marker |
| RATE-X-009 | Forms | CAPTCHA not enforced on repeated submissions | bounded | Own request without token |
| RATE-X-010 | Search | Expensive search endpoint without limit | bounded | 5 sequential heavy queries, compare latency |
| RATE-X-011 | API | Missing per-key or per-user quota | bounded | 20 requests, check X-RateLimit headers |
| RATE-X-012 | API | GraphQL batching bypasses rate limit | bounded | One batched request with 10 operations (own account) |
| RATE-X-013 | Destructive actions | Delete or cancel without re-authentication | bounded | Own test resource, check reauth prompt |
| RATE-X-014 | Account | Account lockout enables DoS of victim | authorized-only | Review policy; no lockout of real accounts |
| RATE-X-015 | Velocity | Coupon or voucher redemption velocity | bounded | Own coupon, 3 sequential redemptions (see business-logic) |
| RATE-X-016 | Headers | Rate-limit headers absent | passive | Response headers |
