# Login, Registration, Password Reset, and Admin Entry Checks (extension)

Class key: `passive`, `bounded` (own test accounts, bounded counts), `authorized-only` (credential tests, lockout-sensitive flows).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| AUTH-X-001 | Login | SQL or NoSQL operator in username/password (see server-side-injection) | bounded | Own account with operator probe, compare responses |
| AUTH-X-002 | Login | Null byte or Unicode case-mapping username collision | bounded | Own test accounts only |
| AUTH-X-003 | Login | HTTP method switch bypasses login check | bounded | Method variation on own path |
| AUTH-X-004 | Admin path | X-Original-URL, X-Rewrite-URL, or path-normalization bypass of 403 | bounded | Header and path variants compared to baseline |
| AUTH-X-005 | Admin path | Forced browsing of /admin, /manager, /debug | passive | Status and title only |
| AUTH-X-006 | Registration | Mass assignment of role or isAdmin at signup | bounded | Own signup with extra field, check stored role |
| AUTH-X-007 | Registration | Duplicate or twin accounts via case or Unicode variants | bounded | Own addresses variants |
| AUTH-X-008 | Registration | Email domain trust for org SSO (anyone with @company can join) | bounded | Own address with org domain, check access |
| AUTH-X-009 | Email change | Email change without re-authentication leads to ATO | bounded | Own account two sessions |
| AUTH-X-010 | Email change | Verification sent to old and new address; token reuse | bounded | Own account flow |
| AUTH-X-011 | Verification | Email verification bypass (token not bound to account) | bounded | Own two accounts swap tokens |
| AUTH-X-012 | Verification | Verification token leaked in API response | bounded | Inspect own signup response |
| AUTH-X-013 | OTP | OTP accepted after expiry or reuse | bounded | Own account, one reuse test |
| AUTH-X-014 | OTP | OTP rate limit bypass via X-Forwarded-For | bounded | At most 10 requests on own account |
| AUTH-X-015 | Password reset | Reset token predictable or reusable | bounded | Two own resets, compare tokens |
| AUTH-X-016 | Password reset | Host header poisoning of reset link | bounded | See open-redirect-and-header-injection HDR-001 |
| AUTH-X-017 | Password reset | Email parameter override (reset sent to attacker address) | bounded | Own two addresses |
| AUTH-X-018 | Account | Account enumeration via response difference or timing | bounded | 5 valid vs 5 invalid usernames (own list), compare |
| AUTH-X-019 | Account | Stored XSS through identity fields (name, username) | bounded | Own profile marker |
| AUTH-X-020 | Account | Path overwrite via username (`../`) | bounded | Own account, harmless marker |
| AUTH-X-021 | Account | SQL truncation of long email (MySQL) | bounded | Own signup with long email; check duplicate creation |
| AUTH-X-022 | Lockout | Lockout bypass by changing case or whitespace in username | bounded | Own account, 5 attempts each |
| AUTH-X-023 | CAPTCHA | CAPTCHA not validated server-side | bounded | Own request without token |
| AUTH-X-024 | Login page | Autocomplete on password fields and remember-me weak | passive | Inspect HTML |
| AUTH-X-025 | Default creds | Default admin credentials on admin login | authorized-only | Only with approval |
