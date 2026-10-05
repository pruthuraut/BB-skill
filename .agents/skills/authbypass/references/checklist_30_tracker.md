# Login & Registration Bypass: 30-Item Master Audit Checklist

This checklist tracks execution progress across all 30 authentication bypass, registration flaw, middleware header spoofing, and privilege escalation checks. It maps directly into the 5 specialized subagents.

**Progress:** `[ 0 / 30 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Method / Verification | Status |
|---|-------------------|----------|-----------------------|--------|
| **01** | Test login for username/email enumeration via timing | Subagent 05 | Measure response latency deltas between valid and non-existent usernames | `[ ]` |
| **02** | Test login with SQL injection in username and password | Subagent 01 | Submit `' OR '1'='1`, `admin'--`, `' OR 1=1#` in auth parameters | `[ ]` |
| **03** | Test for NoSQL injection in authentication endpoints | Subagent 01 | Submit `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": "^admin"}` in JSON body | `[ ]` |
| **04** | Check for LDAP injection in enterprise authentication | Subagent 01 | Submit `*`, `admin*)(|(password=*)`, `)(cn=*))` in LDAP auth fields | `[ ]` |
| **05** | Test auth bypass via parameter tampering (`role=admin`) | Subagent 03 | Inject `role=admin`, `admin=1`, `is_admin=true` into login/session bodies | `[ ]` |
| **06** | Test auth bypass via HTTP method switching | Subagent 02 | Switch POST to GET, HEAD, PUT, OPTIONS, TRACE on login/protected endpoints | `[ ]` |
| **07** | Check auth bypass via forceful browsing to protected pages | Subagent 05 | Navigate directly to `/admin`, `/dashboard`, `/account` without auth cookies | `[ ]` |
| **08** | Test for broken authentication in password reset mechanism | Subagent 04 | Submit reset change without token, with empty token, or tampering `user_id` | `[ ]` |
| **09** | Check duplicate email/username handling & race conditions | Subagent 03 | Submit concurrent registration requests with identical email (Turbo Intruder) | `[ ]` |
| **10** | Test email verification bypass (direct activation) | Subagent 04 | Force status updates (`verified=true`), tamper activation link IDs, or skip step | `[ ]` |
| **11** | Test account takeover via email change without verification | Subagent 04 | Change account email without requiring current email confirmation link | `[ ]` |
| **12** | Test account takeover via phone number change without OTP | Subagent 04 | Update phone number in profile without sending confirmation code to old/new phone | `[ ]` |
| **13** | Test mass assignment in registration (`role`, `isAdmin`) | Subagent 03 | Submit `{"role":"admin", "is_admin":true, "tier":"enterprise"}` during signup | `[ ]` |
| **14** | Check for privilege escalation during user registration | Subagent 03 | Fuzz hidden registration fields: `account_type`, `group_id`, `privilege_level` | `[ ]` |
| **15** | Test `X-Forwarded-For` bypass of IP rate limiting | Subagent 02 | Rotate `X-Forwarded-For`, `X-Originating-IP`, `X-Client-IP` on blocked auth endpoints | `[ ]` |
| **16** | Test `X-Original-URL` / `X-Rewrite-URL` auth bypass | Subagent 02 | Send GET `/` with `X-Original-URL: /admin` or `X-Rewrite-URL: /dashboard` | `[ ]` |
| **17** | Check auth bypass via URL path manipulation | Subagent 02 | Probe `/api/v2/auth/` vs `/api/v1/`, `/login/..;/admin`, `//admin`, `/admin/.` | `[ ]` |
| **18** | Test HTTP parameter pollution in authentication | Subagent 02 | Submit `email=victim@target.com&email=attacker@target.com` in auth request | `[ ]` |
| **19** | Check for authentication via API key in URL query string | Subagent 02 | Audit `?api_key=`, `?token=` parameter leakage into browser history and Referer | `[ ]` |
| **20** | Test timing attack on authentication comparison | Subagent 05 | Measure microsecond differences in HMAC/token validation loops | `[ ]` |
| **21** | Test CAPTCHA bypass in registration and login forms | Subagent 05 | Omit `g-recaptcha-response`, send empty string, or replay solved CAPTCHA token | `[ ]` |
| **22** | Check account creation without email verification | Subagent 04 | Verify if unconfirmed accounts can perform sensitive financial/business actions | `[ ]` |
| **23** | Test disposable email acceptance in registration | Subagent 03 | Register using temporary email providers (`mailinator.com`, `guerrillamail.com`) | `[ ]` |
| **24** | Check for weak password reset security questions | Subagent 05 | Audit knowledge-based authentication (mother's maiden name, pet name) for OSINT | `[ ]` |
| **25** | Test registration with long inputs for buffer overflow/ReDoS | Subagent 01 | Submit 50,000-character strings in username and password fields | `[ ]` |
| **26** | Check for email bomb via repeated verification requests | Subagent 04 | Send 100 rapid requests to `/api/auth/resend-verification` without rate limits | `[ ]` |
| **27** | Test account lockout bypass via email case sensitivity | Subagent 05 | Test `Admin@target.com` vs `admin@target.com` vs `ADMIN@TARGET.COM` | `[ ]` |
| **28** | Check auth bypass via null byte in username | Subagent 01 | Submit `admin%00` or `admin\0` in username parameter (HackerOne null byte bug) | `[ ]` |
| **29** | Test Unicode case mapping confusion in username | Subagent 01 | Register `admın` (Turkish dotless i \u0131) and test if uppercase collides with `ADMIN` | `[ ]` |
| **30** | Check registration with admin-impersonating email format | Subagent 03 | Register `admin@target.com.attacker.com` or `admin+target@gmail.com` | `[ ]` |
