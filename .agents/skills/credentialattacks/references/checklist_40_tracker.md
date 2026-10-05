# Password & Credential Attacks: 40-Item Master Audit Checklist

This checklist tracks execution progress across all 40 authentication, credential security, rate limiting, password reset, and 2FA/MFA verification checks. It maps directly into the 5 specialized subagents.

**Progress:** `[ 0 / 40 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Method / Verification | Status |
|---|-------------------|----------|-----------------------|--------|
| **01** | Test for weak password policies (length, complexity) | Subagent 01 | Attempt registration with 1-char, all-numeric, and non-complex passwords | `[ ]` |
| **02** | Test for default credentials on admin panels & services | Subagent 02 | Probe `admin:admin`, `root:root`, `admin:password`, `tomcat:s3cret` | `[ ]` |
| **03** | Check for common passwords | Subagent 02 | Test top 20 weak passwords against discovered accounts | `[ ]` |
| **04** | Test password reset flow for token predictability/entropy | Subagent 03 | Collect consecutive reset tokens; calculate Shannon entropy & timestamp delta | `[ ]` |
| **05** | Check if password reset token is sent in URL (GET leakage) | Subagent 03 | Audit reset link structure (`?token=` vs POST / fragment) and Referer headers | `[ ]` |
| **06** | Test password reset for email/user enumeration | Subagent 03 | Compare HTTP response status, body size, and response time between valid/invalid emails | `[ ]` |
| **07** | Check if old password is required when changing password | Subagent 01 | Submit password change request omitting `current_password` parameter | `[ ]` |
| **08** | Test for password reuse policies and enforcement | Subagent 01 | Attempt changing password to the existing or recent passwords | `[ ]` |
| **09** | Check for credential stuffing vulnerability (lack of rate limit) | Subagent 02 | Send 50 automated login attempts; monitor for blocking or CAPTCHA trigger | `[ ]` |
| **10** | Test brute force protection with header bypasses | Subagent 02 | Test `X-Forwarded-For`, `X-Originating-IP`, `X-Client-IP` IP rotation | `[ ]` |
| **11** | Check for account lockout mechanism and its threshold | Subagent 02 | Submit 5-15 failed logins for a single account; monitor for 423 Locked / lockout message | `[ ]` |
| **12** | Test if account lockout can be used for user enumeration | Subagent 02 | Compare lockout triggers between existing and non-existent usernames | `[ ]` |
| **13** | Check if passwords are stored in plaintext or reversible encryption | Subagent 03 | Inspect password reset emails (does it email current password?), test profile endpoints | `[ ]` |
| **14** | Test for password length limit causing truncation attacks | Subagent 01 | Test bcrypt 72-byte truncation (e.g. password + 100 'A's still matches) | `[ ]` |
| **15** | Check for Unicode normalization issues in password handling | Subagent 01 | Test passwords with ligature characters (e.g. `ﬁ` vs `fi`, `ª` vs `a`) | `[ ]` |
| **16** | Test password field for SQL injection vulnerabilities | Subagent 01 | Submit `' OR '1'='1`, `' OR ''='`, `admin'--` in password field | `[ ]` |
| **17** | Check if passwords are always transmitted over HTTPS | Subagent 05 | Verify form action `https://`, HSTS headers, and non-HTTPS redirection | `[ ]` |
| **18** | Test for password stored in browser autocomplete | Subagent 05 | Inspect `<input type="password">` for `autocomplete="on"` or missing flag | `[ ]` |
| **19** | Check for password stored in localStorage/sessionStorage | Subagent 05 | Execute DOM check: inspect `window.localStorage` and `sessionStorage` post-login | `[ ]` |
| **20** | Test for 2FA/MFA bypass via direct endpoint access | Subagent 04 | Complete Step 1 login; navigate directly to `/dashboard` without OTP submission | `[ ]` |
| **21** | Check if 2FA can be bypassed via post-auth API endpoints | Subagent 04 | Send authenticated API requests using Step 1 session token without 2FA validation | `[ ]` |
| **22** | Test 2FA brute force on OTP verification codes | Subagent 04 | Send 1,000 OTP guesses with Turbo Intruder; check if OTP is invalidated | `[ ]` |
| **23** | Check if 2FA code is predictable or sequential | Subagent 04 | Generate 5 consecutive OTP requests; analyze PRNG entropy and increments | `[ ]` |
| **24** | Test 2FA code reuse (same code multiple times) | Subagent 04 | Submit the same valid OTP code across two concurrent requests | `[ ]` |
| **25** | Check if backup/recovery codes have sufficient entropy | Subagent 04 | Analyze format and entropy of backup codes (e.g. 8-character hex vs random words) | `[ ]` |
| **26** | Test if 2FA can be disabled without current 2FA verification | Subagent 04 | Send disable 2FA request without providing current OTP code or password | `[ ]` |
| **27** | Check for SMS interception / SIM swapping resilience | Subagent 04 | Audit available 2FA channels (SMS-only vs TOTP Authenticator vs WebAuthn) | `[ ]` |
| **28** | Test for 2FA bypass via response manipulation | Subagent 04 | Intercept failed OTP response (`400/403/401`); tamper status code to `200 OK` | `[ ]` |
| **29** | Check if 2FA is enforced for sensitive account actions | Subagent 05 | Attempt email change, password change, payout address update without 2FA prompt | `[ ]` |
| **30** | Test for rate limiting on 2FA verification endpoint | Subagent 04 | Submit rapid OTP verification requests; inspect `Retry-After` and 429 status | `[ ]` |
| **31** | Test password reset token expiration & single-use | Subagent 03 | Complete password reset; attempt reusing the identical reset link a second time | `[ ]` |
| **32** | Check password reset with different email (Host header / pollution) | Subagent 03 | Inject `X-Forwarded-Host: evil.com` or duplicate `email=` parameters in reset request | `[ ]` |
| **33** | Test password complexity bypass via encoding/special characters | Subagent 01 | Submit URL-encoded, HTML-entity, or null-byte characters (`%00`) in password | `[ ]` |
| **34** | Check for password maximum length DoS (long password hashing) | Subagent 01 | Submit a 10MB password string to measure CPU spike / server response latency | `[ ]` |
| **35** | Test for timing attack on password comparison function | Subagent 02 | Measure microsecond response deltas on correct vs incorrect first characters | `[ ]` |
| **36** | Check for password pepper usage in hash computation | Subagent 03 | Review architecture / documentation for HSM-backed secret pepper enforcement | `[ ]` |
| **37** | Test for simultaneous login from multiple locations policy | Subagent 05 | Authenticate session from IP A; authenticate session from IP B; check session A revocation | `[ ]` |
| **38** | Check for credential rotation policy enforcement | Subagent 05 | Verify account age and check for forced periodic password update prompts | `[ ]` |
| **39** | Test for password manager field detection (`new-password`) | Subagent 05 | Verify `<input autocomplete="new-password">` on registration/reset forms | `[ ]` |
| **40** | Check for CAPTCHA bypass on login/password reset forms | Subagent 02 | Submit requests with omitted, empty, or reused `g-recaptcha-response` parameters | `[ ]` |
