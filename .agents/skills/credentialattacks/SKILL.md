---
name: credentialattacks
description: Master authentication and credential security skill for exhaustive 40-point password policy auditing, brute-force & rate-limiting defenses, password reset flow analysis, and 2FA/MFA bypass testing based on TBHM v4.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `credentialattacks` — Universal Password & Credential Security Skill

## Overview
`credentialattacks` is a comprehensive offensive authentication security skill designed to execute an exhaustive **40-point credential security audit**. It audits password policy boundaries, brute-force and credential stuffing protections, IP rate-limit header bypasses (`X-Forwarded-For`), password reset flows (token entropy, Host header injection takeovers), and multi-factor authentication (2FA/MFA) bypasses (direct access, response manipulation, OTP brute forcing) based on Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)* and real-world bounty notes.

```
                              [ TARGET AUTHENTICATION ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Password Policy│          │  Brute-Force &  │          │  Reset Flows &  │
  │  & Input Flaws  │          │  Rate Limiting  │          │  Takeover Risks │
  │  (8 Checks)     │          │  (8 Checks)     │          │  (7 Checks)     │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
  ┌─────────────────┐                                       ┌─────────────────┐
  │  Subagent 04    │                                       │  Subagent 05    │
  │  2FA/MFA Bypass │                                       │  Client-Side    │
  │  & OTP Auditing │                                       │  Transport & Sess│
  │  (10 Checks)    │                                       │  (7 Checks)     │
  └────────┬────────┘                                       └────────┬────────┘
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT ARTIFACTS ]
                       • credential_audit_report.json
                       • 2fa_bypasses.txt
                       • rate_limit_bypasses.txt
                       • account_takeover_risks.txt
                       • checklist_40_tracker.md (40/40 Complete)
```

---

## The 5 Specialized Subagents

1. **[Subagent 01: Password Policies, Encodings & Input Flaws](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/subagents/subagent_01_password_policies_input.md)**
   *Checks: 01, 07, 08, 14, 15, 16, 33, 34*
   *Focus:* Password complexity, old password verification, password reuse, bcrypt 72-byte truncation, Unicode normalization, SQL injection in password field, and hashing CPU DoS.
2. **[Subagent 02: Default Credentials, Brute Force & Rate Limiting Defenses](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/subagents/subagent_02_bruteforce_ratelimit_defaults.md)**
   *Checks: 02, 03, 09, 10, 11, 12, 35, 40*
   *Focus:* Default service credentials, credential stuffing velocity limits, `X-Forwarded-For` IP spoofing bypasses, account lockout user enumeration, password comparison timing attacks, and CAPTCHA bypasses.
3. **[Subagent 03: Password Reset Flows & Account Takeovers](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/subagents/subagent_03_reset_flows_takeovers.md)**
   *Checks: 04, 05, 06, 13, 31, 32, 36*
   *Focus:* Token PRNG entropy, GET parameter leakage, email enumeration, single-use token replay, Host header injection account takeovers, and plaintext password storage.
4. **[Subagent 04: Multi-Factor Authentication (2FA/MFA) Bypass Auditing](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/subagents/subagent_04_2fa_mfa_bypass.md)**
   *Checks: 20, 21, 22, 23, 24, 25, 26, 27, 28, 30*
   *Focus:* Direct endpoint navigation (`/dashboard`), post-auth API token access without 2FA claim, OTP brute force, sequential codes, code reuse race conditions, backup code entropy, unverified 2FA deactivation, and response status-code tampering (`400/403` to `200 OK`).
5. **[Subagent 05: Client-Side Security, Transport & Session Policies](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/subagents/subagent_05_client_transport_sessions.md)**
   *Checks: 17, 18, 19, 29, 37, 38, 39*
   *Focus:* HTTPS enforcement, browser autocomplete attributes, `localStorage` / `sessionStorage` credential leakage, step-up 2FA re-authentication on sensitive actions, and concurrent multi-session revocation.

For rate-limit IP header bypasses and step-by-step reproduction guides, refer to:
- [Rate Limiting & IP Header Spoofing Reference](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/references/rate_limit_bypass_headers.md)
- [OTP Rate Limiting, Throttling Bypass & Financial Resource Exhaustion Playbook](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/credentialattacks/references/otp_rate_limiting_and_dos_playbook.md)

---

## Master Orchestration Workflow

When executing this skill against a target authentication system:

### Phase 1: Policy & Input Validation (Subagent 01)
* Test password registration with 1-character, numeric, and trivial passwords.
* Test password change omitting the current password parameter.
* Submit a password longer than 72 bytes to test for bcrypt truncation.
* Test Unicode normalization and SQL injection payloads (`' OR '1'='1`) in password fields.

### Phase 2: Brute-Force, Rate Limiting & Lockout Auditing (Subagent 02)
* Check default administrative credentials (`admin:admin`, `tomcat:s3cret`).
* Execute 30 rapid login attempts to measure velocity rate limiting.
* Test header-based IP rotation (`X-Forwarded-For`, `X-Client-IP`, `X-Originating-IP`).
* Measure account lockout thresholds and verify if lockout messages leak user existence.
* Test CAPTCHA validation (omission, empty token, token replay).

### Phase 3: Password Reset Lifecycle & Account Takeover (Subagent 03)
* Test password reset for user enumeration via status code, body, or timing deltas.
* Collect multiple reset tokens to evaluate PRNG entropy and timestamp dependency.
* Verify if reset tokens are sent in URL query strings without restrictive Referrer-Policy.
* Test token single-use invalidation by replaying a completed reset token.
* Inject `Host: evil.com` and `X-Forwarded-Host: evil.com` into password reset requests to test for reset poisoning.

### Phase 4: 2FA / MFA Multi-Factor Bypass Auditing (Subagent 04)
* Complete Step 1 login; attempt direct navigation to `/dashboard` and call authenticated APIs.
* Test 2FA OTP brute-forcing and velocity limits on `/verify-2fa`.
* Intercept failed OTP responses and tamper HTTP status code from `400/403` to `200 OK`.
* Test sending concurrent requests with the same valid OTP to verify one-time use.
* Attempt disabling 2FA without entering the current OTP code.

### Phase 5: Client-Side Credential Storage & Transport Security (Subagent 05)
* Verify strict HTTPS submission for login and reset forms.
* Inspect `localStorage` and `sessionStorage` for cached credentials post-login.
* Audit password input fields for proper `autocomplete` attributes (`current-password`, `new-password`).
* Test step-up 2FA requirements on sensitive account actions (email/payout changes).

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
* `artifacts/credential_audit_report.json` — Consolidated findings across all 40 checks.
* `artifacts/2fa_bypasses.txt` — Confirmed multi-factor authentication bypass vectors.
* `artifacts/rate_limit_bypasses.txt` — Successful IP-spoofing and velocity bypass headers.
* `artifacts/account_takeover_risks.txt` — Password reset poisoning and token reuse findings.
* `artifacts/checklist_40_tracker.md` — 40/40 completed verification matrix.
