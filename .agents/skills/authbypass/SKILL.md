---
name: authbypass
description: Master authentication and registration security skill for exhaustive 30-point login/registration bypass auditing, NoSQL/SQL/LDAP injection, mass assignment, email verification bypasses, and account takeovers based on TBHM v4.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `authbypass` — Universal Login & Registration Bypass Skill

## Overview
`authbypass` is an offensive authentication and identity lifecycle auditing skill designed to execute an exhaustive **30-point login and registration security audit**. It audits injection flaws (SQLi, NoSQLi, LDAP), protocol and middleware bypasses (`X-Original-URL`, HTTP verb switching, path traversal differentials), mass assignment privilege escalation, email/phone verification bypasses, and account takeover vectors based on Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)* and real-world bounty disclosures.

```
                              [ AUTHENTICATION TARGET ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Injections &   │          │  Middleware,    │          │  Registration & │
  │  Semantics      │          │  Headers & Paths│          │  Mass Assignment│
  │  (6 Checks)     │          │  (6 Checks)     │          │  (6 Checks)     │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
  ┌─────────────────┐                                       ┌─────────────────┐
  │  Subagent 04    │                                       │  Subagent 05    │
  │  Verification   │                                       │  Enumeration,   │
  │  & Takeovers    │                                       │  Timing & WAF   │
  │  (6 Checks)     │                                       │  (6 Checks)     │
  └────────┬────────┘                                       └────────┬────────┘
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT ARTIFACTS ]
                       • auth_bypasses_confirmed.txt
                       • account_takeover_vectors.txt
                       • mass_assignment_report.json
                       • path_bypasses.txt
                       • checklist_30_tracker.md (30/30 Complete)
```

---

## The 5 Specialized Subagents

1. **[Subagent 01: Injection & Semantic Payload Bypasses](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/subagents/subagent_01_injection_semantic_bypasses.md)**
   *Checks: 02, 03, 04, 25, 28, 29*
   *Focus:* SQL injection (`' OR 1=1--`), NoSQL operator injection (`{"$gt": ""}`), LDAP injection (`*`), Null Byte truncation (`admin%00`), Unicode Turkish dotless `ı` case collisions, and ReDoS/buffer overflow string lengths.
2. **[Subagent 02: HTTP Protocol & Middleware Header Bypasses](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/subagents/subagent_02_middleware_headers_pathing.md)**
   *Checks: 06, 15, 16, 17, 18, 19*
   *Focus:* HTTP method switching (POST -> GET/PUT/HEAD), `X-Original-URL` / `X-Rewrite-URL` reverse proxy overrides, URL path traversal differentials (`/login/..;/admin`), HTTP parameter pollution, and API key query leakage.
3. **[Subagent 03: Registration Logic, Mass Assignment & Privilege Escalation](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/subagents/subagent_03_registration_mass_assignment.md)**
   *Checks: 05, 09, 13, 14, 23, 30*
   *Focus:* Parameter tampering (`role=admin`), mass assignment (`"isAdmin": true`), privilege escalation during signup, duplicate registration race conditions, disposable email domain acceptance, and admin-impersonating email syntax.
4. **[Subagent 04: Verification Workflows & Account Takeover Flaws](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/subagents/subagent_04_verification_account_takeovers.md)**
   *Checks: 08, 10, 11, 12, 22, 26*
   *Focus:* Broken password reset validation, email verification bypass (response code tampering, direct step skipping), account takeover via unverified email updates, account takeover via phone number modifications, and verification email bombing.
5. **[Subagent 05: Enumeration, Timing Attacks & Defensive Controls](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/subagents/subagent_05_enumeration_timing_controls.md)**
   *Checks: 01, 07, 20, 21, 24, 27*
   *Focus:* Username/email enumeration via password hashing timing deltas, forceful browsing to protected endpoints, timing attacks on comparison functions, CAPTCHA omission/replay, weak KBA security questions, and case-sensitive account lockout bypasses.

For payload references and step-by-step reproduction guides, consult:
- [Authentication Bypass Payloads Reference](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/references/auth_bypass_payloads.md)
- [Real-World Session Puzzling, Response Manipulation & HPP Playbook](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/authbypass/references/session_puzzling_and_otp_playbook.md)

---

## Master Orchestration Workflow

When this skill is executed against a target authentication system:

### Phase 1: Injection & Semantic Payload Verification (Subagent 01)
* Probe SQL injection in login parameters (`' OR '1'='1`).
* Test NoSQL operator injections (`{"$ne": null}`) in JSON bodies.
* Test Null Byte injection (`admin%00`).
* Test Unicode case mapping confusion (`admın` vs `ADMIN`).

### Phase 2: Protocol & Reverse Proxy Header Manipulation (Subagent 02)
* Switch HTTP methods on protected endpoints (POST -> GET/PUT/OPTIONS).
* Inject `X-Original-URL: /admin` and `X-Rewrite-URL: /admin` on root/login requests.
* Test path normalization differentials (`/login/..;/admin`).
* Test HTTP parameter pollution with duplicate parameters.

### Phase 3: Registration Lifecycle & Mass Assignment (Subagent 03)
* Inject administrative properties (`"role":"admin"`, `"isAdmin":true`) during user registration.
* Submit concurrent registration requests for the same email to test for race conditions.
* Test disposable email domain acceptance (`mailinator.com`).
* Attempt registration with admin-impersonating email structures.

### Phase 4: Verification & Account Takeover Auditing (Subagent 04)
* Test bypassing email verification by navigating directly to post-auth pages or tampering response codes.
* Audit profile email update functionality (verify if confirmation is required on the *current* email).
* Audit phone number updates.
* Test sending rapid verification email triggers to verify velocity rate limiting.

### Phase 5: Timing Side-Channels & Defensive Mechanisms (Subagent 05)
* Measure response latency deltas between valid and invalid usernames.
* Test forceful browsing to `/admin` and authenticated routes without cookies.
* Attempt CAPTCHA omission and token replay.
* Test case-variant emails (`Admin@` vs `admin@`) to bypass account lockout.

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
* `artifacts/auth_bypasses_confirmed.txt` — Verified login and authorization bypasses.
* `artifacts/account_takeover_vectors.txt` — Confirmed account takeover findings.
* `artifacts/mass_assignment_report.json` — Accepted elevated registration parameters.
* `artifacts/path_bypasses.txt` — Middleware header and path traversal overrides.
* `artifacts/checklist_30_tracker.md` — 30/30 completed verification matrix.
