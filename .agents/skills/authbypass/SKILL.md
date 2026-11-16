---
name: authbypass
description: Audit authorized login, registration, verification, password-reset and OTP flows across 40 checks — SQL/NoSQL/LDAP injection, null-byte and Unicode case-mapping collisions, HTTP method switching, X-Original-URL and path-normalisation bypasses, parameter pollution, mass assignment and registration privilege escalation, email-parameter manipulation, duplicate/twin accounts, SQL truncation, email/phone change ATO, email-verification bypass chains, leaked tokens, OTP bypass, org email-domain trust, enumeration and timing, CAPTCHA and lockout bypass, path overwrite and stored/blind XSS via identity fields. Built on PortSwigger authentication, access-control, logic-flaw and race-condition labs, OWASP WSTG ATHN/IDNT and the Authentication, Forgot Password, MFA and Mass Assignment cheat sheets.
version: "2.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `authbypass` — Login & Registration Bypass

Find ways to log in as someone else, create an account with privileges or an identity you should not have, or get past verification/OTP/reset controls. The checks are grouped into six subagents; AB-01…AB-30 are the core list and AB-31…AB-40 extend it with verification chains, identity collisions, OTP bypass, and stored input in identity fields.

Primary methodology sources:

- PortSwigger Web Security Academy — Authentication (password-based, multi-factor, other mechanisms), Access control, Business logic examples, Race conditions, SQL/NoSQL injection, Server-side parameter pollution; research *Splitting the email atom* (2024)
- OWASP WSTG v4.2 — 4.3 Identity Management (IDNT-02/03/04/05), 4.4 Authentication (ATHN-03/04/08/09/10), 4.7 Input Validation (SQLi, NoSQLi, LDAP, HPP)
- OWASP Cheat Sheets — Authentication, Forgot Password, Multifactor Authentication, Mass Assignment, Choosing and Using Security Questions
- Community checklists supplied with this skill (email-parameter manipulation, verification bypass chains, twinning, SQL truncation, OTP bypass list, path overwrite, blind XSS)

## Authorization and safety boundary

- Pass the scope gate (below) before any request.
- Use **self-owned accounts only**: A (attacker), B (victim), C (spare), each with an inbox/phone you control. "Victim" addresses in payloads are always **your** B address, never a real user or staff member. Do not register real employees' or `support@target` addresses; prove domain-trust issues with your own domain or the program's designated test domain.
- Rate-sensitive tests are capped: ≤ 15 verification/contact emails, ≤ 20 OTP guesses on your own account (enough to prove a missing limit), ≤ 12 timing samples per name by default. Never brute-force other users' credentials or OTPs.
- Oversized-input tests are single requests at increasing sizes (≤ 100 KB), with pauses — not a DoS.
- SQL/NoSQL/LDAP injection: prove login bypass **as your own account** or a boolean/time signal; do not extract data — hand off to the injection skills.
- Blind XSS uses your own collector and beacon-only payloads. Do not reuse third-party collector IDs from public notes.
- Clean up: delete or rename test accounts that occupy reserved names, revert email/phone changes, and note it in the report.

## Inputs

1. HAR captures of: registration (incl. verification), login (incl. MFA/OTP), logout, forgot/reset password, email change, phone change, invite acceptance, SSO linking
2. `artifacts/discovered_endpoints.txt`, `artifacts/discovered_parameters.json`, `artifacts/technology_profile.json`
3. Hidden/legacy auth endpoints from `contentdiscovery`, `jsrecon` (`/api/v1/register`, `/admin/register`, mobile APIs)
4. Output of `session-management` (session rotation) and `oauth-sso` (SSO linking) where flows overlap

## Workflow

1. **Map the identity lifecycle** for each account type: register → verify → login → MFA → change email/phone/password → reset → delete. Record identifiers (email, username, phone, user ID), how each is normalised, and every endpoint that sends an email/SMS. Write `artifacts/authbypass/identity_map.md`.
2. **Generate payloads offline**: `scripts/identity_variants.py` (email, username, Unicode, truncation, reserved names).
3. **Run the 40-check ledger** in [references/checklist_40.md](references/checklist_40.md) using the subagent split; each subagent file has the step-by-step playbook.
4. **Chain** findings: unverified account + SSO auto-merge (→ `oauth-sso` OA-31); email-change chain + org domain trust (AB-31 → AB-37); HPP in reset (AB-18) + email header injection (AB-33); path overwrite + OAuth redirect gadget (AB-38 → OA-03).
5. **Prove impact minimally** between your own accounts and record request/response pairs.
6. **Report** artifacts and update `[ N / 40 ]`.

## The six subagents

| Subagent | File | Checks |
|---|---|---|
| **01** Injection & Semantic Bypasses | [subagent_01](subagents/subagent_01_injection_semantic_bypasses.md) | 02, 03, 04, 25, 28, 29 |
| **02** Middleware, Headers & Paths | [subagent_02](subagents/subagent_02_middleware_headers_pathing.md) | 06, 15, 16, 17, 18, 19 |
| **03** Registration, Mass Assignment & Identity Collisions | [subagent_03](subagents/subagent_03_registration_mass_assignment.md) | 05, 09, 13, 14, 23, 30, **33, 34, 35** |
| **04** Verification, Reset, OTP & Account Takeover | [subagent_04](subagents/subagent_04_verification_account_takeovers.md) | 08, 10, 11, 12, 22, 26, **31, 32, 36, 37** |
| **05** Enumeration, Timing & Defensive Controls | [subagent_05](subagents/subagent_05_enumeration_timing_controls.md) | 01, 07, 20, 21, 24, 27 |
| **06** Stored Input in Identity Fields & Public Forms | [subagent_06](subagents/subagent_06_identity_field_injection_public_forms.md) | **38, 39, 40** |

Supporting references:
- [references/checklist_40.md](references/checklist_40.md) — every check with severity, commands, pass/fail and references
- [references/email_manipulation_payloads.md](references/email_manipulation_payloads.md) — email/username manipulation, Unicode, truncation, stored-injection payloads
- [references/auth_bypass_payloads.md](references/auth_bypass_payloads.md) — SQLi/NoSQLi/LDAP/header/path payloads
- [references/session_puzzling_and_otp_playbook.md](references/session_puzzling_and_otp_playbook.md) — session puzzling, response manipulation ATO, HPP in OTP

## Status values

- `PASS` — applicable, executed, negative evidence saved.
- `FINDING` — reproduced between self-owned accounts; evidence saved.
- `INFO` — weakness without demonstrated impact (disposable emails accepted, weak timing signal, enumeration on a non-sensitive endpoint).
- `NOT_APPLICABLE` — feature absent (no phone, no security questions, no CAPTCHA); evidence cited.
- `BLOCKED` — cannot execute (needs a second phone number, invite from an admin, scope limits).

Response manipulation (flipping `false` → `true` in your proxy) is only a finding when the **server** subsequently grants the state; a UI-only change is `PASS`/`INFO`.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Login as another user (SQLi/NoSQLi/LDAP bypass, Unicode/truncation collision, reset/OTP/HPP ATO, email change ATO) | Critical |
| Mass assignment / registration privilege escalation, org-domain trust bypass, verification bypass enabling impersonation of a verified address | High–Critical |
| Method/path/header middleware bypass to authenticated content | High (depends on content) |
| OTP or login brute force possible (no limit), CAPTCHA bypass enabling automation, path overwrite of sensitive routes, stored XSS in identity fields | Medium–High |
| Username enumeration, email bombing, disposable emails, weak KBA, API key in URL | Low–Medium / Info (program dependent) |

## Helper scripts

```bash
S=.agents/skills/authbypass/scripts

# Offline: identity manipulation candidates (TSV: check_id, family, payload)
python3 -I $S/identity_variants.py --mode email --email you+b@your-domain.test --attacker you+a@your-domain.test
python3 -I $S/identity_variants.py --mode all --email you+b@your-domain.test --attacker you+a@your-domain.test --username bbtestb

# Scope-gated: method / rewrite-header / path / API-version / IP-header matrix for one protected URL
$S/bypass_matrix.sh --target example.com --url https://app.example.com/admin --out artifacts/authbypass/bypass_matrix.tsv

# Scope-gated: timing comparison (your account vs random names), interleaved, Mann-Whitney U
python3 -I $S/timing_enum.py --target example.com --url https://app.example.com/login \
  --data 'username={user}&password=WrongPass!{n}' --users bbtestA,nouser_x1,nouser_x2 --samples 12 --delay 1
```

Related tools: Burp Suite (Repeater groups / single-packet attack for races, Intruder, Turbo Intruder, Collaborator, Param Miner for hidden params), `ffuf` for hidden registration fields with `wordlists/params.txt`, `sqlmap` only when the injection skill takes over.

## Required artifacts

- `artifacts/authbypass/identity_map.md`
- `artifacts/authbypass/bypass_matrix.tsv`, `artifacts/authbypass/timing_*.txt`
- `artifacts/authbypass/evidence/AB-XX_<short>.txt`
- `artifacts/authbypass/authbypass_checklist_40.tsv` — `check_id  subagent  status  severity  finding_id  evidence_path  notes`
- `artifacts/auth_bypasses_confirmed.txt`, `artifacts/account_takeover_vectors.txt`, `artifacts/mass_assignment_report.json`, `artifacts/path_bypasses.txt` (kept for compatibility with `recon-hunter` and older runs)
- `artifacts/authbypass_report.md` — findings, chains, false positives, blocked checks, `[ N / 40 ]`

## Related skills

- `credentialattacks` — password policy, brute force, reset-flow depth, 2FA/MFA (overlaps AB-08, AB-15, AB-36: run once, cross-reference)
- `session-management` — session rotation after login/reset/email change (SM-03/04/08)
- `oauth-sso` — SSO account linking and pre-account takeover (OA-31), LDAP injection on IdP login (OA-25)
- `access-control` — impact of escalated roles; `business-logic-vulns` — races and multi-account abuse

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, registrations, login attempts, emails/SMS triggered, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.

## Extended checklist (added)

- File: `references/login_reset_admin_extended.md` (Login, registration, reset, OTP, and admin path checks).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
