---
name: session-management
description: Audit authorized web applications across 40 session-management checks covering token entropy and length, fixation and rotation, logout/timeout/password-change invalidation, cookie attributes and prefixes, token leakage (URL, Referer, logs, POST body), session binding, WebSocket and CSRF coupling, refresh-token rotation, and JWT weaknesses (alg none, RS256→HS256 confusion, weak secrets, jku/x5u/kid injection, claim tampering, revocation). Built on PortSwigger Web Security Academy and OWASP WSTG-SESS / Session Management and JWT cheat sheets. Use after authentication flows are mapped and two self-owned test accounts exist.
---

# Session Management Audit

Determine whether the application issues, binds, protects, rotates, and destroys session state so that an attacker cannot predict, fix, steal, replay, or forge another user's session. Every check is executed **only against sessions belonging to test accounts you own**.

Primary methodology sources:

- OWASP WSTG v4.2 §4.6 Session Management Testing (WSTG-SESS-01 … WSTG-SESS-10)
- OWASP Session Management Cheat Sheet, JSON Web Token Cheat Sheet, CSRF Prevention Cheat Sheet
- OWASP ASVS v4.0.3 Chapter V3 (Session Management) and V3.5 (Token-based Session Management)
- PortSwigger Web Security Academy: Authentication, JWT attacks, CSRF / SameSite, XSS exploitation, WebSockets, Burp Sequencer

## Authorization and safety boundary

- Pass the scope gate (below) before any request to the target.
- Use **two self-owned test accounts** (`ATTACKER` = A, `VICTIM` = B) plus, where possible, an unauthenticated browser profile. Never test against, read, or replay sessions belonging to real users.
- Fixation, hijacking, and CSRF proofs must transfer a token **between your own two accounts/browsers only**. XSS-based hijack proofs read `document.cookie` in your own session and display or send it to infrastructure you control; never deploy a stored payload that would execute for other users without explicit program permission.
- JWT secret cracking is **offline only** against tokens issued to your own accounts. Forged JWTs may claim only your own `sub`/user ID unless the program explicitly authorizes cross-user or role-elevation proof; if elevation is authorized, read one harmless endpoint and stop.
- Token collection for entropy analysis targets an **unauthenticated** session-issuing endpoint at a bounded rate (default 200 samples, ≥ 200 ms apart). Do not create hundreds of accounts or logins unless authorized.
- CRLF/cookie-injection probes use a benign marker cookie (`bbtest=1`) and must not poison shared caches; add a unique cache-buster to every probe.
- Timeout tests involve waiting, not flooding. Never run concurrent-session or logout checks in a way that locks out or logs out a real user.

## Inputs

1. `artifacts/technology_profile.json` (framework, session store hints, JWT presence)
2. `artifacts/discovered_endpoints.txt` and `artifacts/discovered_parameters.json`
3. Login, logout, password-change, role-change, refresh, and WebSocket endpoints identified by `authbypass`, `credentialattacks`, `linkparamdiscovery`
4. A proxy history (Burp/Caido HAR export) of a full login → use → logout cycle for each test account

Record which token(s) actually carry the session: cookie(s), `Authorization: Bearer`, custom header, localStorage/sessionStorage, or a combination. Many checks must be repeated for each carrier.

## Workflow

1. **Map the session architecture.** From one clean login HAR, identify: pre-auth token(s), post-auth token(s), refresh token, CSRF token, WebSocket auth, and where each is stored and sent. Decode anything that looks structured (`jwt_inspect.py`, base64, Flask/Rails/Express signed cookies). Write `artifacts/session/session_map.md`.
2. **Run the 40-check ledger** in [references/checklist_40.md](references/checklist_40.md) using the subagent split below. Each row gets a status, severity (if a finding), and evidence path.
3. **Correlate.** Chain findings where they compound (e.g., missing HttpOnly + XSS = SM-11 + SM-16; fixation + no rotation = SM-03/04/36). Use one finding ID per root cause and cross-reference rows.
4. **Validate impact.** Each `FINDING` needs a minimal reproduction using only A/B accounts with request/response pairs and timestamps.
5. **Report.** Produce the required artifacts and update the progress counter `[ N / 40 ]` as you go.

## Subagent split

Divide the ledger across five subagents to preserve context. Each subagent receives `session_map.md`, the two test-account credentials, and only its checks.

| Subagent | Focus | Checks |
|---|---|---|
| **SM-A** Token Generation & Exposure | entropy, length, cross-account predictability, server- vs client-side storage, token in URL / POST body / logs / Referer | 01, 02, 09, 19, 20, 35, 37, 39 |
| **SM-B** Session Lifecycle | fixation, rotation on login and privilege change, logout, idle/absolute timeout, concurrent sessions, password-change invalidation | 03, 04, 05, 06, 07, 08, 34, 36 |
| **SM-C** Cookie Attributes & Transport | Secure, HttpOnly, SameSite, Domain, Path, `__Host-`/`__Secure-` prefixes, HTTP↔HTTPS migration, CRLF cookie injection | 10, 11, 12, 13, 14, 15, 38, 40 |
| **SM-D** Binding & Cross-Channel | XSS hijack, IP / User-Agent binding, refresh-token rotation, WebSocket handshake auth, CSRF-token binding | 16, 17, 18, 31, 32, 33 |
| **SM-E** JWT Deep Testing | alg/sig/exp review, `none`, RS256→HS256, weak HMAC secret, exp/nbf, sensitive claims, jku/x5u, kid injection, claim tampering, revocation | 21–30 |

Skip SM-E entirely (mark `NOT_APPLICABLE` with evidence) only if no JWT/JWS/JWE is issued anywhere, including in refresh flows, WebSocket auth, and third-party SSO callbacks.

## Status values

- `PASS` — applicable, executed, and negative evidence saved.
- `FINDING` — reproducible weakness demonstrated with A/B accounts; evidence saved.
- `INFO` — hardening gap with no demonstrated exploit path (e.g., SameSite=Lax default but no state-changing GETs found).
- `NOT_APPLICABLE` — the mechanism is absent (e.g., no JWT, no WebSocket); state the evidence.
- `BLOCKED` — could not execute (needs whitebox/log access, account limits, scope); state why.

A scanner flag (Burp passive "cookie without HttpOnly") is a lead, not a finding: confirm the cookie actually carries session authority before reporting.

## Severity guidance

| Condition | Typical severity |
|---|---|
| JWT `none` / alg confusion / weak secret enabling forged sessions for arbitrary users | Critical |
| Predictable session IDs, session fixation leading to ATO, kid/jku injection with signature bypass | High–Critical |
| Session not invalidated on logout / password change, refresh tokens not rotated, token in URL leaked to third party | Medium–High |
| Missing HttpOnly with demonstrated XSS | High (report under XSS with session-theft impact) |
| Missing Secure/SameSite/prefix, overly broad Domain/Path, long timeouts with no demonstrated exploit | Low–Info |

Adjust to the program's severity table; many programs exclude standalone cookie-flag findings.

## Helper scripts

All scripts live in `scripts/` inside this skill. Active ones enforce the scope gate.

```bash
S=.agents/skills/session-management/scripts

# Collect unauthenticated session tokens for entropy analysis (scope-gated)
$S/collect_tokens.sh --target example.com --url https://app.example.com/login \
  --cookie SESSIONID --count 200 --delay 0.25 --out artifacts/session/tokens_raw.txt

# Offline: entropy, charset, length, duplicates, per-position bias, sequential patterns
python3 -I $S/token_entropy.py artifacts/session/tokens_raw.txt

# Offline: audit every Set-Cookie in a saved response (curl -D / Burp raw response)
python3 -I $S/cookie_audit.py artifacts/session/login_response_headers.txt --session-names SESSIONID,sid

# Offline: decode a JWT and flag risky headers/claims
python3 -I $S/jwt_inspect.py "eyJhbGciOi..."
```

External tools: Burp Suite (Sequencer, Repeater, JWT Editor extension), `jwt_tool` (ticarpi), `hashcat -m 16500`, `curl`, browser devtools. For RS256→HS256 confusion without a published key, PortSwigger's `sig2n` / `rsa_sign2n` derives candidate public keys from two signed tokens.

## Required artifacts

- `artifacts/session/session_map.md`
- `artifacts/session/tokens_raw.txt` and `artifacts/session/entropy_report.txt`
- `artifacts/session/cookie_audit.txt`
- `artifacts/session/jwt_analysis.md` (if applicable)
- `artifacts/session/evidence/` (request/response pairs, named `SM-XX_<short>.txt`)
- `artifacts/session/session_checklist_40.tsv` — columns: `check_id  status  severity  finding_id  evidence_path  notes`
- `artifacts/session_management_report.md` — findings, chains, false positives, blocked checks, and `[ N / 40 ]` coverage

Redact other people's data; test-account tokens in evidence should be invalidated (logout/password change) after the assessment.

## Related skills

- `credentialattacks` — password reset, MFA, brute force (session side effects of reset flows feed SM-08)
- `authbypass` — login/registration logic and session puzzling playbook (`authbypass/references/session_puzzling_and_otp_playbook.md`)
- `access-control` — use forged/elevated sessions from SM-E/SM-29 as input for vertical privilege tests
- `api-security` — CORS with credentials interacts with SM-12 (SameSite)

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, token collection, login/logout cycles, JWT replay, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.

## Extended checklist (added)

- File: `references/cookies_and_jwt_extended.md` (Cookie attributes, session lifecycle, and JWT checks).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
