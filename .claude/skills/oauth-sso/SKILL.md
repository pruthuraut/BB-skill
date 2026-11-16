---
name: oauth-sso
description: Audit authorized OAuth 2.0, OpenID Connect, SAML 2.0 and enterprise SSO (Kerberos/NTLM/LDAP) integrations across 50 checks — redirect_uri bypasses and code/token theft, state/nonce CSRF, PKCE downgrade, scope escalation, code reuse, client_secret exposure, id_token signature/aud/iss/nonce validation, token substitution, unverified-email account linking, Dynamic Client Registration, acr/amr MFA downgrade, DPoP/mTLS binding, SAML XSW / comment injection / signature exclusion / replay / XSLT / XXE, SSO session and logout propagation. Built on PortSwigger OAuth & OpenID labs and research, OWASP WSTG-ATHZ-05 and OAuth2/SAML cheat sheets, and RFC 6749/6819/7636/9700. Use when a target offers "Login with …", SSO, an OAuth provider, or SAML federation.
---

# OAuth 2.0, OpenID Connect & SSO Audit

Determine whether an attacker can obtain, inject, replay, or escalate a federated identity or delegated token — leading to account takeover, account linking abuse, or unauthorized API access. OAuth bugs are implementation bugs: the spec is permissive, so test what the **client app**, the **authorization server/IdP**, and the **resource server** each actually enforce.

Primary methodology sources:

- PortSwigger Web Security Academy — OAuth 2.0 authentication vulnerabilities, OpenID Connect, and the *Hidden OAuth attack vectors* research
- OWASP WSTG v4.2 **WSTG-ATHZ-05** (Testing for OAuth Weaknesses — authorization server and client), OAuth2 Cheat Sheet, SAML Security Cheat Sheet
- RFC 6749 (OAuth 2.0), RFC 6819 (threat model), **RFC 9700** (OAuth 2.0 Security BCP), RFC 7636 (PKCE), RFC 9449 (DPoP), RFC 8705 (mTLS), RFC 7591 (DCR), RFC 8628 (device grant), RFC 8693 (token exchange), RFC 9207 (`iss` in authorization response), OpenID Connect Core 1.0
- SAML: *On Breaking SAML* (XML Signature Wrapping), Duo Labs 2018 comment-injection disclosure, CompassSecurity SAML Raider

## Authorization and safety boundary

- Pass the scope gate before any request. **Both** the client application and the IdP/authorization server must be in scope. Large third-party IdPs (Google, Microsoft, Okta, Auth0, GitHub, Apple, Facebook) are almost never in scope: test how *the target* uses them, not the IdP itself.
- Use **self-owned accounts only**: `A` (attacker) and `B` (victim) on the target, plus `A-idp` / `B-idp` identities at the IdP. "Victim" steps (clicking a CSRF link, opening an attacker page) are performed by *you* in B's browser profile.
- Exfiltration endpoints (stolen codes/tokens, malicious `redirect_uri`, JWKS hosts) must be infrastructure you control (Burp Collaborator, your own VPS). Never send victim material to third-party paste/log services.
- Do not register Dynamic Client Registration clients with deceptive names/logos on production; use a clearly labelled name (`bbtest-<handle>`) and delete/report it afterwards.
- Stop after proof: one code/token captured for **your own** B account and one authenticated read of B's profile.
- Kerberos delegation and NTLM relay (OA-23/24) are **internal-network attacks**. On internet-facing bug bounty scope, perform only passive/config evidence (NTLM info disclosure, Negotiate exposure, EPA/channel-binding status). Relay or delegation abuse requires explicit written authorization for internal/AD testing or an isolated lab — otherwise mark `LAB_REQUIRED`.
- Device-flow and CIBA tests must not send push notifications or codes to users other than your own identities.

## Inputs

1. `artifacts/technology_profile.json` (IdP vendor, SSO libraries)
2. `artifacts/discovered_endpoints.txt` — look for `/oauth`, `/authorize`, `/auth`, `/callback`, `/oauth-callback`, `/sso`, `/saml`, `/acs`, `/login/oauth`, `/.well-known/openid-configuration`, `/connect/`, `/realms/` (Keycloak), `/adfs/`, `/idp/`, `/Shibboleth.sso`
3. **HAR captures** of complete flows, one per account, for every login method: social login, account linking ("Connect Google"), SSO, mobile/native (via proxy), logout
4. Mobile/desktop app packages if native clients exist (for PKCE / client_secret analysis — hand to `jsrecon` for JS bundles)

## Workflow

1. **Discover and fingerprint.** Run `scripts/oidc_discover.sh` against every authorization server host. Record grant/response types, PKCE methods, `registration_endpoint`, `device_authorization_endpoint`, `backchannel_authentication_endpoint`, `end_session_endpoint`, JWKS, SAML metadata. Write `artifacts/oauth/flow_map.md`: client(s), IdP(s), grant type per flow, where tokens end up (cookie, localStorage, URL), and which party validates what.
2. **Audit captured flows offline.** `python3 -I scripts/oauth_har_audit.py flow.har` flags missing/static state, missing nonce, PKCE absent or `plain`, implicit/hybrid response types, tokens in URLs, codes leaking in Referer, `client_secret` sent from the browser, and scope drift.
3. **Run the 50-check ledger** in [references/checklist_50.md](references/checklist_50.md) using the subagent split. Checks OA-01…OA-30 are the core list; OA-31…OA-50 are extended vectors from PortSwigger research, WSTG and public reports.
4. **Chain.** Most high-impact OAuth findings are chains: open redirect + loose `redirect_uri` → code theft → ATO; missing state + account linking → ATO; unverified email at IdP + auto-merge → ATO. Use one finding ID per chain and cross-reference rows.
5. **Prove impact minimally** with A/B accounts and record full request/response evidence.
6. **Report** artifacts and update `[ N / 50 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **OA-A** Redirect URI & Front-Channel Leakage | redirect_uri bypasses, open-redirect chains, Referer leakage, implicit fragments, token/authorize redirect mismatch, response_mode, postMessage, Host-header poisoning | 03, 04, 05, 06, 30, 35, 36, 37 |
| **OA-B** State, CSRF & Account Linking | state presence/validation, login & linking CSRF, IdP-initiated flows, unverified-email merge, implicit-flow identity trust, session poisoning, silent auth / consent | 01, 02, 21, 31, 32, 34, 38 |
| **OA-C** Code, Token & Client Security | scope escalation, code reuse, PKCE (+downgrade), client_secret exposure, token exchange, client credentials, refresh rotation, DPoP/mTLS, DCR, acr/amr, device/CIBA, audience confusion, CORS, errors, revocation, ROPC, JAR, SSRF via metadata URLs | 07, 08, 09, 10, 11, 26, 27, 28, 29, 33, 39, 40, 41, 42, 43, 44, 48, 49, 50 |
| **OA-D** OpenID Connect & SSO Session | id_token signature, nonce, token substitution, SSO session persistence, federated logout | 16, 17, 18, 19, 20 |
| **OA-E** SAML | XML injection, XSW, replay, XSLT, NameID comment injection, signature exclusion / cert trust, audience/recipient, XXE | 12, 13, 14, 15, 22, 45, 46, 47 |
| **OA-F** Enterprise Directory Auth | Kerberos delegation, NTLM relay, LDAP injection in SSO login | 23, 24, 25 |

Mark whole groups `NOT_APPLICABLE` only with evidence (e.g., no SAML endpoints, metadata, or `SAMLRequest`/`SAMLResponse` parameters anywhere in HARs).

## Coverage map (generic OAuth test-case categories → checks)

| Category | Checks |
|---|---|
| Authorization request | 01, 02, 03, 07, 09, 36, 38, 39, 49 |
| User authentication | 21, 25, 31, 32, 39, 50 |
| User consent | 07, 34, 38 |
| Redirect URI validation | 03, 04, 30, 35 |
| Code exchange | 08, 09, 29, 30 |
| Access token validation | 16, 18, 28, 41 |
| Scope | 07, 11, 26, 41 |
| Refresh token | 27 |
| Error handling | 04, 43 |
| CORS | 42 |
| Logout & revocation | 19, 20, 44 |
| Security (transport, secrets, federation) | 05, 06, 10, 12–15, 22–24, 33, 37, 40, 45–48 |

## Status values

- `PASS` — applicable, executed, negative evidence saved.
- `FINDING` — reproduced with A/B accounts; full request/response evidence saved.
- `INFO` — deviation from RFC 9700/OIDC best practice without a demonstrated exploit (e.g., implicit flow still enabled but no leak found; PKCE `plain` allowed).
- `NOT_APPLICABLE` — mechanism absent; evidence cited.
- `LAB_REQUIRED` — needs internal-network/AD authorization or a lab (OA-23/24 relay/delegation abuse).
- `BLOCKED` — could not execute (scope, missing second IdP account, mobile client unavailable).

## Severity guidance

| Condition | Typical severity |
|---|---|
| Auth code / access token theft via redirect_uri bypass → ATO | Critical |
| Missing/unvalidated state on account-linking → attacker identity linked to victim | High–Critical |
| Unverified email auto-merge, implicit-flow identity trust, id_token signature/aud/iss not validated, SAML XSW / signature exclusion / comment injection | Critical |
| PKCE downgrade, code reuse, scope escalation, refresh-token reuse | Medium–High (depends on what an attacker can reach) |
| client_secret in public client | Medium (High if it enables token minting for other users / confidential-only grants) |
| Missing nonce, IdP-initiated SSO enabled, federated logout gaps, PKCE `plain`, implicit enabled | Low–Medium / Info without a chain |
| NTLM info disclosure (internal hostnames/domain) | Low–Info |

## Helper scripts

```bash
S=.agents/skills/oauth-sso/scripts
SM=.agents/skills/session-management/scripts

# Discover OIDC/OAuth/SAML metadata (scope-gated, read-only GETs)
$S/oidc_discover.sh --target example.com --host auth.example.com --out artifacts/oauth/discovery

# Offline: audit a HAR of a complete login / linking flow
python3 -I $S/oauth_har_audit.py artifacts/oauth/login_A.har | tee artifacts/oauth/har_audit.txt

# Offline: generate redirect_uri bypass candidates (and full authorize URLs)
python3 -I $S/redirect_uri_variants.py --registered https://app.example.com/oauth/callback \
  --attacker YOUR-COLLAB.oastify.com --authorize https://auth.example.com/authorize \
  --param client_id=abc --param response_type=code --param scope=openid > artifacts/oauth/redirect_candidates.tsv

# Pre-auth redirect_uri validation differential (scope-gated, rate-limited, no cookies sent)
$S/probe_authorize.sh --target example.com --urls artifacts/oauth/redirect_candidates.tsv --delay 1

# Offline: decode a SAMLResponse / SAMLRequest and flag weaknesses
python3 -I $S/saml_inspect.py artifacts/oauth/saml_response.b64

# Offline: decode id_tokens / JWT access tokens (shared with session-management)
python3 -I $SM/jwt_inspect.py "$ID_TOKEN"
```

External tools: Burp Suite (Repeater, Collaborator, **SAML Raider**, **JWT Editor**, *EsPReSSO* for SSO protocols), `jwt_tool`, browser devtools, `xmlsec1` (verify SAML signatures locally), `nmap --script http-ntlm-info` (OA-24 passive), `ldapsearch` only in authorized internal tests.

## Required artifacts

- `artifacts/oauth/flow_map.md` and `artifacts/oauth/discovery/`
- `artifacts/oauth/har_audit.txt`, `artifacts/oauth/redirect_candidates.tsv`, `artifacts/oauth/authorize_probe.tsv`
- `artifacts/oauth/saml_analysis.md` (if SAML)
- `artifacts/oauth/evidence/OA-XX_<short>.txt`
- `artifacts/oauth/oauth_checklist_50.tsv` — columns `check_id  status  severity  finding_id  evidence_path  notes`
- `artifacts/oauth_sso_report.md` — findings, chains, false positives, LAB_REQUIRED/BLOCKED items, `[ N / 50 ]`

Revoke OAuth grants and delete DCR test clients after the assessment, and note it in the report.

## Related skills

- `session-management` — JWT attack primitives (SM-21…30) apply to id_tokens and JWT access tokens; post-login session rotation (SM-03/04)
- `credentialattacks` / `authbypass` — password reset and MFA flows that coexist with SSO; OA-50 (ROPC) bypasses their controls
- `ssrf-audit` — OA-48 (jwks_uri / request_uri / logo_uri / SAML metadata fetches)
- `linkparamdiscovery` / `contentdiscovery` — open redirects and path-traversal gadgets for OA-03/04
- `access-control` — impact mapping for escalated scopes and impersonated identities

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, authorization flows, token exchanges, client registration, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- Run the gate for **each** host involved (client app, authorization server, API). A third-party IdP host that fails the gate may only be used as a normal user of its login page.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.

## Extended checklist (added)

- File: `references/oauth_extended.md` (OAuth, OIDC, SAML, and identity provider checks).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
