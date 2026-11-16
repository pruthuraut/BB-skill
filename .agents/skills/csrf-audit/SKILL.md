---
name: csrf-audit
description: Deep cross-site request forgery (CSRF / XSRF, CWE-352) audit for authorized applications — 20 core checks (all state-changing POST/PUT/DELETE, token presence and validation, token removal, cross-session reuse, predictability and entropy, session binding, JSON with CORS, XML, multipart, AJAX X-Requested-With, WebSocket handshake, SameSite, login CSRF, password change, email change, X-Forwarded-* bypass, _method override, Origin/Referer validation, GraphQL mutations, API CORS) plus about 45 bypass rows (empty/undefined/array/same-length/static-part tokens, POST to GET, double-submit cookie, referer regex and domain-confusion, no-referrer, Origin null via data: iframe, text/plain JSON padding, content-type switching, user-agent gated checks, clickjacking, XSS and subdomain-takeover chains, OAuth state), PoC templates, a token-variant probe, and a token entropy analyzer. Triggers on "CSRF", "XSRF", "cross-site request forgery", "csrf token", "anti-csrf", "SameSite", "login CSRF", "JSON CSRF", "method override", "_method", "Origin header check", "Referer check", "double submit cookie", "CSRF PoC", "XSRFProbe", or when route_target.py routes csrf, xsrf, _token, authenticity_token, or _method parameters.
---

# CSRF Audit (20 core checks + bypass matrix)

CSRF makes a logged-in victim's browser send a state-changing request the victim did not intend. It needs three conditions: a relevant action, cookie-based (ambient) authentication, and no request parameter the attacker cannot predict. Every check here tries to break the third condition, or to show the browser will send the cookie when the app assumes it won't.

- Checklist: `references/csrf_checklist.md` (XSRF-001 to XSRF-020 core rows, XSRF-B-* bypass rows, where to hunt).
- PoC templates: `references/csrf_poc_templates.md` (form GET/POST, auto-submit, multipart, text/plain JSON, fetch/XHR, method override, no-referrer, null Origin, referer domain confusion, login CSRF, WebSocket, GraphQL, clickjacking frame).
- Reports, writeups, tools, labs: `references/csrf_reports_and_writeups.md`.
- Tracker: `references/csrf_tracker.md` (copy to `artifacts/<target>/`, update 0/20 to 20/20).
- Probe: `scripts/csrf_probe.py` (replays one own-account request with token, method, content-type, Origin, and Referer variants; scope-gated, max 20 requests, 1 per second).
- Token analyzer: `scripts/csrf_token_analyze.py` (offline: length, charset, entropy, duplicates, static prefix/suffix, timestamp and hash hints).
- Related: `csrf-audit` (CSRF-001 to CSRF-009, clickjacking, headers), `session-management` (cookie attributes), `oauth-sso` (state parameter), `cors-audit` and `api-security` (CORS), `client-side-js-security` (WebSocket), `xss` (token theft chains), `subdomain-takeover`.

## Subagents

| Subagent | Checks | Focus |
|---|---|---|
| 01 Surface and tokens | XSRF-001 to 006 | Inventory state-changing requests, token presence, removal, reuse, entropy, session binding |
| 02 Content types and transports | XSRF-007 to 011, 019, 020 | JSON/CORS, XML, multipart, AJAX header, WebSocket, GraphQL, API CORS |
| 03 Browser and header defenses | XSRF-012, 016, 017, 018 | SameSite, X-Forwarded-*, method override, Origin/Referer validation |
| 04 High-impact flows | XSRF-013, 014, 015 | Login CSRF, password change, email change (account takeover paths) |
| 05 Bypass matrix and chains | XSRF-B-* | Token tricks, referer and origin tricks, clickjacking, XSS, subdomain + CORS, OAuth state |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Set up two own accounts in two separate browser profiles: **attacker** (A) and **victim** (V). The "victim" is always your own account. Host PoC pages on a domain you control (or `localhost`), never on the target.
3. Inventory: proxy a full walk-through and list every state-changing request (method, path, content type, auth style, token location). Prioritize: change password, change email, change phone, enable/disable 2FA, API key generation, add/delete users and roles, linked accounts and OAuth connect, payment methods, subscription, account deletion, logout, profile, comments, likes, add-to-cart, transfers, webhook and integration setup.
4. Classify authentication. Only cookie or HTTP-auth sessions are CSRF-able. A bearer token in `Authorization` set by JavaScript is not, unless the app also accepts the cookie (check by dropping the header).
5. Read the cookies: SameSite, Secure, `__Host-` prefix, and whether the browser default (Lax in Chrome, with the 2-minute top-level POST grace window for new cookies) applies.
6. Token tests: run `scripts/csrf_probe.py` on a harmless own-account request (for example display name). It sends baseline, removed, empty, `undefined`, array, same-length random, last-character change, other-session token, POST to GET, method override, content-type switches, no Referer, foreign Referer, `Origin: null`, foreign Origin, and no `X-Requested-With`. Every "accepted" variant is a lead; confirm by re-reading the state.
7. Token quality: collect 20 or more tokens (log out and in, new sessions, both accounts) and run `scripts/csrf_token_analyze.py tokens.txt`. Look for static parts, duplicates, timestamps, or short length.
8. Work through the bypass matrix (`XSRF-B-*`) for each defense you found.
9. Build the PoC from `references/csrf_poc_templates.md`, open it in the victim profile, and confirm the state changed on the victim account. A finding is the state change, not just a 200 response.
10. Chain for impact: email change plus password reset is account takeover; login CSRF plus stored self-XSS; CSRF plus clickjacking for flows needing a click.
11. Save findings to `artifacts/<target>/csrf_findings.json`, PoCs to `artifacts/<target>/csrf_pocs/`, and the tracker to `artifacts/<target>/csrf_tracker.md`.

## Classes

- `passive`: reading forms, JS, cookies, CORS headers, and tokens; offline token analysis.
- `bounded`: own-account replays (the probe), and PoCs opened in your own victim profile against your own victim account.
- `authorized-only`: anything that would run against a real user, mass-delivered PoCs, logout or delete actions on shared resources, and chains that need another vulnerability exploited (XSS, subdomain takeover). Explicit approval for that specific check.

## Rules

- Never send a PoC link to a real user or post it publicly. Victim = your own second account.
- Use harmless state changes for probing (display name, bio, a test comment). Test password and email change only on your own victim account, and restore them after.
- Do not mark "token missing" as a finding without a working PoC: SameSite, CORS preflight, or bearer auth may block it in practice. State which browser and version the PoC worked in.
- A CSRF on logout or a harmless toggle is usually low; report impact honestly.

## Mitigation guidance for reports

- Synchronizer token per session (or per request), at least 128 bits from a CSPRNG, tied to the session, validated on every state-changing request whether or not the parameter is present, compared in constant time.
- If stateless: signed double-submit cookie (HMAC bound to the session), with a `__Host-` cookie.
- Session cookies with `SameSite=Lax` or `Strict`, `Secure`, `HttpOnly`, and the `__Host-` prefix. Never change state on GET.
- Verify `Origin` (fall back to `Referer`) against an exact allowlist; reject `null` and missing values on state-changing requests.
- Require `Content-Type: application/json` strictly on JSON APIs and keep CORS to an exact-origin allowlist without credentials for untrusted origins.
- Disable `_method` and `X-HTTP-Method-Override` unless needed, and re-check tokens after the override.
- Re-authentication (current password, MFA) for password, email, 2FA, and API-key changes.
- `frame-ancestors 'none'` or `X-Frame-Options: DENY` on sensitive pages.

## Sources

OWASP CSRF Prevention Cheat Sheet and WSTG-SESS-05, CWE-352, PortSwigger Web Security Academy CSRF and SameSite labs, Detectify login/logout CSRF research, the user-supplied methodology notes, writeups, and HackerOne reports listed in `references/csrf_reports_and_writeups.md`.

## Merged skills (content preserved)

These skills covered the same topic and were merged here. Nothing was removed: each original SKILL.md, reference file, and Cursor rule is kept under `references/merged/<name>/`, and each script is in `scripts/` (a prefix marks name collisions).

- `csrf-and-headers-audit`: full content in `references/merged/csrf-and-headers-audit/` (SKILL.md, references, rule); scripts in `scripts/`
- `clickjacking-audit`: full content in `references/merged/clickjacking-audit/` (SKILL.md, references, rule); scripts in `scripts/`
