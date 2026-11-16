---
name: clickjacking-audit
description: Audit authorized applications for clickjacking (UI redressing, CWE-1021) across 10 core checks — iframe embedding of target pages, X-Frame-Options presence and value, CSP frame-ancestors, same-origin framing bypass (SAMEORIGIN abused via framing gadgets, user content, or nested frames), drag-and-drop data exfiltration, cursorjacking with a hidden or fake cursor, multi-step clickjacking, sensitive action buttons, authentication flow pages, and transparent iframes over decoy content — plus about 25 variant and bypass rows (ALLOW-FROM, conflicting or duplicate headers, meta-tag policies ignored, report-only CSP, inconsistent coverage across routes and error pages, frame-busting script bypass with sandbox, double-clickjacking with popups, prefilled forms via URL parameters, likejacking, keystroke hijacking, third-party cookie and SameSite limits). Includes PoC templates and a scope-gated checker that parses framing defenses and writes PoC pages. Triggers on "clickjacking", "UI redressing", "X-Frame-Options", "frame-ancestors", "iframe embedding", "frameable", "framebusting", "cursorjacking", "likejacking", "double clickjacking", or when a sensitive action needs only one or a few clicks.
---

# Clickjacking Audit (10 core checks + variants)

Clickjacking loads the target page in an invisible or disguised frame and tricks the victim into clicking, dragging, or typing on it. It needs three things: the page can be framed cross-site, the victim's session is sent inside the frame, and a sensitive action completes with clicks (no unpredictable typing). Missing headers on a page with no sensitive action is informational.

- Checklist: `references/clickjacking_checklist.md` (CJ-001 to CJ-010 core, CJ-V-* variants and bypasses, severity guide).
- PoC templates: `references/clickjacking_poc_templates.md` (basic overlay with opacity slider, sandbox frame-buster bypass, multi-step, cursorjacking, drag-and-drop, prefilled form, double-clickjacking, nested same-origin framing).
- Tracker: `references/clickjacking_tracker.md` (copy to `artifacts/<target>/`, update 0/10 to 10/10).
- Checker: `scripts/clickjack_check.py` (scope-gated GET per URL; parses X-Frame-Options, CSP and CSP-Report-Only frame-ancestors, meta tags, duplicates and conflicts, frame-busting script; writes a PoC HTML for each frameable URL).
- Related: `csrf-and-headers-audit` (CLICK-001, CLICK-002, headers), `csrf-audit` (XSRF-B-035, CSRF + clickjacking), `session-management` (SameSite), `xss` (same-origin gadgets), `oauth-sso` (consent pages).

## Subagents

| Subagent | Checks | Focus |
|---|---|---|
| 01 Defenses | CJ-002, 003, 004 | XFO, frame-ancestors, consistency across routes, same-origin gadgets |
| 02 Exploitability | CJ-001, 008, 009, 010 | Frame sensitive pages and auth flows, confirm the session loads in the frame, build overlays |
| 03 Advanced variants | CJ-005, 006, 007, CJ-V-* | Drag-and-drop, cursorjacking, multi-step, double-clickjacking, prefilled forms |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. List sensitive click-only actions: delete account, disable 2FA, add or remove users, change roles, connect or authorize apps (OAuth consent), approve payments, follow or like, share or publish, generate API keys, change privacy settings, confirm email change, admin toggles. Also list auth pages: login, SSO, OAuth authorize, password reset, MFA enroll.
3. Run `scripts/clickjack_check.py --urls pages.txt --cookie 'session=OWN' --poc-dir artifacts/<target>/clickjacking_pocs`. It reports, per URL, whether framing is blocked and why, and writes a PoC for frameable pages.
4. Check consistency: the same defense must appear on every route, method, error page, and alternative host (mobile, legacy, API-rendered HTML). A single unprotected sensitive page is enough.
5. Open each PoC (served from `localhost` or your own domain) in your own victim browser profile. Confirm the page renders inside the frame **logged in**. Modern browsers block third-party cookies or send `SameSite=Lax` cookies only to top-level navigations, so a logged-out frame is usually not exploitable. Record browser and version.
6. Build the overlay: position the decoy so the click lands on the sensitive button (opacity slider in the template), and prove the action completes on your own victim account.
7. Try variants for pages that seem protected: frame-buster script bypass with `sandbox`, same-origin gadgets for `SAMEORIGIN`, double-clickjacking (popup + window swap), prefilled forms via URL parameters, multi-step flows.
8. Save findings to `artifacts/<target>/clickjacking.json`, PoCs to `artifacts/<target>/clickjacking_pocs/`, and the tracker to `artifacts/<target>/clickjacking_tracker.md`.

## Classes

- `passive`: reading headers, meta tags, and frame-busting scripts.
- `bounded`: GET requests with your own session; PoCs opened in your own victim profile to perform actions on your own account.
- `authorized-only`: anything shown to real users, likejacking on public social features with real accounts, and chains that need XSS or user-content hosting on the target origin.

## Rules

- Never deliver a clickjacking page to real users or publish it.
- Report missing headers on non-sensitive pages as informational. Rate by the action you can make the victim perform, and how many clicks it needs.
- Restore any state changed on your victim account.

## Mitigation guidance for reports

- `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` / exact origins) as the primary control, sent as an HTTP header (not meta).
- `X-Frame-Options: DENY` or `SAMEORIGIN` for older browsers; never `ALLOW-FROM` (unsupported in modern browsers).
- Apply to every HTML response, including errors and alternate hosts.
- `SameSite=Lax` or `Strict` session cookies so framed pages load logged out.
- Require confirmation with re-authentication, typing, or a CAPTCHA for critical actions; disable buttons until the page is visible and focused (defense against double-clickjacking).
- Do not rely on JavaScript frame-busting.

## Sources

OWASP Clickjacking Defense Cheat Sheet and WSTG-CLNT-09, CWE-1021, PortSwigger Web Security Academy clickjacking labs, MDN X-Frame-Options and CSP frame-ancestors, Paulos Yibelo's double-clickjacking research (2024), and public HackerOne clickjacking reports.
