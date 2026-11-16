---
name: csrf-and-headers-audit
description: Audit authorized applications for cross-site request forgery (missing or unvalidated tokens, SameSite gaps, method switching, JSON content-type CSRF), clickjacking (frame-ancestors and X-Frame-Options), security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP), and cookie prefixes. Triggers on "CSRF", "missing token", "SameSite", "clickjacking", "X-Frame-Options", "CSP", "HSTS", "security headers", "securityheaders", "cookie flags", or when a fingerprint shows a page with state-changing forms.
---

# CSRF and Security Headers

Test state-changing actions on your own test account with and without the anti-CSRF token, and audit the response headers that protect browsers. Never test CSRF against real users or with a victim's session.

Checklist: `references/csrf_clickjacking_headers.md` (about 30 rows).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Headers and cookies (passive): run HDR-SEC-001 to HDR-SEC-007, CSP-001 to CSP-006, COOKIE-PFX-001 and COOKIE-PFX-002 on each distinct page type. Record the header set per page.
3. CSRF (bounded): on your own account, change one harmless setting (for example a display name) three ways: with token, with token removed, with token value replaced. Compare results. Repeat with method switch (CSRF-003) and content-type switch (CSRF-006).
4. Clickjacking (bounded): frame the sensitive page on a local test page you host, using only your own account, and confirm framing is blocked or allowed (CLICK-001, CLICK-002).
5. CSP analysis: parse the policy and list bypass candidates (unsafe-inline, whitelisted CDN with JSONP, base-uri gaps). Confirm candidates with the JSONP check on the allowed host only.
6. Save results to `artifacts/<target>/csrf_headers.json`.

## Classes

- `passive`: header, cookie, and source reads.
- `bounded`: one own-account state change with and without token.
- `authorized-only`: anything that changes another account.

## Rules

- A missing security header alone is informational or low. Report it with the page where the risk applies.
- Use only your own accounts for CSRF. The target object must be one you created.
