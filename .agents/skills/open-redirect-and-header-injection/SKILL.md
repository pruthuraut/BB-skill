---
name: open-redirect-and-header-injection
description: Audit authorized applications for open redirects (url, redirect, next, returnTo parameters, parser bypasses, redirect chains), CRLF and response header injection, Host header poisoning, and email header injection in forms. Triggers on "open redirect", "redirect parameter", "returnUrl", "CRLF", "header injection", "%0d%0a", "Host header", "password reset link poisoning", or when route_target.py routes redirect-type parameters.
---

# Open Redirect and Header Injection

Find where the application sends the user (or a header) to a value you control. Use an out-of-band host you own for every redirect test. Never send phishing or link content to real users.

Checklist: `references/redirect_and_crlf.md`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. List redirect-style parameters from `route_target.py --params` (redirect, next, return, continue, goto, url target).
3. For each parameter, send one request per variant from the checklist (OR-001 to OR-005) with your OOB host. Compare the `Location` header and status.
4. Test header reflection with a CRLF marker (CRLF-001 to CRLF-004). Confirm via response headers, not body text.
5. Test Host header behaviour on password reset and absolute URL generation using your own account (HDR-001 to HDR-003).
6. For email forms, use only your own address and a benign marker (EMAIL-HDR-001).
7. Save evidence (request, Location or header diff) to `artifacts/<target>/redirects.json`.

## Classes

- `passive`: header and source reads.
- `bounded`: a few requests to your OOB host or own accounts.
- `authorized-only`: anything beyond that.

## Rules

- Open redirect alone is usually low severity. Report it with a concrete chain (OAuth code theft, token leakage) when one exists, and link to oauth-sso.
- Never deliver redirects to real users or submit forms that notify third parties.

## Additional checklist and tools (added)

- Covers: Open redirect (15 checks) and CRLF injection (10 checks).
- Checklist: `references/open_redirect_crlf_checks.md`.
- Tools: scripts/redirect_crlf_probe.py (bounded, own OOB host and marker).
- Class policy: `passive` and `bounded` run in scope with the stated limits. `authorized-only` needs explicit approval for that check. These probes never send gadget, execution, or flood payloads.
