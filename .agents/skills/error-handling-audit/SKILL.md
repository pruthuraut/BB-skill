---
name: error-handling-audit
description: Audit authorized applications for improper error handling across 10 checks — verbose errors with stack traces and file paths, database errors disclosing queries, framework/version disclosure on error pages, internal IP and path disclosure, error-based disclosure via crafted input (type confusion, quotes, nulls, arrays, oversize, encoding), differential errors revealing valid vs invalid input (user/object enumeration, oracle behavior), missing or default custom error pages, debug-mode error pages in production, API status-code hygiene (500 vs 400/404/422), and GraphQL error disclosure — with a scope-gated crafted-input probe that fingerprints stack traces, DB errors, framework versions, default error pages, and status-code misuse, and a differential mode for enumeration. Triggers on "error handling", "verbose error", "stack trace", "exception", "debug page", "500 error", "error-based disclosure", "custom error page", "user enumeration via error", "database error", "GraphQL errors", or when responses show tracebacks or framework banners.
---

# Error Handling Audit (10 checks)

Errors should tell the user what went wrong in general terms, return the correct status code, and log details server-side. Every detail that leaks (stack frames, SQL, paths, versions, internal hosts) helps an attacker, and every difference between "valid" and "invalid" errors can become an oracle.

- Checklist: `references/error_handling_checklist.md` (EH-001 to EH-010, crafted input catalog, default error page signatures, status-code expectations).
- Tracker: `references/error_handling_tracker.md`.
- `scripts/error_probe.py`: scope-gated crafted-input probe. Per parameter it sends type, syntax, length, encoding, and structure variants, then fingerprints stack traces, DB errors with query text, framework versions, internal IPs and paths, default error pages, and 5xx on client errors. `--enum` mode compares responses for a known-valid and a known-invalid value (EH-006). Signatures are shared with `server-config-audit/../server-config-audit/scripts/misconfig_probe.py`.
- Related: `server-config-audit` (SMC-005, SMC-006, SMC-015, SMC-017), `data-exposure-audit` (DE-005), `sqli` (error-based SQLi), `graphql-audit` (GQL-009, GQL-010), `authbypass` and `credentialattacks` (enumeration), `api-security`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Pick endpoints: pages with parameters, API endpoints (JSON bodies), file and ID parameters, login/reset/signup (for EH-006), and GraphQL.
3. Run the probe per endpoint:

   ```bash
   python3 .agents/skills/error-handling-audit/scripts/error_probe.py --target example.com \
     --url 'https://api.example.com/v1/items?id=5&sort=name' --cookie 'session=OWN' \
     --json-body '{"name":"x","qty":1}' --method POST --out artifacts/example.com/errors.json
   ```

4. Enumeration differential (EH-006), with your own account as the valid value:

   ```bash
   python3 .agents/skills/error-handling-audit/scripts/error_probe.py --target example.com \
     --url https://www.example.com/login --method POST --form 'email=FUZZ&password=WrongPass1!' \
     --enum --valid you@example.test --invalid nobody-$(date +%s)@example.test
   ```

   Differences in status, length, message, or timing reveal valid inputs. Keep repetitions low (default 3 each).
5. Custom error pages (EH-007): the probe requests a random path and malformed requests and matches default server/framework pages.
6. GraphQL (EH-010): `--graphql https://api.example.com/graphql` sends malformed queries and inspects `errors[].extensions` for exceptions and stack traces; deeper checks in graphql-audit.
7. Confirm leads manually and redact paths, IPs, and hostnames as needed for the report.
8. Save findings to `artifacts/<target>/error_handling.json` and the tracker to `artifacts/<target>/error_handling_tracker.md`.

## Classes

- `passive`: reading errors already in proxy history.
- `bounded`: a fixed set of malformed inputs per parameter (about 15), low-rate enumeration differentials with your own account as the valid value.
- `authorized-only`: large-scale enumeration, inputs designed to crash or exhaust the service, and error-based data extraction (handled by sqli under its own rules).

## Rules

- Do not send payloads intended to crash services (huge bodies, deep recursion, zip bombs).
- Enumeration: prove the difference with a handful of requests; do not enumerate real users.
- Stop if errors cause instability (5xx spikes, timeouts).

## Mitigation guidance for reports

- Global exception handler returning generic messages with a correlation ID; log details server-side only.
- Production configs: debug off, `customErrors On`, `display_errors=Off`, `DEBUG=False`, `server.error.include-stacktrace=never`, Express `NODE_ENV=production`, GraphQL `debug: false` / masked errors.
- Correct status codes: 400/422 for invalid input, 401/403 for auth, 404 for missing, 500 only for server faults.
- Identical responses (message, status, timing) for valid and invalid usernames, emails, IDs, and tokens.
- Custom error pages for 400/401/403/404/405/500/502/503 at the app and the edge (web server, CDN, load balancer).
- Remove version banners from error pages and headers.

## Sources

OWASP WSTG-ERRH-01 and ERRH-02, OWASP Error Handling and Logging cheat sheets, CWE-209, CWE-210, CWE-211, CWE-204 (observable response discrepancy), CWE-756 (missing custom error page), and framework hardening guides.
