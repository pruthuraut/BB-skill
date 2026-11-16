---
name: data-exposure-audit
description: Audit authorized applications for sensitive data exposure across 20 checks — secrets and internal data in page source and HTML comments, JavaScript and source maps, API keys in client code, meta tags and data attributes, error messages and stack traces, debug and status endpoints, robots.txt and sitemap.xml, .env and config files, backups and archives, version control directories (.git/.svn/.hg), server log files, HTTP response headers, cookies without Secure/HttpOnly, localStorage/sessionStorage, IndexedDB, email/PII in API responses, excessive API data, sensitive data in URL parameters, autocomplete on sensitive fields, and referrer leakage to external sites. Includes a scope-gated page and file exposure scanner (secrets, comments, meta, hidden fields, source maps, robots/sitemap, sensitive files by signature, headers, cookies, autocomplete, referrer policy, external links), an offline API response PII/excess-data analyzer, and a browser storage dump snippet. Triggers on "data exposure", "information disclosure", "sensitive data", "PII", "secrets in JS", "API key exposed", "source map", "HTML comments", ".env", ".git exposed", "backup file", "log file", "excessive data exposure", "localStorage token", "autocomplete", "Referer leak", or when recon artifacts need a data-leak pass.
---

# Data Exposure Audit (20 checks)

Find sensitive data the application hands to anyone who looks: in pages, scripts, files, headers, cookies, browser storage, API responses, URLs, and outgoing Referers. Report only data that is actually sensitive (credentials, tokens, keys, PII, internal topology), with redacted evidence.

- Checklist: `references/data_exposure_checklist.md` (DE-001 to DE-020, secret patterns, sensitive file list, PII field names, severity guide).
- Browser storage snippet: `references/browser_storage_dump.md` (DevTools console code for localStorage, sessionStorage, IndexedDB, cookies, and Cache Storage on your own session).
- Tracker: `references/data_exposure_tracker.md`.
- `scripts/exposure_scan.py`: scope-gated scanner for pages and files (secret patterns, HTML comments, meta and hidden inputs, data attributes, linked JS and `.map` files, robots/sitemap paths, sensitive file signatures, response headers, cookie flags, autocomplete, Referrer-Policy and external links on sensitive pages). File contents are matched in memory; only redacted excerpts are stored.
- `scripts/api_pii_scan.py`: offline analyzer for saved API responses (JSON/HAR): PII and secret fields, other users' identifiers, field counts vs what the UI shows, sensitive data in URLs.
- Related: `jsrecon` (deep JS mining), `contentdiscovery` (`exposure_and_errors.md`), `saas-third-party-exposure` (public vs secret keys), `error-handling-audit`, `server-config-audit` (SMC-004 to SMC-006), `session-management` (cookies), `client-side-js-security` (STOR rows), `api-security` (API-X-017), `cloud-supplychain` (repos), `crypto-audit` (keys).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Pages and files:

   ```bash
   python3 .agents/skills/data-exposure-audit/scripts/exposure_scan.py --target example.com \
     --urls pages.txt --cookie 'session=OWN' --files --out artifacts/example.com/data_exposure.json
   ```

   Include logged-in pages from your own account and the main JS bundles. `--files` checks the sensitive file list (DE-007 to DE-011) by content signature on each host.
3. JS depth: run jsrecon on bundles and recovered source maps; classify keys with saas-third-party-exposure (public identifiers vs secrets).
4. API responses: export your proxy history as HAR (or save JSON responses) for your own account and run `scripts/api_pii_scan.py history.har --own-email you@example.test --own-id 1042`. Look for other users' PII, password hashes, tokens, internal flags, and fields the UI never shows.
5. Browser storage: on your own logged-in session, run the snippet from `references/browser_storage_dump.md`; check for tokens, PII, and data that survives logout.
6. URLs and Referer: grep proxy history for tokens, emails, and IDs in query strings; check pages that hold such URLs for external resources and `Referrer-Policy`.
7. Autocomplete: the scanner flags password, card, CVV, SSN, and OTP inputs without `autocomplete="off"`/`new-password`/`one-time-code` (usually informational).
8. Verify every hit by hand, redact secrets (first and last 4 characters), and rate by what the data enables.
9. Save findings to `artifacts/<target>/data_exposure.json` and the tracker to `artifacts/<target>/data_exposure_tracker.md`.

## Classes

- `passive`: reading pages, JS, headers, cookies, and your own API responses and storage.
- `bounded`: GET requests for known sensitive file paths and debug endpoints (status and signature only), and fetching linked JS and source maps.
- `authorized-only`: downloading full backups, databases, or logs; cloning exposed `.git` repositories beyond proving exposure; using any found credential; reading other users' data beyond the minimum proof.

## Rules

- Never use exposed credentials or keys. Report location, type, and a redacted value; recommend rotation.
- Stop at proof for files: status, size, content type, and a redacted first line. Do not download dumps or archives.
- For other users' PII, record the field names and one redacted example; do not collect more.

## Mitigation guidance for reports

- Remove comments, debug output, and secrets from client code at build time; do not ship source maps publicly; keep secrets server-side.
- Return only fields the client needs (response DTOs, field-level authorization); never return hashes, tokens, or internal flags.
- Block dotfiles, backups, logs, and VCS folders at the web server; keep them outside the web root.
- Generic error pages; disable debug endpoints in production.
- `Secure`, `HttpOnly`, `SameSite` on cookies; avoid tokens in web storage; clear storage on logout.
- No sensitive data in URLs; `Referrer-Policy: strict-origin-when-cross-origin` or stricter; minimize third-party resources on sensitive pages.
- Remove server, framework, and internal headers.

## Sources

OWASP WSTG-INFO-05 (webpage content), WSTG-CONF-04/05 (backup and unreferenced files, admin interfaces), WSTG-ERRH-01, WSTG-CLNT-12 (browser storage), OWASP API3:2023 (excessive data exposure / BOPLA), CWE-200, CWE-209, CWE-312, CWE-359, CWE-532, CWE-538, CWE-598.
