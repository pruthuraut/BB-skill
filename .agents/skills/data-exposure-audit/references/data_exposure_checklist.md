# Data Exposure Checklist

Class key: `passive` = pages, JS, headers, cookies, own API responses and storage. `bounded` = GETs for known sensitive paths (status and signature only), fetching JS and maps. `authorized-only` = downloading dumps/backups/logs, cloning `.git`, using credentials, collecting other users' data.

## Core checks (20)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| DE-001 | Page source | Sensitive data in page source and HTML comments (credentials, internal hosts, TODOs with secrets, disabled features, internal IPs, developer names and emails) | passive | exposure_scan.py `comments`, `secrets`, `internal` |
| DE-002 | JavaScript | Sensitive data in JS files and source maps (`//# sourceMappingURL`, `.map` reachable with `sourcesContent`) | bounded | exposure_scan.py fetches linked JS and `.map`; jsrecon for depth |
| DE-003 | Client keys | API keys and secrets in client-side code (AWS, Stripe secret, private tokens, JWT secrets, OAuth client secrets) | passive | exposure_scan.py secret patterns; classify public vs secret (saas-third-party-exposure) |
| DE-004 | Meta / attributes | Sensitive data in meta tags, hidden inputs, and data attributes (`csrf` is fine; user IDs of others, internal URLs, keys, roles, debug flags are not) | passive | exposure_scan.py `meta`, `hidden_inputs`, `data_attrs` |
| DE-005 | Errors | Sensitive data in error messages and stack traces | bounded | See error-handling-audit EH-001 to EH-004 |
| DE-006 | Debug endpoints | Sensitive data in debug and status endpoints (`/actuator/env`, `/server-status`, `/debug/vars`, `/_profiler`, `/health` with details, `/metrics`, `/info`) | bounded | exposure_scan.py `--files` debug group; server-config-audit SMC-006 |
| DE-007 | robots / sitemap | Sensitive paths or data in robots.txt and sitemap.xml (admin, backup, staging, internal, tokens in URLs) | bounded | exposure_scan.py `--files` robots/sitemap parsing |
| DE-008 | Config | `.env` files and configuration (`.env`, `.env.local`, `.env.production`, `config.json`, `appsettings.json`, `web.config`, `wp-config.php.bak`, `settings.py`, `application.yml`, `.npmrc`, `.aws/credentials`, `docker-compose.yml`) | bounded | exposure_scan.py signature match (`DB_PASSWORD=`, `APP_KEY=`, `"ConnectionStrings"`) |
| DE-009 | Backups | Backup files and archives (`.bak`, `.old`, `.orig`, `~`, `.swp`, `backup.zip`, `site.tar.gz`, `db.sql`, `dump.sql`, `<host>.zip`) | bounded | exposure_scan.py status + magic bytes; never download fully |
| DE-010 | VCS | Version control directories (`.git/HEAD`, `.git/config`, `.svn/entries`, `.svn/wc.db`, `.hg/`, `.bzr/`, `.DS_Store`) | bounded | exposure_scan.py signature (`ref: refs/heads/`, `[core]`); cloning is authorized-only |
| DE-011 | Logs | Log files on the server (`/logs/`, `error.log`, `access.log`, `debug.log`, `laravel.log`, `storage/logs/laravel.log`, `npm-debug.log`, `/var/log` via traversal) | bounded | exposure_scan.py signature (timestamps + levels); record size only |
| DE-012 | Headers | Sensitive data in response headers (internal IPs, hostnames, backend server names, user IDs, tokens, debug headers like `X-Debug-Token`, `X-Backend-Server`, `X-Upstream`) | passive | exposure_scan.py `headers` |
| DE-013 | Cookies | Cookies carrying sensitive data or missing `Secure`/`HttpOnly`/`SameSite`; PII or roles in cookie values (base64/JSON) | passive | exposure_scan.py `cookies` with decoded values |
| DE-014 | Web storage | Tokens, PII, or secrets in localStorage/sessionStorage; data not cleared on logout | passive | `browser_storage_dump.md` snippet on own session |
| DE-015 | IndexedDB | Sensitive records in IndexedDB (offline caches, message stores) persisting after logout | passive | Snippet; check after logout |
| DE-016 | API PII | Email and PII exposure in API responses (other users' emails, phones, addresses, DOB in lists, search, comments, followers) | passive | api_pii_scan.py on own HAR |
| DE-017 | Excess data | Excessive data in API responses (full user objects, password hashes, tokens, internal flags, `isAdmin`, deleted fields) | passive | api_pii_scan.py field comparison; API-X-017 |
| DE-018 | URLs | Sensitive data in URL parameters (tokens, session IDs, passwords, emails, reset codes, API keys in GET) | passive | api_pii_scan.py URL scan; exposure_scan.py link scan |
| DE-019 | Autocomplete | Autocomplete enabled on sensitive fields (password reuse prompts, card number, CVV, SSN, OTP) | passive | exposure_scan.py `autocomplete` |
| DE-020 | Referer | Sensitive URLs leaked via Referer to external sites (third-party scripts, images, links on pages with tokens in URL; weak Referrer-Policy) | passive | exposure_scan.py `referrer` (policy + external resources on pages with sensitive params) |

## Secret patterns (used by exposure_scan.py and api_pii_scan.py)

| Type | Pattern hint |
|---|---|
| AWS access key | `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}` |
| AWS secret | `aws_secret_access_key` + 40 chars |
| Google API key | `AIza[0-9A-Za-z_-]{35}` (often public; check restrictions) |
| Stripe secret | `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_` |
| GitHub token | `ghp_`, `gho_`, `ghu_`, `ghs_`, `github_pat_` |
| Slack | `xox[baprs]-`, `hooks.slack.com/services/` |
| Private key | `-----BEGIN ... PRIVATE KEY-----` |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.` |
| Generic | `(api[_-]?key\|secret\|token\|password\|passwd\|client_secret)\s*[:=]\s*['"][^'"]{8,}` |
| Connection strings | `mongodb(+srv)?://user:pass@`, `postgres://`, `mysql://`, `Server=...;Password=` |
| SendGrid / Mailgun / Twilio | `SG.` + 66 chars, `key-[0-9a-f]{32}`, `AC[0-9a-f]{32}` + `SK[0-9a-f]{32}` |

## PII and sensitive field names (api_pii_scan.py)

`email`, `phone`, `mobile`, `address`, `street`, `zip`, `postcode`, `dob`, `birth`, `ssn`, `national_id`, `passport`, `tax_id`, `iban`, `card`, `pan`, `cvv`, `password`, `password_hash`, `hash`, `salt`, `token`, `access_token`, `refresh_token`, `api_key`, `secret`, `otp`, `mfa_secret`, `totp`, `reset_token`, `session`, `ip`, `last_login_ip`, `lat`, `lng`, `location`, `isAdmin`, `role`, `permissions`, `internal`, `debug`.

## Severity guide

| Exposure | Typical rating |
|---|---|
| Working cloud keys, database credentials, private keys, `.git` with secrets, `.env` with secrets | Critical / High |
| Other users' PII in bulk (emails, phones, addresses) | High |
| Password hashes or reset tokens in API responses | High |
| Source maps revealing internal code without secrets | Low / Informational |
| Internal IPs, versions, stack traces without data | Low / Informational |
| Public API keys meant for clients (Maps, Firebase web key) | Informational unless unrestricted with billing impact |
| Missing cookie flags without demonstrated exposure | Low |
| Autocomplete on password fields | Informational |

## Cross-references

| DE row | Related rows |
|---|---|
| DE-002, DE-003 | jsrecon, saas-third-party-exposure |
| DE-005 | error-handling-audit |
| DE-006 | server-config-audit SMC-006 |
| DE-008 to DE-011 | contentdiscovery `exposure_and_errors.md`, file-download-audit FD-008 |
| DE-013 | session-management cookie rows, tls-audit TLSX-011 |
| DE-014, DE-015 | client-side-js-security STOR-001 to STOR-003 |
| DE-016, DE-017 | api-security API-X-017, idor, graphql-audit |
| DE-018, DE-020 | session-management token leakage rows |
