# CORS Checklist

Class key: `passive` = headers already in proxy history, JS, and config. `bounded` = GET/HEAD/OPTIONS with an Origin header and your own session; PoCs read only your own data in your own victim profile. `authorized-only` = real users, network interception, shared-cache poisoning, internal pivoting, or chains needing another vulnerability.

`T` = target registrable domain (for example `target.com`). `A` = a domain you control (for example `attacker.example`).

A **finding** is a sensitive response readable from an attacker-reachable origin in a current browser. Header reflection alone is a lead.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CORS-001 | Origin | Arbitrary Origin reflected in ACAO | bounded | `Origin: https://A` on an authenticated endpoint; check ACAO equals it and ACAC is true |
| CORS-002 | Origin | `null` origin trusted (`ACAO: null` with credentials) | bounded | `Origin: null`; PoC via sandboxed iframe (template 3) |
| CORS-003 | Origin | Subdomain origin trusted (`https://anything.T`) | bounded | `Origin: https://cors-test.T`; then check if any subdomain has XSS, takeover, or user content |
| CORS-004 | Origin | Target-domain trust: `https://T`, `https://www.T`, other ports and schemes of T | bounded | Send each; note `http://T` and odd ports (TLS-break and port-sharing risk) |
| CORS-005 | Credentials | ACAC true together with a wildcard or reflected origin (and `*` with credentials misbehaving in custom clients) | bounded | Check ACAO `*` + ACAC true (browsers block, but note); reflected origin + ACAC true is the exploitable form |
| CORS-006 | Suffix match | Suffix check bypass: `https://AT` (`attackertarget.com`), `https://sub.AT` | bounded | Register-style origins ending with T without a dot boundary |
| CORS-007 | Prefix match | Prefix check bypass: `https://T.A` (`target.com.attacker.com`), `https://T-A`, `https://Tcomputer` | bounded | Origins starting with T |
| CORS-008 | Regex | Insecure regex: unescaped dot (`targetXcom`), unanchored, `.*`, case-insensitive host mix | bounded | `https://wwwXtarget.com`, `https://target.com.A`, `https://A/target.com`, uppercase variants |
| CORS-009 | Methods/headers | Different methods and headers allowed (`Access-Control-Allow-Methods`, `-Headers` with `*`, PUT, DELETE, Authorization) | bounded | OPTIONS preflight with `Access-Control-Request-Method: PUT/DELETE` and `-Headers: Authorization, X-Custom`; also switch GET to POST and POST to GET with the evil Origin |
| CORS-010 | Preflight | Preflight bypass: same request works as a simple request (text/plain, form, no custom header), or preflight response approves anything | bounded | Send the API call without the custom header or as `text/plain`; check ACAO on the actual request too |
| CORS-011 | Subdomains | Trust for arbitrary subdomains (`*.T` logic) including non-existent or user-controllable ones (user pages, sandboxes, previews) | bounded | `Origin: https://doesnotexist-<rand>.T`; list user-content subdomains (pages, docs, preview) |
| CORS-012 | Third party | Third-party whitelisting (github.io, s3.amazonaws.com, cloudfront, herokuapp, vercel.app, netlify.app, codepen, jsfiddle, partners, localhost) | bounded | Send each common host; any where you can host content is exploitable |
| CORS-013 | Reflection | Header reflection without validation (ACAO reflects any value, including garbage, spaces, CR) | bounded | `Origin: https://A`, `Origin: x`, `Origin: https://A%0d` (raw CR only in a manual request); check Vary |
| CORS-014 | Encoding | Origin validation bypass via encoding and parser tricks (backtick, underscore, `%60`, `%09`, `@`, `\`, `ß`, punycode) | bounded | CORS-B-020 to CORS-B-036 |
| CORS-015 | WebSocket | Origin not checked on WebSocket upgrade (cross-site WebSocket hijacking) | bounded | Upgrade request with `Origin: https://A` and own cookie; send a harmless read message (template 9) |

## Bypass origin matrix

Send each as `Origin:` on a sensitive endpoint with your own session. `scripts/cors_probe.py` generates these.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CORS-B-001 | Origin | `https://A` (attacker.com) | bounded | Probe |
| CORS-B-002 | Origin | `null` | bounded | Probe |
| CORS-B-003 | Origin | `https://A.T` (attacker.target.com) | bounded | Probe |
| CORS-B-004 | Origin | `https://attackerT` (attackertarget.com) | bounded | Probe |
| CORS-B-005 | Origin | `https://sub.attackerT` (sub.attackertarget.com) | bounded | Probe |
| CORS-B-006 | Origin | `https://T.A` (target.com.attacker.com, expected-host.com.attacker.com) | bounded | Probe |
| CORS-B-007 | Origin | `https://Tputer` style (expected-host.computer: `target.co` + `mputer`) | bounded | Probe |
| CORS-B-008 | Origin | `https://A/T` (attacker.com/target.com) | bounded | Probe |
| CORS-B-009 | Origin | `https://A?T`, `https://A#T` | bounded | Probe |
| CORS-B-010 | Origin | `http://T` (scheme downgrade) | bounded | Probe; enables TLS break (CORS-I-006) |
| CORS-B-011 | Origin | `https://T:8443`, `https://T:80` (port) | bounded | Probe |
| CORS-B-012 | Origin | `https://T` uppercase or mixed case (`TARGET.COM`) | bounded | Probe |
| CORS-B-013 | Origin | `https://T.` (trailing dot) | bounded | Probe |
| CORS-B-014 | Origin | `https://wwwXT` (unescaped dot in `www.target.com` regex) | bounded | Probe |
| CORS-B-015 | Origin | `https://T-A`, `https://T_A` | bounded | Probe |
| CORS-B-016 | Origin | `https://notT` (endsWith without dot) | bounded | Probe, same as B-004 with other prefixes |
| CORS-B-017 | Origin | `https://localhost`, `http://127.0.0.1`, `http://localhost:3000` (dev origins) | bounded | Probe |
| CORS-B-018 | Origin | `file://`, `chrome-extension://...`, `capacitor://localhost`, `ionic://localhost` (app origins) | bounded | Probe |
| CORS-B-019 | Origin | Empty value, `*`, and whitespace | bounded | Probe |
| CORS-B-020 | Parser | `https://T%60.A` / ``https://T`.A`` (Safari backtick) | bounded | Probe both raw and encoded |
| CORS-B-021 | Parser | `https://T_.A` (underscore, Chrome and Firefox) | bounded | Probe |
| CORS-B-022 | Parser | Special characters after T: `!`, `$`, `&`, `'`, `(`, `)`, `*`, `+`, `,`, `;`, `=`, `-`, `~`, `{`, `}`, `\|` then `.A` | bounded | Probe the set; note which the server accepts |
| CORS-B-023 | Parser | `https://sub.attacker T` (space) and `https://sub.attacker%T` | bounded | Probe |
| CORS-B-024 | Parser | `foo@A:80@T` | bounded | Probe |
| CORS-B-025 | Parser | `foo@A%20@T` | bounded | Probe |
| CORS-B-026 | Parser | `A%09T` (tab) | bounded | Probe |
| CORS-B-027 | Parser | `https://A\@T`, `https://A\\@T` (backslash) | bounded | Probe |
| CORS-B-028 | Parser | `127.1.1.1:80\@127.2.2.2:80` | bounded | Probe on internal-trust apps |
| CORS-B-029 | Parser | `127.1.1.1:80:\@@127.2.2.2:80` | bounded | Probe |
| CORS-B-030 | Parser | `127.1.1.1:80#\@127.2.2.2:80` | bounded | Probe |
| CORS-B-031 | Unicode | `https://ß.A` and other IDN (`ſ`, fullwidth dot `．`) normalised to ASCII | bounded | Probe raw and punycode |
| CORS-B-032 | Unicode | Punycode lookalike of T (`xn--...`) | bounded | Probe |
| CORS-B-033 | Encoding | URL-encoded dot or slash: `https://T%2eA`, `https://A%2fT` | bounded | Probe |
| CORS-B-034 | Encoding | Double origin values (`Origin: https://T, https://A`) and duplicated Origin header | bounded | Manual request |
| CORS-B-035 | Encoding | `https://T@A` (userinfo, browser treats host as A) | bounded | Probe |
| CORS-B-036 | Third party | `https://<you>.github.io`, `https://<bucket>.s3.amazonaws.com`, `https://*.herokuapp.com`, `https://*.vercel.app`, `https://*.netlify.app`, `https://*.cloudfront.net`, `https://codepen.io`, `https://jsfiddle.net` | bounded | Probe; exploitable if you can host a page there |

## Impact and chains

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CORS-I-001 | Data theft | Credentialed read of PII, API keys, tokens, messages, billing | bounded | PoC reads own victim data only (template 1 or 2) |
| CORS-I-002 | CSRF token theft | Read the anti-CSRF token cross-origin, then submit a state change (CORS to CSRF) | bounded | Own victim; see csrf-audit XSRF-B-011 |
| CORS-I-003 | IDOR via CORS | Credentialed endpoint keyed by ID readable cross-origin, combined with IDOR | bounded | Own two accounts only (template 6) |
| CORS-I-004 | Account takeover | Read password-reset token, session token in body, or OAuth code | bounded | Own victim account; restore after |
| CORS-I-005 | Internal network | ACAO `*` without credentials on intranet apps: victim browser as a proxy past IP-based auth (similar to DNS rebinding) | authorized-only | Report the configuration; do not scan victim networks; note Private Network Access limits |
| CORS-I-006 | TLS break | HTTPS app trusts an `http://` origin (subdomain over plain HTTP); network attacker injects a page on that origin | authorized-only | Report trust of http origin; no interception |
| CORS-I-007 | XSS trust chain | Trusted subdomain has XSS; JS there reads the main app with credentials | authorized-only | Prove XSS and trust separately on own account (template 8) |
| CORS-I-008 | Takeover trust chain | Trusted subdomain or third-party host is claimable | authorized-only | See subdomain-takeover; never claim |
| CORS-I-009 | Client cache | Dynamic ACAO without `Vary: Origin`, plus a header-reflected XSS reachable via CORS-sent custom header; browser cache serves poisoned response | bounded | Check Vary on dynamic ACAO; reproduce only in own browser |
| CORS-I-010 | Server cache | Origin reflected without sanitising CR (`Origin: z\rContent-Type: text/html; charset=UTF-7`) stored by a shared cache | authorized-only | Report the reflection; never poison a shared cache (see http-protocol-cache) |
| CORS-I-011 | Preflight cache | Long `Access-Control-Max-Age` with permissive preflight | passive | Note value |
| CORS-I-012 | Exposed headers | `Access-Control-Expose-Headers` exposes auth or token headers | passive | Note headers |
| CORS-I-013 | Out-of-scope pivot | Out-of-scope but trusted origin used to read in-scope data | authorized-only | Report trust; exploit only with approval |

## Severity guide

| Configuration | Typical severity |
|---|---|
| Arbitrary origin reflected + ACAC true + sensitive data | High to critical (ATO if tokens readable) |
| `null` trusted + ACAC true + sensitive data | High |
| Any subdomain trusted + ACAC true, with XSS or takeover on a subdomain | High (chain) |
| Any subdomain trusted, no known weak subdomain | Low or informational |
| `http://` origin trusted on HTTPS app | Medium (needs network attacker) |
| ACAO `*` without credentials, public data | Informational |
| ACAO `*` without credentials, intranet or IP-authenticated data | Medium (internal pivot) |
| Reflection without credentials, non-sensitive endpoint | Informational |
| Missing `Vary: Origin` alone | Low |

## Where to look

- API endpoints returning user objects: `/api/me`, `/api/user`, `/account`, `/profile`, `/settings`, `/billing`, `/keys`, `/tokens`, `/oauth/*`, `/graphql`.
- Pages that show usernames, emails, passwords, API keys, or CSRF tokens.
- Mobile and partner APIs, legacy versions, staging hosts, error pages (for example a 404 page that reflects Origin).
- Responses that only emit Access-Control-* headers when an Origin header is present.

## Cross-references

| CORS row | Related rows |
|---|---|
| CORS-001, 005 | api-security API-X-008, API-X-011; csrf-and-headers-audit CORS-EXTRA-001 |
| CORS-002 | API-X-009 |
| CORS-006, 007 | API-X-010 |
| CORS-I-002 | csrf-audit XSRF-020, XSRF-B-011 |
| CORS-015 | csrf-audit XSRF-011, client-side-js-security |
| CORS-I-008 | subdomain-takeover |
| CORS-I-010 | http-protocol-cache |
