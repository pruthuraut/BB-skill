---
name: cors-audit
description: "Deep CORS misconfiguration (CWE-346 origin validation error, CWE-942) audit for authorized applications — 15 core checks (arbitrary Origin reflection, null origin, subdomain trust, target-domain trust, credentials with wildcard, suffix and prefix matching, regex bypass, methods and headers, custom-header preflight, arbitrary subdomains, third-party whitelisting, unvalidated reflection, encoding tricks, WebSocket upgrade) plus about 40 bypass origins (attackertarget.com, target.com.attacker.com, target.computer, backtick/underscore/%60 parser breaks, @ and userinfo tricks, tab and space, backslash, ß and Unicode, scheme downgrade to http, ports), impact rows (credentialed data theft, CSRF token theft, IDOR via CORS, internal network pivot without credentials, TLS breaking through an http subdomain, XSS-on-trusted-origin chains, Vary: Origin cache poisoning, CR header injection), concept reference (SOP, simple vs preflighted requests, all CORS headers), PoC templates, and a scope-gated Origin-matrix probe that writes a PoC page. Triggers on \"CORS\", \"Access-Control-Allow-Origin\", \"ACAO\", \"Access-Control-Allow-Credentials\", \"origin reflection\", \"null origin\", \"Corsy\", \"CORScanner\", \"CorsMe\", \"preflight\", \"Vary: Origin\", \"cross-origin\", or when a response carries Access-Control-* headers."
---

# CORS Audit (15 core checks + bypass and impact matrix)

CORS relaxes the same-origin policy: the server names which origins may **read** its responses. A misconfiguration is only exploitable when a sensitive response becomes readable cross-origin, which usually means `Access-Control-Allow-Origin` (ACAO) echoes an attacker-controllable origin **and** `Access-Control-Allow-Credentials: true` (ACAC) is set on an endpoint that returns user data. CORS is not a CSRF defense; it controls reading, not sending.

- Checklist: `references/cors_checklist.md` (CORS-001 to CORS-015 core, CORS-B-* bypass origins, CORS-I-* impact and chains, severity guide).
- Concepts: `references/cors_concepts.md` (SOP and its exceptions, simple vs preflighted requests, request and response headers, null origin sources, Vary, parser behavior).
- PoC templates: `references/cors_poc_templates.md` (XHR, fetch, null-origin sandbox iframe, preflighted custom header, CSRF-token theft, IDOR loop, internal network, WebSocket, XSS-on-subdomain).
- Reports, tools, research: `references/cors_reports_and_tools.md`.
- Tracker: `references/cors_tracker.md` (copy to `artifacts/<target>/`, update 0/15 to 15/15).
- Probe: `scripts/cors_probe.py` (sends the Origin matrix plus preflights to your URLs with your own session, classifies each response, and can write a PoC HTML for the best finding; scope-gated, GET/HEAD/OPTIONS only).
- Related: `api-security` (API-X-008 to API-X-012), `csrf-audit` (XSRF-020, CORS-to-CSRF), `csrf-audit` (CORS-EXTRA-001), `client-side-js-security` and `csrf-audit` XSRF-011 (WebSockets), `subdomain-takeover`, `xss`, `request-smuggling-audit` (cache poisoning), `idor`.

## Subagents

| Subagent | Checks | Focus |
|---|---|---|
| 01 Discovery | CORS-001, 013 | Find every response with Access-Control-* headers; send Origin to every authenticated endpoint (headers often appear only when Origin is present) |
| 02 Origin validation | CORS-002 to 008, 011, 012, 014 | Null, subdomain, domain, suffix, prefix, regex, third-party, encoding and parser bypasses |
| 03 Preflight and methods | CORS-009, 010, 015 | Allowed methods and headers, preflight bypass, WebSocket upgrade Origin |
| 04 Impact and chains | CORS-005, CORS-I-* | Credentialed theft, token theft, IDOR, internal pivot, TLS break, XSS trust, cache |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Discovery, single target: crawl with Burp, then search history for `Access-Control`. For every authenticated JSON or HTML response that returns user data (profile, API keys, tokens, PII, messages, billing), resend with an `Origin` header. Sensitive pages that disclose usernames, emails, keys, or passwords are the priority.
3. Discovery, many hosts: `subfinder -d target.com -o domains.txt`, `httpx -l domains.txt -o alive.txt`, then run `scripts/cors_probe.py --urls alive.txt` (or CorsMe / Corsy / CORScanner on in-scope hosts only). Repeat the single-target step on hits.
4. Quick manual check: `curl -s -I 'https://HOST/api/v1/me' -H 'Origin: https://evil.example' -H 'Cookie: <own session>'` and read ACAO, ACAC, and Vary.
5. Run the Origin matrix with `scripts/cors_probe.py` on the sensitive endpoints, using your own session cookie or header. It sends the bypass origins (CORS-B-*), switches GET and POST, and sends preflights with methods and custom headers.
6. For each reflected origin, decide if it is reachable by an attacker: an arbitrary domain you can register (always), `null` (sandboxed iframe), any subdomain (needs XSS or takeover on a subdomain), an `http://` origin (needs a network attacker), a third-party host (needs control of content there, for example github.io, s3, or a CDN).
7. Confirm in a real browser: host the PoC on your own domain or `localhost`, open it in your own victim browser profile logged in to your own account, and show the sensitive data read. Browser behavior decides; header reflection alone is a lead.
8. Rate impact with the severity guide in the checklist, then look for chains (CORS-I-*).
9. Save findings to `artifacts/<target>/cors_findings.json`, PoCs to `artifacts/<target>/cors_pocs/`, and the tracker to `artifacts/<target>/cors_tracker.md`.

## Classes

- `passive`: reading Access-Control-* headers already in proxy history, JS fetch calls, and configs.
- `bounded`: Origin and preflight requests to in-scope endpoints with your own session (GET, HEAD, OPTIONS), and PoCs read by your own victim profile.
- `authorized-only`: anything against real users, man-in-the-middle for the http-subdomain TLS break, server-side cache poisoning on shared caches, internal-network pivoting, and chains needing XSS or takeover on another host. Explicit approval for that specific check.

## Rules

- Read only your own data in PoCs. Do not exfiltrate to third-party loggers; print in the page or log to your own server and delete afterward.
- Do not report ACAO `*` without credentials on public data, or reflection on endpoints with no sensitive data, as more than informational.
- Record the exact browser and version: SameSite cookie defaults, third-party cookie blocking, and Private Network Access change exploitability.
- Never claim a subdomain or third-party resource to prove trust (see subdomain-takeover).

## Mitigation guidance for reports

- Exact-match allowlist of full origins (scheme, host, port); never reflect Origin, never use substring, prefix, suffix, or unanchored regex.
- Never trust `null`. Do not trust `http://` origins from an HTTPS app. Trust subdomains only if all are hardened.
- Do not combine credentials with broad origins; `*` is only for public, unauthenticated data.
- Always send `Vary: Origin` when ACAO is dynamic.
- Keep `Access-Control-Allow-Methods` and `-Headers` minimal; short `Max-Age`.
- Remember CORS is not access control: authenticate and authorize server-side, and still use CSRF defenses.
- Validate the `Origin` header on WebSocket upgrades.

## Sources

PortSwigger Web Security Academy CORS labs and "Exploiting CORS misconfigurations for Bitcoins and bounties", MDN CORS and Same-origin policy, Corben Leo's advanced CORS techniques, OWASP WSTG-CLNT-07, CWE-346 and CWE-942, and the writeups and tools listed in `references/cors_reports_and_tools.md`.
