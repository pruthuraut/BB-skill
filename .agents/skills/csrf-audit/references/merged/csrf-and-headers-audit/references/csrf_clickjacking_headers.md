# CSRF, Clickjacking, Security Headers, CSP, HSTS, Cookie Prefixes

Class key: `passive` (headers and page source), `bounded` (own-account state-changing request with and without the token, on a test account only).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CSRF-001 | State-changing forms | CSRF token missing from forms | passive | Grep forms for token field names on password, email, settings pages |
| CSRF-002 | State-changing forms | Token not validated (replay, random value, removed) | bounded | Own account: replay the request with token removed, with random value, and with another account's token |
| CSRF-003 | State-changing forms | Method switch (POST to GET) accepted | bounded | Re-send own-account state change as GET, compare |
| CSRF-004 | Cookies | SameSite missing or None on session cookie | passive | `curl -sI` and read Set-Cookie |
| CSRF-005 | SameSite=Lax | Top-level GET state change | bounded | Review GET endpoints that change state |
| CSRF-006 | JSON APIs | Content-type switch to form-encoded accepted without CORS preflight | bounded | Own account: send form-encoded body to JSON endpoint |
| CSRF-007 | Htmx / AJAX | CSRF missing on XHR endpoints | bounded | Same as CSRF-002 for AJAX calls |
| CSRF-008 | OAuth | Missing state parameter (login CSRF) | bounded | Own client: omit state and check callback acceptance |
| CSRF-009 | WebSocket | Cross-site WebSocket hijacking (no Origin check) | bounded | Origin: https://evil.example on handshake, expect rejection (see linkparamdiscovery) |
| CLICK-001 | Framing | No X-Frame-Options or frame-ancestors | passive | `curl -sI` and look for both headers |
| CLICK-002 | Framing | Sensitive action frameable (account settings) | bounded | Local HTML frame test page on your host against own account |
| HDR-SEC-001 | Transport | HSTS missing or max-age below 1 year, no includeSubDomains | passive | `curl -sI https://` Strict-Transport-Security |
| HDR-SEC-002 | Transport | HTTP does not redirect to HTTPS | passive | `curl -sI http://` status and Location |
| HDR-SEC-003 | Content | X-Content-Type-Options missing | passive | Response headers |
| HDR-SEC-004 | Content | Referrer-Policy missing or unsafe-url | passive | Response headers |
| HDR-SEC-005 | Content | Permissions-Policy missing on sensitive pages | passive | Response headers |
| HDR-SEC-006 | Content | Cache-Control missing on authenticated responses | passive | Response headers on own session |
| HDR-SEC-007 | Cross-origin | COOP / COEP / CORP missing where isolation needed | passive | Response headers |
| CSP-001 | CSP | Missing CSP | passive | Response headers and meta tags |
| CSP-002 | CSP | unsafe-inline or unsafe-eval in script-src | passive | Parse CSP string |
| CSP-003 | CSP | Wildcard or whitelisted CDN host with JSONP or open redirect | bounded | Check known JSONP endpoints on allowed hosts (own request, no payload delivery) |
| CSP-004 | CSP | Base-uri or object-src missing | passive | Parse CSP |
| CSP-005 | CSP | Nonce reused or static | bounded | Two page loads, compare nonce |
| CSP-006 | CSP | Report-only mode in production | passive | Check for Content-Security-Policy-Report-Only without enforced header |
| CORS-EXTRA-001 | CORS | Reflected origin with credentials (see api-security) | bounded | Origin probe |
| COOKIE-PFX-001 | Cookies | Missing __Host- or __Secure- prefixes on session cookies | passive | Set-Cookie names |
| COOKIE-PFX-002 | Cookies | Missing Secure or HttpOnly | passive | Set-Cookie attributes |
