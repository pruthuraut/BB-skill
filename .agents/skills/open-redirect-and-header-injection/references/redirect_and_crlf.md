# Open Redirect, CRLF and Header Injection Checks

Class key: `passive` (read headers/source), `bounded` (a few requests to your own OOB or test host), `authorized-only` (anything beyond that).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| OR-001 | Generic redirect | Redirect parameter (url, redirect, next, returnTo, returnUrl) accepts external host | bounded | `?url=https://<your-oob-host>` and check Location header |
| OR-002 | Generic redirect | Parser bypass: `https://target.com@evil`, `//evil`, `///evil`, `https://evil%2f@target.com` | bounded | Send each variant, record Location header |
| OR-003 | Generic redirect | Backslash and tab variants (`https:\\evil`, `/\/evil`) | bounded | Location header comparison |
| OR-004 | Generic redirect | Redirect validated by startswith or contains target.com (bypass via `target.com.evil`) | bounded | `https://target.com.<oob-host>` |
| OR-005 | Generic redirect | Redirect via 302 on login (`/login?redirect=`) | bounded | Location header on login GET |
| OR-006 | Generic redirect | DOM open redirect via location/hash sinks | bounded | Review JS for `location =` with source from URL; test with own host |
| OR-007 | 301/302 redirects | Redirect chain reveals staging or internal origin | passive | `curl -sIL` and record each Location host |
| OR-008 | 301/302 redirects | Newline or extra header injection in redirect value | bounded | Encoded `%0d%0a` in own test parameter; check Set-Cookie added |
| OR-009 | OAuth callback | redirect_uri open or prefix-match bypass (see oauth-sso) | bounded | Own client; see oauth-sso checks |
| OR-010 | Keycloak / OIDC | Wildcard redirect URI allows token theft | bounded | Review registered redirect URIs |
| CRLF-001 | URL parameter | Value reflected into response header (`%0d%0aSet-Cookie:`) | bounded | `?lang=en%0d%0aX-Test:1` and check response headers |
| CRLF-002 | Redirect Location | CRLF in redirect target adds headers | bounded | `?url=https://x%0d%0aX-Test:1` |
| CRLF-003 | Cookie value | CRLF in cookie-set values | bounded | Own-input reflection with CRLF, check Set-Cookie |
| CRLF-004 | Response splitting | Body injection after Content-Length: 0 | bounded | Own-input probe, check body split |
| HDR-001 | Host header | Password reset link built from Host header | bounded | Reset request with Host: <oob-host> on own account; inspect email link |
| HDR-002 | X-Forwarded-Host | Absolute URLs or cache keys trust forwarded host | bounded | Header probe and compare response URLs |
| HDR-003 | Host routing | Internal vhost reachable by Host override | bounded | Host header set to known internal name on in-scope IP |
| EMAIL-HDR-001 | Contact or registration forms | Email header injection (`%0d%0aBcc:`) | bounded | Own-address test with CRLF; check the message you receive |
