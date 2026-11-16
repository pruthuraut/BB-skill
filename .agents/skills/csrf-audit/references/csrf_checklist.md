# CSRF Checklist

Class key: `passive` = forms, JS, cookies, and headers read only; offline token analysis. `bounded` = own-account replays and PoCs opened in your own victim profile against your own victim account. `authorized-only` = anything reaching real users, shared resources, or needing another vulnerability exploited.

A row is a **finding** only when a PoC page on another origin changes state on your victim account in a current browser.

## Core checks (20)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-001 | State-changing requests | CSRF in all state-changing requests (POST, PUT, PATCH, DELETE, and state-changing GET) | bounded | Inventory every state change; for each, replay without token from a PoC page against own victim account |
| XSRF-002 | Forms | CSRF token present in forms and validated server-side | bounded | Grep hidden inputs and meta tags; run csrf_probe.py baseline vs modified token |
| XSRF-003 | Token | Token bypass by removing the parameter entirely (validation only when present) | bounded | csrf_probe.py `token_removed` variant; also remove the token header |
| XSRF-004 | Token | Token reuse across sessions (token from account A accepted for account V) | bounded | Pass A's token with `--other-token` while using V's cookie |
| XSRF-005 | Token | Token predictability and entropy (short, sequential, timestamp, hash of user ID, static part) | passive | Collect 20+ tokens, run csrf_token_analyze.py; try hashing known values (user ID, email, time) |
| XSRF-006 | Token | Token tied to session (global pool, tied to a non-session cookie, survives logout) | bounded | Use a token from a logged-out or older session; swap the csrf cookie with A's cookie and token pair |
| XSRF-007 | JSON APIs | JSON endpoint reachable cross-site: text/plain or form body accepted, or CORS allows credentialed origin | bounded | csrf_probe.py content-type variants; check `Access-Control-Allow-Origin` and `-Credentials` on an evil Origin |
| XSRF-008 | XML | XML endpoint accepts a form-delivered body (text/plain with XML, enctype trick) | bounded | Send XML as `text/plain` from a form; confirm parse and state change on own account |
| XSRF-009 | Multipart | multipart/form-data body accepted where the token is only checked for urlencoded or JSON | bounded | Re-encode the own-account request as multipart without token |
| XSRF-010 | AJAX | X-Requested-With (or custom header) is the only defense and can be dropped, or the check is missing on some routes | bounded | csrf_probe.py `no_x_requested_with` variant; check whether CORS allows the header cross-site |
| XSRF-011 | WebSocket | Cross-site WebSocket hijacking: handshake authenticated by cookie with no Origin check or token | bounded | Handshake with `Origin: https://evil.example` from own session; send a harmless own-account message |
| XSRF-012 | Cookies | SameSite missing, None, or Lax with state-changing GET (and the 2-minute Lax-by-default POST window) | passive | Read Set-Cookie; list GET endpoints that change state; note cookie issuance time behavior |
| XSRF-013 | Login | Login CSRF: victim browser logged into the attacker account (no token or Origin check on login, OAuth or SSO without state) | bounded | PoC logs own victim profile into own attacker account; show the impact (saved data, history, card) |
| XSRF-014 | Password | CSRF on password change (no current password, or current password field removable) | bounded | Own victim account: PoC without token and without current_password; restore password after |
| XSRF-015 | Email | CSRF on email or phone change (leads to ATO via reset) | bounded | Own victim account: PoC changes email to own attacker inbox; restore after |
| XSRF-016 | Headers | CSRF defense bypassed with X-Forwarded-Host / X-Forwarded-For / X-Original-URL / Host trust | bounded | Own account: add forwarded headers that match the trusted host; note that browsers cannot set them, so impact requires a proxy-reachable path |
| XSRF-017 | Method | HTTP method override bypass (`_method`, `X-HTTP-Method-Override`, `X-Method-Override`) | bounded | csrf_probe.py `method_override` variant; POST form with `_method=PUT/DELETE` from PoC |
| XSRF-018 | Origin/Referer | Origin and Referer validation: missing, regex/substring match, null accepted, absent header accepted | bounded | csrf_probe.py Origin and Referer variants; see XSRF-B-020 to 028 |
| XSRF-019 | GraphQL | GraphQL mutations via GET, urlencoded, or text/plain body, or no token on mutations | bounded | Send own-account mutation as GET query string and as form body; confirm state change |
| XSRF-020 | API CORS | API endpoints with credentialed CORS to arbitrary or weak origins (read token or act cross-site) | bounded | Origin probe with evil, null, and suffix/prefix origins; check ACAO and ACAC; see api-security |

## Bypass matrix

### Token value tricks

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-001 | Token | Token parameter removed | bounded | csrf_probe.py `token_removed` |
| XSRF-B-002 | Token | Token empty (`csrf_token=`) or whitespace | bounded | csrf_probe.py `token_empty` |
| XSRF-B-003 | Token | Token literal `undefined`, `null`, `0`, `1`, `true` | bounded | csrf_probe.py `token_undefined`; repeat with other literals by hand |
| XSRF-B-004 | Token | Token sent as empty array (`csrf_token[]=`), PHP and Node frameworks | bounded | csrf_probe.py `token_array` |
| XSRF-B-005 | Token | Random token of the same length and charset | bounded | csrf_probe.py `token_random_same_length` |
| XSRF-B-006 | Token | First or last character changed or deleted | bounded | csrf_probe.py `token_last_char` |
| XSRF-B-007 | Token | Token from another session or account (attacker feeds own valid token) | bounded | csrf_probe.py `--other-token` |
| XSRF-B-008 | Token | Previously used or expired token accepted (fixed per account) | bounded | Replay a token captured hours earlier |
| XSRF-B-009 | Token | Only the static part checked (`837456mzy29jkd` + changing suffix) | passive | csrf_token_analyze.py static prefix/suffix; send only the static part |
| XSRF-B-010 | Token | Token is a hash of a known value (MD5/SHA1 of user ID, email, timestamp) | passive | Analyzer hash-length hint; hash known values offline and compare |
| XSRF-B-011 | Token | Token obtained by the attacker through a separate request (token endpoint without auth binding, CORS-readable) | bounded | Fetch the token endpoint cross-origin from a PoC; check if readable |
| XSRF-B-012 | Token | Token leaked in URL, Referer, logs, or HTML injection (dangling markup) | bounded | Search GET URLs and outgoing Referers for the token; HTML injection points on own account |
| XSRF-B-013 | Token | Token parameter name case or duplicate (`CSRF_TOKEN`, two params, first or last wins) | bounded | Own account: duplicate param with valid and invalid values |

### Double-submit cookie

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-014 | Double submit | Cookie and body only compared to each other (`csrf=fake` in both accepted) | bounded | Own account: set both to the same invented value |
| XSRF-B-015 | Double submit | Attacker can set the csrf cookie (CRLF, subdomain, cookie tossing, non-`__Host-` cookie) | authorized-only | Needs a cookie-injection primitive; report the dependency, test only on own account |

### Method and content type

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-016 | Method | POST changed to GET with params in the query and no token | bounded | csrf_probe.py `post_to_get`; GET also defeats SameSite=Lax |
| XSRF-B-017 | Method | PUT/DELETE reached by POST + `_method` or override header | bounded | csrf_probe.py `method_override` |
| XSRF-B-018 | Content type | JSON body accepted as `text/plain` (no preflight) | bounded | csrf_probe.py `ct_text_plain`; PoC uses enctype text/plain padding |
| XSRF-B-019 | Content type | JSON endpoint accepts urlencoded or multipart (and validates token only for JSON) | bounded | csrf_probe.py `ct_form`; manual multipart |

### Referer and Origin

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-020 | Referer | Referer removed (`<meta name="referrer" content="no-referrer">`) accepted | bounded | csrf_probe.py `no_referer`; PoC with no-referrer meta |
| XSRF-B-021 | Referer | Substring match: `https://target.com.evil.example` or `https://evil.example/target.com` | bounded | csrf_probe.py `referer_evil`; PoC uses history.pushState to put target name in the path |
| XSRF-B-022 | Referer | Domain confusion: `https://evil.example/anything@target.com`, `target.com` in query | bounded | PoC with `unsafe-url` referrer policy and pushState path |
| XSRF-B-023 | Referer | Header name confusion: server reads `Referrer` vs `Referer` | bounded | Own replay with misspelled header only |
| XSRF-B-024 | Origin | `Origin: null` accepted (sandboxed iframe, data: URL iframe) | bounded | csrf_probe.py `origin_null`; PoC data: iframe or sandbox iframe |
| XSRF-B-025 | Origin | Origin absent accepted (some browsers omit Origin in data: iframes or on GET) | bounded | Replay with no Origin; browser test in Firefox and Chrome |
| XSRF-B-026 | Origin | Foreign Origin accepted (not validated at all) | bounded | csrf_probe.py `origin_evil` |
| XSRF-B-027 | Origin | Weak origin regex (`target.com.evil.example`, `eviltarget.com`, unescaped dot) | bounded | Replay with crafted origins |
| XSRF-B-028 | Origin | Check only for subdomains: any `*.target.com` trusted (pair with XSS or takeover on a subdomain) | authorized-only | Report the trust; exploit only with an approved chain |

### Browser, client, and SameSite

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-029 | SameSite | Lax cookie + state-changing GET via top-level navigation | bounded | PoC `<a>` or `location=` on own victim |
| XSRF-B-030 | SameSite | Lax-by-default 2-minute window (Chrome) after login or cookie refresh | bounded | PoC opens login refresh then POSTs within 2 minutes; own victim |
| XSRF-B-031 | SameSite | SameSite bypass via sibling subdomain (same-site, not same-origin) or client-side redirect gadget | authorized-only | Needs a gadget on a sibling domain; report path |
| XSRF-B-032 | User-Agent | Token check skipped for mobile, tablet, or API user agents | bounded | Own replay with a mobile UA and no token |
| XSRF-B-033 | Endpoints | Mobile or legacy API version without token (`/api/v1`, `/m/`) | bounded | Same action on alternate endpoints without token |
| XSRF-B-034 | Image | State-changing GET triggered by an image URL the app lets users set (avatar remote URL, embedded image) | authorized-only | Own account only: set image to an own-account action URL; never target viewers |

### Chains

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSRF-B-035 | Clickjacking | Action requires a click and the page is frameable | bounded | Frame test page against own victim (see csrf-and-headers-audit CLICK-002) |
| XSRF-B-036 | XSS | XSS on the same site reads the token and submits | authorized-only | Report the chain; prove on own account only |
| XSRF-B-037 | Subdomain + CORS | Taken-over or attacker-controlled subdomain trusted by CORS or Origin check | authorized-only | See subdomain-takeover; never claim resources |
| XSRF-B-038 | OAuth | OAuth or account-linking without `state`, or state bypass (null byte `%00`, reused, not bound) | bounded | Own client and accounts; see oauth-sso |
| XSRF-B-039 | Account linking | Link social account to victim via CSRF (attacker identity linked to victim account) | bounded | Own two accounts; PoC links attacker social to victim; unlink after |
| XSRF-B-040 | Deep links | Mobile deep link performs an action without confirmation | bounded | Own device and accounts |
| XSRF-B-041 | Logout | Logout CSRF (low alone; useful for login CSRF chains) | bounded | Own victim; report as chain helper |
| XSRF-B-042 | Password change | Current-password and token both removable in password change | bounded | Own victim; restore after |
| XSRF-B-043 | 2FA | Disable 2FA or add backup method without token or re-auth | bounded | Own victim; re-enable after |
| XSRF-B-044 | API keys | Generate or reveal API keys cross-site | bounded | Own victim; revoke keys after |
| XSRF-B-045 | Integrations | Webhook, Slack, payment-provider, or OAuth app connection without CSRF | bounded | Own victim; disconnect after |

## Where to hunt

- Account: change password, change email, change phone, profile update, avatar, account deletion or suspension, logout, linked accounts.
- Security: enable or disable 2FA, backup codes, security questions, sessions list, API key generation, OAuth app grants.
- Admin and team: add or delete users, change roles and permissions, invites, workspace settings.
- Money: transfers, payment methods, subscriptions, add to cart, checkout, payouts, payment provider connect.
- Content: comments, likes, follows, posts, support tickets, feedback.
- Integrations: webhook and third-party setup (Slack, PayPal, GitHub apps), import from URL.
- Alternate surfaces: mobile API, older API versions, GraphQL, WebSockets, deep links.

## Decision guide

1. Auth is a header token set by JS and cookies are not accepted → not CSRF-able (note it, move on).
2. Cookie SameSite=Strict on the session → only same-site gadgets apply (XSRF-B-031).
3. SameSite=Lax → look for state-changing GET (XSRF-B-016, B-029) and the 2-minute window (B-030).
4. SameSite=None or missing on an old browser target → full CSRF surface.
5. Token present → token tricks (B-001 to B-013), then double-submit (B-014, B-015).
6. No token, Origin or Referer checked → B-020 to B-028.
7. JSON only → B-018, B-019, XSRF-007, XSRF-020.

## Cross-references

| XSRF row | Related rows |
|---|---|
| XSRF-002, 003 | csrf-and-headers-audit CSRF-001, CSRF-002 |
| XSRF-012 | CSRF-004, CSRF-005, session-management cookie rows |
| XSRF-007 | CSRF-006, api-security CORS |
| XSRF-010 | CSRF-007 |
| XSRF-013, B-038 | CSRF-008, oauth-sso |
| XSRF-011 | CSRF-009, client-side-js-security |
| B-035 | CLICK-001, CLICK-002 |
| B-016 | CSRF-003 |
