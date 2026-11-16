# Privilege Escalation & Function-Level Authorization: 37-Check Ledger

**Progress:** `[ 0 / 37 assessed ]`

Layout per check: **severity if vulnerable**, tags, objective, commands, pass/fail, references. PE-01…PE-25 are the core list; PE-26…PE-37 extend it (PortSwigger access-control labs and the unique checks of the previous version of this skill). A white-box appendix follows.

Variables: `$T` target origin · `$S` = `.agents/skills/access-control/scripts` · `$E` = `artifacts/access_control/evidence` · `$U1`, `$U2`, `$M`, `$ADM`, `$T2` = auth header for each self-owned role (`Cookie: …` or `Authorization: …`) · `$ORG` your org ID, `$ORG2` your second org.

Universal test: perform the function as the **highest** role that is allowed (baseline), then as each lower role and anonymously. Confirm effect from an independent session.

```bash
asrole() {  # asrole ROLEVAR METHOD URL [JSON]
  local h="${!1}"
  curl -sk -o "$E/tmp_$1.txt" -w "$1 %{http_code} %{size_download}\n" -X "$2" -H "$h" \
    ${4:+-H 'Content-Type: application/json' -d "$4"} "$3"
}
```

Status: `PASS` · `FINDING` · `INFO` · `NOT_APPLICABLE` · `CONFIG_REVIEW` · `BLOCKED`.

Reference shorthands:
- `PS-AC` = `https://portswigger.net/web-security/access-control`
- `PS-API` = `https://portswigger.net/web-security/api-testing`
- `WSTG-ATHZ-02` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema`
- `WSTG-ATHZ-03` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation`
- `API5` = `https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/`
- `API3` = `https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`
- `CS-AUTHZ` = `https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html`
- `A01` = `https://owasp.org/Top10/A01_2021-Broken_Access_Control/`

---

## PE-A — Role & Identity Claims

### PE-03 · Role manipulation in request parameters (`role=admin`) — `CRITICAL`
Tags: `privesc` `parameter-tampering` · Subagent: PE-A

Add/modify role-bearing parameters on login, session-bootstrap, profile, settings and any request that returns the current user: `role`, `roles[]`, `isAdmin`, `is_admin`, `admin`, `user_type`, `access_level`, `permissions[]`, `groups[]`, `is_staff`, `is_superuser`, `tier`.

```bash
python3 -I $S/priv_mutator.py --json '{"name":"bbtest"}' | awk -F'\t' '$1 ~ /role-field/' | head -20
asrole U1 POST "$T/api/session/refresh" '{"role":"admin"}'
```
- **Fail:** U1's effective permissions change (verify with an admin-only request afterwards).
- **Refs:** `PS-AC` (lab: User role controlled by request parameter) · `WSTG-ATHZ-03`

### PE-04 · Role manipulation in JWT claims (`role`, `scope`, `groups`) — `CRITICAL`
Tags: `privesc` `jwt` `claims` · Subagent: PE-A

Decode U1's token, then test whether role claims are trusted: (1) unsigned/forged tokens (`session-management` SM-22/23/24/27/28 for signature bypass), (2) claims the server copies from request to token (`/token/refresh` with `scope=admin`), (3) claims the backend reads from a **different, unsigned** source (ID token vs access token, `X-User-Roles` set by gateway).

```bash
python3 -I .agents/skills/session-management/scripts/jwt_inspect.py "$U1_JWT" | grep -iE 'role|scope|group|perm|admin'
python3 jwt_tool.py "$U1_JWT" -I -pc role -pv admin -X a        # only meaningful if alg none accepted
```
- **Fail:** elevated claim accepted.
- **Refs:** https://portswigger.net/web-security/jwt · `WSTG-ATHZ-03` · `session-management` SM-29

### PE-05 · Role manipulation in session cookies — `CRITICAL`
Tags: `privesc` `cookie` · Subagent: PE-A

Cookies like `Admin=false`, `role=user`, `uid=…`, base64/JSON cookies (`eyJyb2xlIjoidXNlciJ9`), unsigned framework sessions (Flask `session`, Express `cookie-session`, Rails with known `secret_key_base`).

```bash
echo 'eyJyb2xlIjoidXNlciJ9' | base64 -d     # {"role":"user"} -> re-encode with "admin"
flask-unsign --decode --cookie "$FLASK_COOKIE"; flask-unsign --unsign --cookie "$FLASK_COOKIE" --no-literal-eval   # offline secret check
```
- **Fail:** modified cookie grants admin functions.
- **Refs:** `PS-AC` (lab: User role controlled by request parameter — `Admin=true` cookie) · `session-management` SM-35

### PE-07 · Privilege escalation via mass assignment (`isAdmin: true`) — `CRITICAL`
Tags: `privesc` `mass-assignment` `bopla` · Subagent: PE-A

Mirror every property returned by `GET /api/users/me` / `GET /api/users/{id}` (as ADM) back into U1's `PATCH /api/users/me`, `POST /api/users`, `PUT /api/members/{id}`. Pay attention to nested objects (`{"membership":{"role":"owner"}}`) and arrays (`"permissions":["*"]`).

```bash
asrole ADM GET "$T/api/users/$U2_ID"                                     # learn the admin-visible schema
asrole U1 PATCH "$T/api/users/me" '{"isAdmin":true,"role":"admin","permissions":["*"],"membership":{"role":"owner"}}'
asrole U1 GET "$T/api/admin/users"
```
- **Fail:** any privilege-bearing field persisted.
- **Refs:** `PS-API` (Mass assignment lab) · `API3` · https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### PE-08 · Role change via profile update endpoint — `CRITICAL`
Tags: `privesc` `profile-update` · Subagent: PE-A

The profile/settings update (often JSON, sometimes the same endpoint admins use with extra fields) accepts `roleid`, `role_id`, `group_id`. PortSwigger lab: `POST /my-account/change-email {"email":…,"roleid":2}`. Also test the admin's "edit user" endpoint with U1's own ID.

```bash
asrole U1 POST "$T/my-account/change-email" '{"email":"you+u1@your-domain.test","roleid":2}'
asrole U1 PUT "$T/api/admin/users/$U1_ID" '{"role":"admin"}'
```
- **Fail:** U1's role changes.
- **Refs:** `PS-AC` (lab: User role can be modified in user profile) · `WSTG-ATHZ-03`

### PE-09 · Privilege escalation via API parameter tampering — `HIGH`
Tags: `privesc` `api` `parameter-tampering` · Subagent: PE-A

Admin-only *behaviours* exposed through parameters on user endpoints: `?all=true`, `?scope=global`, `?include=deleted,internal`, `?as_admin=1`, `?tenant=*`, `?fields=password_hash,api_key`, `"notify":false`, `"skip_approval":true`, `"verified":true`, `"price":0` (hand price to `business-logic`).
- **Fail:** parameter unlocks admin-only data or behaviour for U1.
- **Refs:** `API5` · `API3` · `WSTG-ATHZ-02`

### PE-35 · Hidden debug / staff / internal parameters and headers — `HIGH`
Tags: `privesc` `debug` `hidden-params` · Subagent: PE-A

`?debug=1`, `?admin=true`, `?internal=1`, `?staff=1`, `?test=1`, `?preview=1`, `X-Debug: 1`, `X-Internal: true`, `X-Admin: true`, `X-Staff: 1`, `X-Forwarded-For: 127.0.0.1` on IP-allowlisted admin paths, `X-Env: staging`. Mine with Param Miner (headers + params).
- **Fail:** extra functions/data/stack traces or admin behaviour enabled.
- **Refs:** https://github.com/PortSwigger/param-miner · `WSTG-ATHZ-02`

---

## PE-B — Admin Surface & Request Tricks

### PE-01 · Vertical privilege escalation (normal user → admin) — `CRITICAL`
Tags: `privesc` `vertical` · Subagent: PE-B

Replay every ADM request as U1, M and anon with `role_matrix.py`; then manually verify any allowed admin function.

```bash
python3 -I $S/role_matrix.py --target example.com --har artifacts/access_control/ADM.har \
  --role "U1=$U1" --role "M=$M" --admin-markers 'Admin panel,Manage users' --out artifacts/access_control/role_matrix.tsv
```
- **Fail:** any admin function performed/viewed by a lower role.
- **Refs:** `PS-AC` (Vertical privilege escalation) · `WSTG-ATHZ-03` · `A01`

### PE-06 · Admin endpoints protected with authorization — `CRITICAL`
Tags: `privesc` `bfla` `admin-api` · Subagent: PE-B

Enumerate admin API endpoints (ADM HAR, JS bundles, OpenAPI specs, `/api/admin/*`, `/internal/*`, `/manage/*`, `/staff/*`, `/actuator`, `/_admin`) and call each as U1 and anon. Admin APIs are often protected only by the UI not linking to them.
- **Fail:** admin API responds with data/effect to U1/anon.
- **Refs:** `API5` · `PS-AC` (Unprotected functionality)

### PE-11 · Direct access to admin functionality via URL — `HIGH`
Tags: `privesc` `forced-browsing` `unprotected-functionality` · Subagent: PE-B

Admin pages at predictable or disclosed URLs: `/admin`, `/administrator`, `/admin-panel`, `/console`; disclosed in `robots.txt`, `sitemap.xml`, JS (`if (isAdmin) { link = '/admin-x7f3' }`), source maps, error pages. Request as U1/anon.

```bash
curl -sk "$T/robots.txt" | grep -i disallow
grep -rhoE "['\"](/[a-zA-Z0-9_-]*(admin|manage|staff|internal|console)[a-zA-Z0-9_/-]*)['\"]" artifacts/js/ 2>/dev/null | sort -u
```
- **Fail:** admin page/function reachable without the admin role.
- **Refs:** `PS-AC` (labs: Unprotected admin functionality; …with unpredictable URL)

### PE-16 · Role-based access bypass via URL encoding tricks — `HIGH`
Tags: `privesc` `path-normalisation` `encoding` · Subagent: PE-B

Front-end/route rule matches `/admin` literally; back end normalises: `/ADMIN`, `/Admin`, `/%61dmin`, `/%2561dmin`, `/admin%2f`, `/admin/`, `/admin;/`, `/admin..;/`, `//admin`, `/./admin`, `/x/../admin`, `/admin%00`, `/admin%20`, `/admin.json`, `/%2e/admin`, Unicode `/ａdmin`.

```bash
python3 -I $S/priv_mutator.py --path /admin/users | awk -F'\t' '$1=="path"' > $E/PE-16_paths.tsv
.agents/skills/authbypass/scripts/bypass_matrix.sh --target example.com --url "$T/admin/users" --cookie "${U1#Cookie: }"
```
- **Fail:** any variant returns the admin response to U1.
- **Refs:** `PS-AC` (URL-matching discrepancies) · Orange Tsai, *Breaking Parser Logic* (Black Hat 2018)

### PE-18 · Privilege escalation via HTTP method override headers — `HIGH`
Tags: `privesc` `method-override` · Subagent: PE-B

Authorization rules keyed on method (e.g., deny `POST /admin/users/delete`) while the framework honours `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `_method=` body/query. Also plain method switching (`POST`→`GET` with params in the query).

```bash
asrole U1 POST "$T/admin-roles?username=$U2_NAME&action=upgrade"
curl -sk -H "$U1" "$T/admin-roles?username=$U2_NAME&action=upgrade" -w '\nGET %{http_code}\n'
curl -sk -H "$U1" -H 'X-HTTP-Method-Override: PUT' -X POST "$T/api/users/$U2_ID/role" -d 'role=admin' -w '\n%{http_code}\n'
```
- **Fail:** action executes for U1 (target only U2, your own account).
- **Refs:** `PS-AC` (lab: Method-based access control can be circumvented) · `PS-API` (HTTP methods)

### PE-19 · Privilege escalation via content-type switching — `HIGH`
Tags: `privesc` `content-type` `parser-differential` · Subagent: PE-B

Same endpoint, different parser path: JSON → `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`, `application/xml`; JSON with duplicate keys; validators/allowlists applied to one parser only (e.g., `role` stripped from JSON but accepted from form).

```bash
python3 -I $S/priv_mutator.py --json '{"email":"you+u1@your-domain.test","role":"admin"}' | awk -F'\t' '$1=="content-type"'
```
- **Fail:** forbidden field/action accepted under another content type.
- **Refs:** `PS-API` (Testing supported content types) · `API3`

### PE-26 · Referer-based and location-based access control — `HIGH`
Tags: `privesc` `referer` `geo` · Subagent: PE-B

Sub-pages that only check `Referer: …/admin`, or controls based on `X-Forwarded-For`/geo/IP headers (`CF-IPCountry`, `X-Country-Code`, `X-Client-IP`), or VPN/office-IP allowlists that trust headers.

```bash
curl -sk -H "$U1" -H "Referer: $T/admin" "$T/admin-roles?username=$U1_NAME&action=upgrade" -w '\n%{http_code}\n'
curl -sk -H "$U1" -H 'X-Forwarded-For: 127.0.0.1' -H 'CF-IPCountry: US' "$T/admin" -o /dev/null -w '%{http_code}\n'
```
- **Fail:** header alone grants access.
- **Refs:** `PS-AC` (lab: Referer-based access control; Location-based access control)

---

## PE-C — Architecture Layers

### PE-12 · Privilege escalation via GraphQL mutations — `CRITICAL`
Tags: `privesc` `graphql` `mutations` · Subagent: PE-C

List mutations (introspection, InQL, or suggestions/field-guessing when introspection is off), then call admin mutations as U1: `updateUserRole`, `addTeamMember(role:)`, `setFeatureFlag`, `createApiKey(scopes:)`, `impersonate`. Batch/alias to bypass per-request checks.

```graphql
mutation { updateUser(id: "U2_ID", input: { role: ADMIN }) { id role } }
```
- **Fail:** U1 executes admin mutations.
- **Refs:** https://portswigger.net/web-security/graphql · https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html · `API5`

### PE-17 · Improper authorization at the API gateway level — `HIGH`
Tags: `privesc` `api-gateway` `trust-boundary` · Subagent: PE-C

Gateway enforces role on `/api/admin/*` but the backend is reachable another way: direct origin IP/host, alternate host (`api-internal.`, `origin.`), path variants the gateway routes differently (PE-16), HTTP/2 vs HTTP/1.1, gateway-injected identity headers (`X-User-Role`, `X-Authenticated-User`, `X-Consumer-Groups`) that the backend trusts if supplied by the client.

```bash
for h in 'X-User-Role: admin' 'X-Authenticated-Userid: admin' 'X-Consumer-Groups: admin' 'X-Roles: admin' 'X-Forwarded-User: admin'; do
  curl -sk -H "$U1" -H "$h" "$T/api/admin/users" -o /dev/null -w "$h -> %{http_code} %{size_download}\n"; done
```
- **Fail:** backend trusts client headers or is reachable bypassing the gateway policy.
- **Refs:** `CS-AUTHZ` · `API5`

### PE-20 · Inconsistent authorization between UI and API — `HIGH`
Tags: `privesc` `ui-vs-api` · Subagent: PE-C

Buttons hidden/disabled for U1 (UI-only control) while the API accepts the call. Enable disabled form fields, unhide elements, or replay ADM's API calls (PE-01). Also mobile app vs web API vs public API differences.
- **Fail:** API performs an action the UI denies to U1.
- **Refs:** `A01` (access control enforced only client-side) · `WSTG-ATHZ-02`

### PE-32 · API key / personal access token / OAuth scope escalation — `HIGH`
Tags: `privesc` `api-keys` `scopes` · Subagent: PE-C

Create a read-only or project-scoped key as U1: can it write, reach other projects, create new keys with broader scopes, or call admin endpoints? Can U1 create keys with scopes U1 doesn't have (`scopes:["admin"]`)? Do keys keep working after U1's role is lowered (→ PE-28)?
- **Fail:** key exceeds its scope or its creator's privileges.
- **Refs:** `API5` · `oauth-sso` OA-07

### PE-33 · GraphQL field-level authorization — `HIGH`
Tags: `privesc` `graphql` `field-level` · Subagent: PE-C

Admin-only fields on shared types (`User.email`, `User.role`, `User.apiKeys`, `Org.billing`, `auditLogs`) returned to U1 when requested directly or via nested edges/fragments.

```graphql
query { me { org { members { email role lastLoginIp apiKeys { token } } billing { cardLast4 } } } }
```
- **Fail:** U1 receives fields reserved for admins.
- **Refs:** https://portswigger.net/web-security/graphql · `API3`

### PE-36 · Cache-layer authorization leakage — `HIGH`
Tags: `privesc` `cache` `web-cache-deception` · Subagent: PE-C

Privileged responses cached and served to others: web cache deception on admin/account pages (`/admin/users/x.css`, `/account;.js`), shared caches ignoring `Authorization`/`Cookie` in the key, CDN caching of `/api/me`. Use cache-busters and only your own sessions (ADM primes, U1/anon fetch).

```bash
curl -sk -H "$ADM" "$T/admin/users/bbtest$RANDOM.css" -D - -o /dev/null | grep -iE 'cache|age|x-cache'
```
- **Fail:** U1/anon retrieves ADM's cached privileged response.
- **Refs:** https://portswigger.net/web-security/web-cache-deception · `A01`

---

## PE-D — Tenancy, Membership & Sharing

### PE-02 · Horizontal privilege escalation (user A → user B data) — `HIGH`
Tags: `privesc` `horizontal` · Subagent: PE-D

Object-level testing is in the [`idor`](../../idor/SKILL.md) skill (35 checks, `idor_replay.py`). Here, record the result and test **function-level** horizontal access: U1 performing account functions on U2 (change U2's email/password/2FA, view U2's sessions, export U2's data) via endpoints that take a user identifier.
- **Fail:** U1 performs account functions for U2.
- **Refs:** `PS-AC` (Horizontal privilege escalation; Horizontal to vertical) · `idor` checklist

### PE-14 · Broken access control in multi-tenant applications — `CRITICAL`
Tags: `privesc` `multi-tenant` · Subagent: PE-D

Replay ADM (org 1) requests with T2's session (org 2) and vice versa; swap tenant identifiers in subdomains (`org1.app` → `org2.app` with org1 session), headers (`X-Tenant-Id`), paths (`/orgs/{id}/…`), JWT claims (`tid`, `org_id`), and search/filter scopes.

```bash
python3 -I $S/role_matrix.py --target example.com --har artifacts/access_control/ADM.har --role "T2=$T2" --out artifacts/access_control/tenant_matrix.tsv
```
- **Fail:** cross-tenant read/write.
- **Refs:** `A01` · `API1`/`API5` · `references/idor_and_privilege_reproduction_playbook.md` §2

### PE-15 · Privilege escalation via group/team membership change — `CRITICAL`
Tags: `privesc` `membership` `teams` · Subagent: PE-D

As U1 (member): add yourself to admin/owner groups, change own membership role, join private teams by ID, approve own join request, remove the owner, transfer ownership to yourself, add U1 to `org2` teams.

```bash
asrole U1 POST "$T/api/teams/$ADMIN_TEAM_ID/members" "{\"user_id\":\"$U1_ID\",\"role\":\"owner\"}"
asrole U1 PATCH "$T/api/orgs/$ORG/members/$U1_ID" '{"role":"admin"}'
```
- **Fail:** U1 gains a higher membership role or joins a restricted group.
- **Refs:** `API5` · `WSTG-ATHZ-03`

### PE-21 · Privilege escalation via organisation ID manipulation — `CRITICAL`
Tags: `privesc` `org-id` · Subagent: PE-D

Where U1 is admin of their *own* org (self-service) but member of another: send admin actions with the other org's ID (`/orgs/$ORG2/settings` while authorised as admin only in `$ORG`). Server must check the role **in the target org**, not "is admin somewhere".
- **Fail:** admin rights from one org apply to another.
- **Refs:** `A01` · `API5`

### PE-25 · Privilege escalation via shared resource access — `HIGH`
Tags: `privesc` `sharing` · Subagent: PE-D

Share links/permissions: view-only shares that allow edit via API, re-sharing with higher permission than you hold, share links that grant org membership, public links exposing admin views, permission inheritance (folder → file) mistakes, revoked shares still working.
- **Fail:** shared access exceeds what was granted or survives revocation.
- **Refs:** `A01` · `API5`

### PE-29 · Invitation and delegation abuse — `CRITICAL`
Tags: `privesc` `invites` `delegation` · Subagent: PE-D

M invites with `role: owner/admin` (higher than M's own), invite acceptance with tampered role, invite tokens reusable/transferable to other emails or other orgs, accepting an invite meant for another address, delegated admins granting roles above their level, pending invites still valid after the inviter is demoted.

```bash
asrole M POST "$T/api/orgs/$ORG/invites" '{"email":"you+inv@your-domain.test","role":"owner"}'
```
- **Fail:** any path yields a role above the inviter's or for an unintended recipient/org.
- **Refs:** `WSTG-ATHZ-03` · `API5`

### PE-30 · Impersonation / "login as user" / support access — `CRITICAL`
Tags: `privesc` `impersonation` · Subagent: PE-D

Endpoints like `/admin/impersonate/{id}`, `?as_user=`, `X-Impersonate-User`, `act_as`, support-mode tokens. Test as U1/M; test whether ADM of org 1 can impersonate users of org 2 or platform staff; check impersonation tokens' scope/expiry and audit trail.
- **Fail:** U1/M impersonates anyone, or ADM impersonates outside their tenant.
- **Refs:** `CS-AUTHZ` · `API5`

---

## PE-E — Features, Data & State

### PE-10 · Privilege escalation via feature flag manipulation (client side) — `HIGH`
Tags: `privesc` `feature-flags` · Subagent: PE-E

Flags delivered to the client (`/api/flags`, LaunchDarkly/Unleash/Split payloads, `window.__FEATURES__`, localStorage) that gate admin/beta functionality. Override them (Burp match/replace on the flags response) and see whether the **server** then serves the gated function.
- **Fail:** server-side function works for U1 once the client flag is flipped (UI-only gating).
- **Refs:** `A01` (client-side enforcement) · `WSTG-ATHZ-02`

### PE-13 · Privilege escalation via race condition in role assignment — `HIGH`
Tags: `privesc` `race-condition` `toctou` · Subagent: PE-E

Races between: demotion and an in-flight admin action; accepting the same invite twice/with two roles; role change + permission check; "last owner" protections (two owners demote each other simultaneously); limit overrun on seat-limited roles.

```bash
python3 -I $S/race_burst.py --target example.com --request artifacts/access_control/accept_invite.req --count 10
```
- **Fail:** inconsistent end state granting extra privilege (two owner records, role above invite, admin action after demotion).
- **Refs:** https://portswigger.net/web-security/race-conditions · https://portswigger.net/research/smashing-the-state-machine

### PE-22 · Privilege escalation via feature toggle API — `CRITICAL`
Tags: `privesc` `feature-toggle` `admin-api` · Subagent: PE-E

Server-side toggle endpoints (`PUT /api/features/{flag}`, `/api/orgs/{id}/settings {"sso_enforced":false}`, `/api/plans/override`, Unleash/Flagsmith admin APIs exposed) callable by U1, or toggles that change who is admin (`"allow_member_invites":true`, `"default_role":"admin"`).
- **Fail:** U1 changes feature/security settings of the org/platform.
- **Refs:** `API5` · `A01`

### PE-23 · Privilege escalation via backup / restore — `CRITICAL`
Tags: `privesc` `backup` `restore` · Subagent: PE-E

Export a backup of **your own** workspace as ADM, inspect it (roles, user records, settings, secrets), modify role data (U1 → owner) and restore as M/U1 or into another of your workspaces. Also: who can trigger backup/restore; do backups contain other tenants or credentials; are backup files accessible by URL (→ `idor` ID-09).
- **Fail:** restore elevates roles, crosses tenants, or backups leak secrets.
- **Refs:** `A01` · `WSTG-ATHZ-03`

### PE-24 · Privilege escalation via import / export with role data — `HIGH`
Tags: `privesc` `import` `export` `csv` · Subagent: PE-E

User/member CSV/JSON import with a `role` column (`you+x@your-domain.test,owner`), SCIM/LDAP sync payloads with group mapping, project templates carrying permissions, export endpoints that include fields/rows beyond the requester's rights (other tenants, admin-only columns).
- **Fail:** import assigns roles beyond the importer's rights, or export leaks higher-privilege data.
- **Refs:** `API3` · `A01`

### PE-27 · Multi-step admin flows with control on one step only — `HIGH`
Tags: `privesc` `multi-step` · Subagent: PE-E

Capture ADM's multi-step action (select user → confirm role change → apply), then replay only the **final** step as U1 (PortSwigger lab: *Multi-step process with no access control on one step*).

```bash
asrole U1 POST "$T/admin-roles" "{\"action\":\"upgrade\",\"confirmed\":true,\"username\":\"$U1_NAME\"}"
```
- **Fail:** final step executes for U1.
- **Refs:** `PS-AC` (Multi-step processes)

### PE-28 · Privilege retention after demotion / removal — `HIGH`
Tags: `privesc` `stale-privileges` `revocation` · Subagent: PE-E

Promote U2 to admin, capture U2's session/JWT/API key/refresh token, demote or remove U2 from the org, then reuse every credential for admin and member actions. Check cached permissions, long-lived JWT `role` claims, WebSocket connections, SSO-provisioned groups.
- **Fail:** removed/demoted user retains privileges beyond a short, documented window.
- **Refs:** `session-management` SM-30/34 · `CS-AUTHZ` (permission changes take effect immediately)

### PE-31 · Approval workflow and state-transition bypass — `HIGH`
Tags: `privesc` `workflow` `approval` · Subagent: PE-E

Self-approval (requester approves own request), approving with a role that should only request, skipping pending states (`status: "approved"` on create), editing an approved object back to draft and re-submitting, forcing transitions out of order (old check 17).
- **Fail:** U1 completes a workflow that requires a higher role or another person.
- **Refs:** https://portswigger.net/web-security/logic-flaws · `business-logic` skill

### PE-34 · Step-up authentication / re-auth bypass for privileged actions — `HIGH`
Tags: `privesc` `step-up` `mfa` · Subagent: PE-E

Privileged actions (role change, API key creation, ownership transfer, disabling SSO/MFA) that require password/MFA re-entry: replay without the re-auth token, reuse an old re-auth token, call the API directly, or use another endpoint for the same action.
- **Fail:** privileged action completes without fresh step-up.
- **Refs:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html (re-authentication) · `authbypass` AB-36

### PE-37 · Plan / entitlement bypass (paid features) — `MEDIUM`
Tags: `privesc` `entitlements` `billing` · Subagent: PE-E

Free-plan U1 calls paid-plan endpoints (SSO config, audit logs, exports, extra seats, API rate tiers), flips `plan`/`tier`/`subscription` fields in requests or responses, uses trial-only features after expiry. No payment manipulation (hand to `business-logic`).
- **Fail:** paid functionality available server-side to a lower plan.
- **Refs:** `API5` · `business-logic` skill

---

## Appendix — White-box / defensive review (`CONFIG_REVIEW`)

Carry these from the previous version of this skill; assess only with source/config access or vendor documentation, and never mark `PASS` from black-box silence.

| ID | Review item | Evidence needed |
|---|---|---|
| WB-1 | Centralised, deny-by-default authorization middleware/policy (Casbin, Pundit, Spring `@PreAuthorize`, OPA) applied to every route | Route list vs policy coverage |
| WB-2 | Data-layer ownership/tenant binding (`WHERE tenant_id = :session_tenant`, row-level security, Prisma/ORM scopes) | Query/ORM code |
| WB-3 | Indirect reference maps or scoped IDs where raw IDs are unnecessary | Design/code |
| WB-4 | Security logging and alerting on authorization failures | Log samples / SIEM rules |
| WB-5 | Password-reset token bound to its user (moved to `authbypass` AB-08) | — |

## Ledger template (`artifacts/access_control/access_control_checklist_37.tsv`)

```
check_id	status	severity	finding_id	evidence_path	notes
PE-01
...
PE-37
```
