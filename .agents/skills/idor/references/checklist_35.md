# IDOR / BOLA: 35-Check Ledger

**Progress:** `[ 0 / 35 assessed ]`

Layout per check: **severity if vulnerable**, tags, objective, commands, pass/fail, references. ID-01…ID-25 are the core list; ID-26…ID-35 extend it from PortSwigger labs, OWASP and the community sources supplied with this skill.

Variables: `$T` target origin · `$S` = `.agents/skills/idor/scripts` · `$E` = `artifacts/idor/evidence` · `$A_SESS` / `$B_SESS` cookie or `Authorization` header for accounts A and B · `$A_ID` / `$B_ID` user IDs · `$A_OBJ` / `$B_OBJ` object IDs owned by each.
Accounts (all yours): **A**, **B** same role · **C** different role · **A2** different tenant/org.

The universal test (apply in every check): request A's object with **(1)** A's session (baseline), **(2)** B's session, **(3)** no session, **(4)** C's and A2's sessions where relevant. Compare status, size, and content markers — not status alone.

```bash
idor() {  # usage: idor METHOD URL [BODY]  -> prints A / B / anon results for A's object
  for who in A B anon; do
    case $who in A) h="$A_SESS";; B) h="$B_SESS";; anon) h="X-None: 1";; esac
    curl -sk -o "$E/tmp_$who.txt" -w "$who %{http_code} %{size_download}\n" -X "$1" -H "$h" \
      ${3:+-H 'Content-Type: application/json' -d "$3"} "$2"
  done
  grep -c "a-user@your-domain.test" "$E"/tmp_B.txt "$E"/tmp_anon.txt
}
```

Status: `PASS` · `FINDING` · `INFO` · `NOT_APPLICABLE` · `BLOCKED`.

Reference shorthands:
- `PS-IDOR` = `https://portswigger.net/web-security/access-control/idor`
- `PS-AC` = `https://portswigger.net/web-security/access-control`
- `WSTG-ATHZ-04` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References`
- `CS-IDOR` = `https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html`
- `CS-AUTHZ` = `https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html`
- `API1` = `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`
- `API3` = `https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`

---

## ID-A — Identifier Discovery & Predictability

### ID-06 · UUID vs sequential integer identifiers — `HIGH`
Tags: `idor` `uuid` `sequential` · Subagent: ID-A

Classify every identifier (`id_extract.py`). Sequential/short IDs make exploitation trivial; UUIDs only raise the bar for *finding* IDs — authorization must still be tested with B's real UUID. Look for endpoints that accept **both** forms (`/users/{uuid}` and `/users/{numeric_id}`, `?id=` vs `?uuid=`): the numeric path is often the unprotected legacy one.

```bash
python3 -I $S/id_extract.py artifacts/idor/A.har artifacts/idor/B.har | awk -F'\t' '{print $3}' | sort | uniq -c
idor GET "$T/api/users/$A_UUID"; idor GET "$T/api/users/$A_NUMERIC_ID"
```

- **Fail:** B accesses A's object with either ID form.
- **Refs:** `PS-IDOR` · `PS-AC` (lab: User ID controlled by request parameter, with unpredictable user IDs) · https://www.rfc-editor.org/rfc/rfc9562

### ID-07 · Encoded identifiers (base64, URL, hex, hashes, signed blobs) — `HIGH`
Tags: `idor` `encoding` · Subagent: ID-A

Decode opaque-looking values: base64 (`eyJ1c2VyX2lkIjoxMDQxfQ==` → `{"user_id":1041}`), base64 of `User:1041` (GraphQL global IDs), hex (`0x411`), URL/double-URL encoding, hashids, `md5(id)`/`sha1(email)` (unsalted hashes of known values are predictable). Re-encode B's ID the same way.

```bash
python3 -I $S/id_extract.py --decode 'eyJ1c2VyX2lkIjoxMDQxfQ=='
python3 -I $S/id_mutator.py 1042 --encodings-only
echo -n 1042 | md5sum; echo -n 'b-user@your-domain.test' | sha1sum
```

- **Fail:** re-encoded B identifier accepted with A's session (or vice versa).
- **Refs:** `CS-IDOR` (indirect references are not a substitute for access checks) · `WSTG-ATHZ-04`

### ID-15 · Wrapping / boundary identifiers (negative, zero, MAX_INT, overflow, type) — `MEDIUM`
Tags: `idor` `integer-overflow` `type-juggling` · Subagent: ID-A

Values that defeat ownership checks but resolve to real rows: `0`, `-1`, `-1042`, `2147483647`, `2147483648 + id` (32-bit wrap), `4294967296 + id`, `9223372036854775807`, `1042.0`, `1042e0`, `01042`, `0x412`, `"1042"` vs `1042`, `1042abc` (MySQL casts to 1042), `true`, `null`.

```bash
python3 -I $S/id_mutator.py 1042 --other 1041 | awk -F'\t' '$1 ~ /wrap|juggle/'
```

- **Fail:** any variant returns B's object to A, or bypasses an `id == session.user_id` comparison.
- **Refs:** https://cwe.mitre.org/data/definitions/190.html · `WSTG-ATHZ-04`

### ID-16 · Other users' UUIDs/GUIDs obtainable via information leaks — `HIGH`
Tags: `idor` `id-harvesting` `info-leak` · Subagent: ID-A

Where can an attacker get B's unpredictable ID without B's help? Check (with A's session, about B): public profiles, @mentions, comments, team/member lists, shared links, invite flows, search/autocomplete, error messages, other API responses (`"owner": {"id": …}`), JS bundles, OAuth "Sign in with" buttons/URLs exposing org UUIDs, emails/notifications, Referer headers, and archives (Wayback, OTX, URLScan, Common Crawl, VirusTotal via `waymore`/`gau`).

```bash
grep -rhoE '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}' artifacts/urls_all.txt | sort -u | head
python3 -I $S/id_extract.py --urls artifacts/urls_all.txt | grep -i uuid | head
```

- **Fail/Impact:** document the leak path for B's ID; combine with any authorization gap. A leak alone is `INFO` unless the ID is a bearer secret (share link, reset token).
- **Refs:** Joseph Thacker, *IDORs with unpredictable IDs are valid vulnerabilities* · https://github.com/xnl-h4ck3r/waymore · `PS-AC` (lab: unpredictable user IDs — ID leaked in blog author link)

### ID-26 · UUID / ObjectId / snowflake predictability — `HIGH`
Tags: `idor` `uuid-v1` `objectid` `predictability` · Subagent: ID-A

- **UUIDv1/v6/v7** embed a timestamp (+ MAC/node, clock sequence): given B's object created between two of A's (A creates X, B creates target, A creates Y), the target ID lies "sandwiched" between X and Y — small search space.
- **Nil / fixed UUIDs** (`00000000-0000-0000-0000-000000000000`, `11111111-…`) used for system/admin/test accounts.
- **MongoDB ObjectId** = 4-byte timestamp + 5-byte random-per-process + 3-byte counter → neighbours of your own IDs are predictable.
- **Snowflake / ULID / KSUID** are time-ordered.
- **v3/v5** are hashes of a name (namespace + email/username) → computable.

```bash
python3 -I $S/id_extract.py --decode e6e3422c-c82d-11ed-8761-3ff799965458   # version, timestamp, node
python3 -I $S/id_mutator.py 64a1f0c2e4b0a1b2c3d4e5f6                     # ObjectId neighbours (counter +/-)
```

- **Fail:** a predicted ID resolves to an object you own (prove with A/B objects created in sequence); fixed UUID accepted for privileged objects.
- **Refs:** https://www.rfc-editor.org/rfc/rfc9562 · Dana Epp, *Attacking predictable GUIDs when hacking APIs* · UUIDv1 "sandwich attack" research (Lupin & Holmes) · https://www.mongodb.com/docs/manual/reference/method/ObjectId/

### ID-27 · Hidden identifier parameters on profile/settings/payment endpoints — `HIGH`
Tags: `idor` `hidden-params` `param-mining` · Subagent: ID-A

Endpoints that act on "the current user" (`/settings/profile`, `/user/profile`, `/account/settings`, `/username`, `/profile`, payment/billing) may honour an undocumented `user_id`/`account_id`. Mine with Arjun / Param Miner / `fuzzparam` using `references/idor_param_names.txt` and values set to B's ID.

```bash
arjun -u "$T/api/settings/profile" -m GET --headers "$A_SESS" -w .agents/skills/idor/references/idor_param_names.txt -oJ $E/ID-27_arjun.json
ffuf -u "$T/api/settings/profile?FUZZ=$B_ID" -H "$A_SESS" -w .agents/skills/idor/references/idor_param_names.txt -mc all -fs <baseline_size> -rate 5
```

- **Fail:** a discovered parameter switches the target to B.
- **Refs:** https://github.com/s0md3v/Arjun · https://github.com/0xsapra/fuzzparam · https://github.com/PortSwigger/param-miner (Param Miner)

---

## ID-B — Identifier Locations

### ID-01 · IDOR in URL path parameters (`/users/123/profile`) — `HIGH`
Tags: `idor` `path` · Subagent: ID-B

```bash
idor GET "$T/api/users/$A_ID/profile"     # run with B and anon
```
Also: path traversal inside the object path (`/users/$B_ID/../$A_ID`), trailing segments (`/users/$A_ID/`, `/users/$A_ID.json`), and the same object under a parent you own (`/orgs/$B_ORG/projects/$A_PROJECT`).
- **Refs:** `PS-IDOR` · `WSTG-ATHZ-04` · `API1`

### ID-02 · IDOR in query parameters (`?user_id=123&doc_id=456`) — `HIGH`
Tags: `idor` `query` · Subagent: ID-B

Change each ID independently (user owned by B, doc owned by A, and vice versa) — mixed-ownership combinations often pass a check on only one parameter. Also duplicate the parameter (`?doc_id=$B_OBJ&doc_id=$A_OBJ`, `doc_id[]=`).
- **Refs:** `PS-AC` (lab: User ID controlled by request parameter) · `WSTG-ATHZ-04`

### ID-03 · IDOR in POST form parameters — `HIGH`
Tags: `idor` `form-body` · Subagent: ID-B

`application/x-www-form-urlencoded` and `multipart/form-data` fields (`user_id`, `account`, hidden inputs). Try moving the ID between body and query (`POST /update?user_id=$A_ID` with body `user_id=$B_ID`) — frameworks merge them differently.
- **Refs:** `WSTG-ATHZ-04` · `PS-IDOR`

### ID-04 · IDOR in JSON request bodies — `HIGH`
Tags: `idor` `json` · Subagent: ID-B

```bash
idor POST "$T/api/orders/view" "{\"order_id\":$A_OBJ}"
idor POST "$T/api/orders/view" "{\"order_id\":[$A_OBJ]}"
idor POST "$T/api/orders/view" "{\"order_id\":{\"id\":$A_OBJ}}"
idor POST "$T/api/orders/view" "{\"order_id\":$B_OBJ,\"order_id\":$A_OBJ}"     # duplicate key
```
Also switch `Content-Type` to form/XML when the server accepts multiple parsers.
- **Refs:** `API1` · `WSTG-ATHZ-04`

### ID-05 · IDOR in HTTP headers (`X-User-Id`, `X-Account-Id`, `X-Requester-Id`) — `CRITICAL`
Tags: `idor` `headers` `trust-boundary` · Subagent: ID-B

Internal identity headers set by gateways are sometimes honoured when sent by the client.

```bash
for h in X-User-Id X-UserId X-Account-Id X-Requester-Id X-Customer-Id X-Tenant-Id X-Org-Id X-Impersonate X-Forwarded-User X-Remote-User X-Auth-User; do
  curl -sk -o /dev/null -w "$h %{http_code} %{size_download}\n" -H "$B_SESS" -H "$h: $A_ID" "$T/api/me"; sleep 0.5
done
```
- **Fail:** response switches to A's data.
- **Refs:** `CS-AUTHZ` (do not trust client-supplied identity) · `API1`

### ID-11 · IDOR by modifying cookie values — `HIGH`
Tags: `idor` `cookie` · Subagent: ID-B

Non-session cookies carrying identity/state: `user_id=`, `uid=`, `account=`, `org=`, `role=`, base64/JSON cookies, unsigned framework cookies (see `session-management` SM-35).
- **Fail:** changing the cookie switches the acting/viewed user.
- **Refs:** `PS-AC` (lab: User role controlled by request parameter — cookie `Admin=false`) · `WSTG-ATHZ-04`

### ID-14 · IDOR via parameter addition — `HIGH`
Tags: `idor` `parameter-addition` · Subagent: ID-B

Add an ID the request doesn't normally carry: `GET /api/me` → `/api/me?user_id=$A_ID`, `/api/me/$A_ID`; JSON `{"name":"x"}` → `{"name":"x","user_id":A}`; `PUT /api/profile` with `"id": A`. Derive names from other endpoints' responses (if `/api/orders` returns `customer_id`, add `customer_id` to `/api/profile`).
- **Fail:** the added parameter overrides the session identity.
- **Refs:** `API3` · `WSTG-ATHZ-04`

### ID-19 · IDOR in nested objects (`user.profile.id`, `order.item.id`) — `HIGH`
Tags: `idor` `nested` `json-path` · Subagent: ID-B

Parent owned by B but child owned by A: `{"order":{"id":B_ORDER,"items":[{"id":A_ITEM}]}}`; `/orders/$B_ORDER/items/$A_ITEM`; `{"user":{"id":B_ID,"address":{"id":A_ADDRESS}}}`. Servers often authorise the parent only.
- **Fail:** child object of another owner read/modified through your parent.
- **Refs:** `API1` · `API3`

---

## ID-C — Methods, Versions & Channels

### ID-10 · IDOR with different HTTP methods (GET/PUT/PATCH/DELETE) — `CRITICAL`
Tags: `idor` `http-methods` · Subagent: ID-C

Read may be protected while write/delete is not (or vice versa). On B's **throwaway** object: try `PUT`, `PATCH`, `DELETE`, `POST` with `_method=`/`X-HTTP-Method-Override`, and `HEAD`/`OPTIONS` from A.

```bash
curl -sk -X PATCH -H "$A_SESS" -H 'Content-Type: application/json' -d '{"title":"bbtest-idor"}' "$T/api/notes/$B_THROWAWAY" -w '\n%{http_code}\n'
curl -sk -X DELETE -H "$A_SESS" "$T/api/notes/$B_THROWAWAY" -w '\n%{http_code}\n'          # own throwaway object only
```
- **Fail:** B's object changed/deleted by A (verify from B's view).
- **Refs:** `PS-AC` (Method-based access control can be circumvented) · `API1`

### ID-12 · IDOR in WebSocket messages — `HIGH`
Tags: `idor` `websocket` `real-time` · Subagent: ID-C

Messages like `{"action":"subscribe","channel":"user:1041"}`, `{"type":"get_history","conversation_id":…}`, `{"cmd":"READY"}` (PortSwigger chat lab). Replay from A's socket with B's IDs (Burp WebSocket Repeater). Check subscription to other users' channels and per-message authorization after connect.
- **Fail:** A receives B's events/history or performs actions on B's objects.
- **Refs:** https://portswigger.net/web-security/websockets · `PS-IDOR` (lab: Insecure direct object references — chat transcripts)

### ID-20 · Cross-application IDOR within the same organisation — `HIGH`
Tags: `idor` `cross-app` `shared-backend` · Subagent: ID-C

Same object IDs across products/subdomains (main app, admin, mobile API, partner portal, support desk, legacy `v1.`, `beta.`). An ID protected in the main app may be readable via `support.target.com/api/tickets/{id}` or the mobile API.
- **Fail:** A's object accessible to B through a sibling application.
- **Refs:** `API1` · `WSTG-ATHZ-04`

### ID-24 · IDOR in API-key-scoped resources — `HIGH`
Tags: `idor` `api-key` `scope` · Subagent: ID-C

Create API keys/tokens for A and B (and scoped keys: read-only, project-limited). Does B's key access A's resources? Does a project-scoped key reach other projects? Can a key read/rotate/revoke **other** keys (`/api/keys/{id}`)?
- **Fail:** key scope not enforced at object level.
- **Refs:** `API1` · https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/

### ID-25 · IDOR across API versions (v1 vs v2) — `HIGH`
Tags: `idor` `api-versioning` · Subagent: ID-C

```bash
for v in v1 v2 v3 v0 beta internal; do curl -sk -o /dev/null -w "$v %{http_code} %{size_download}\n" -H "$B_SESS" "$T/api/$v/orders/$A_OBJ"; done
```
Also `/api/orders` vs `/api/v2/orders`, `Accept: application/vnd.target.v1+json`, `?api-version=2019-01-01`, mobile API hosts.
- **Fail:** older/other version lacks the check.
- **Refs:** https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ · `API1`

### ID-28 · Format / extension / content negotiation switching — `MEDIUM`
Tags: `idor` `format` `content-negotiation` · Subagent: ID-C

`/users/$A_ID` protected but `/users/$A_ID.json`, `.xml`, `.csv`, `.pdf`, `?format=json`, `?export=1`, `Accept: application/json`, `/print/…`, `/embed/…`, `/preview/…`, `/api/…/raw` not.
- **Fail:** alternate representation returns A's data to B.
- **Refs:** `WSTG-ATHZ-04`

### ID-29 · GraphQL object-level authorization — `HIGH`
Tags: `idor` `graphql` `node` · Subagent: ID-C

`node(id:)` / `nodes(ids:)` with global IDs (`base64("User:1041")`), direct queries (`user(id:)`, `order(id:)`), nested edges (`me { team { members { email } } }`), aliases to batch many IDs, and mutations taking IDs. Use introspection/InQL to list ID-taking fields.

```graphql
query { a: node(id:"VXNlcjoxMDQx") { ... on User { email } }  b: order(id: 1041) { total owner { email } } }
```
- **Fail:** A's nodes returned to B.
- **Refs:** https://portswigger.net/web-security/graphql · `API1` · `api-security` skill

### ID-32 · IDOR through OAuth / third-party integrations and webhooks — `HIGH`
Tags: `idor` `oauth` `integrations` `webhooks` · Subagent: ID-C

Integration endpoints keyed by IDs: connected-app listings (`/integrations/{id}`), OAuth client/grant management, webhook configs/deliveries (`/webhooks/{id}/deliveries` often contain full payloads), "Sign in with" org UUIDs, PII returned via OAuth-connected data (monke.ie *OAuth IDOR → PII*).
- **Fail:** B reads A's integration secrets, webhook payloads, or connected-account PII.
- **Refs:** https://monke.ie/oauth-idor-pii/ · `oauth-sso` skill · `API1`

---

## ID-D — Feature-Specific Objects

### ID-09 · IDOR in file download/upload endpoints — `HIGH`
Tags: `idor` `files` `attachments` · Subagent: ID-D

Downloads (`/download?file=`, `/files/{id}`, `/attachments/{uuid}`, signed URLs, `/transcripts/2.txt`); uploads that take an ID (`PUT /files/{id}` overwriting B's file; upload to `?folder_id=` / `?user_id=` of A). Check direct object-storage URLs (S3/GCS keys with sequential names; pre-signed URLs with long expiry reusable by anyone).

```bash
idor GET "$T/api/files/$A_FILE/download"
curl -sk -H "$B_SESS" -F "file=@bbtest.txt" "$T/api/files/upload?folder_id=$A_FOLDER" -w '\n%{http_code}\n'
```
- **Fail:** B downloads A's file or writes into/over A's storage.
- **Refs:** `PS-IDOR` (lab: chat transcript download by incrementing filename) · `WSTG-ATHZ-04`

### ID-13 · IDOR in batch / bulk operations — `HIGH`
Tags: `idor` `bulk` `batch` · Subagent: ID-D

`{"ids":[B1,B2,A1]}`, `/api/bulk?ids=…`, GraphQL batching, CSV import with IDs, JSON-RPC batch, `/batch` endpoints that fan out sub-requests. Servers frequently check only the first item or only that the list is non-empty.
- **Fail:** A's object included in B's bulk result/action.
- **Refs:** `API1` · `PS-AC`

### ID-17 · IDOR in search and filter parameters — `HIGH`
Tags: `idor` `search` `filter` · Subagent: ID-D

Filters like `owner_id=`, `user=`, `org=`, `created_by=`, `filter[account_id]=`, `q=owner:…`, Elasticsearch/Lucene query strings (`q=*`, `user_id:*`), OData `$filter=`. Also check whether search results leak fields of objects you can't open.
- **Fail:** B lists A's objects/fields via search/filter.
- **Refs:** `API1` · `API3`

### ID-18 · IDOR in pagination parameters (offset, cursor) — `MEDIUM`
Tags: `idor` `pagination` `cursor` · Subagent: ID-D

Cursors often encode IDs/owner (`base64({"last_id":1041,"user":1042})`): decode, change owner, re-encode. Large `limit`/`per_page` or negative `offset` may drop the owner filter. Use small ranges near your own IDs.

```bash
python3 -I $S/id_extract.py --decode "$CURSOR"
```
- **Fail:** cursor/offset tampering returns A's objects to B.
- **Refs:** `API1` · `WSTG-ATHZ-04`

### ID-21 · Receipts / invoices / orders by sequential number — `HIGH`
Tags: `idor` `invoice` `sequential` · Subagent: ID-D

Invoice/receipt/order numbers (`INV-2026-001041`), PDF links, "public" receipt URLs with short tokens, email receipt links. Create one paid/free order in A and B to get adjacent numbers; test cross-access only between those.
- **Fail:** B opens A's invoice/receipt (PII, address, payment details).
- **Refs:** `WSTG-ATHZ-04` · `API1`

### ID-22 · IDOR in messaging / comment endpoints — `HIGH`
Tags: `idor` `messages` `comments` · Subagent: ID-D

Read conversations (`/conversations/{id}`), send into another conversation, edit/delete others' comments/messages, read private/draft/hidden comments, attachment IDs inside messages, reactions/read-receipts revealing activity.
- **Fail:** A's private messages readable or A's comments editable by B.
- **Refs:** `PS-IDOR` · `API1`

### ID-23 · IDOR in notification subscription endpoints — `MEDIUM`
Tags: `idor` `notifications` `subscriptions` · Subagent: ID-D

Subscribe B to A's object events (`/watch`, `/subscribe?object_id=`, webhook/email/push subscriptions, `PUT /notifications/settings` with `user_id`), unsubscribe A (`/unsubscribe?uid=` links), list A's notifications.
- **Fail:** B receives notifications about A's objects, or changes A's notification settings.
- **Refs:** `API1`

---

## ID-E — Roles, Writes & Indirect References

### ID-08 · IDOR across user roles (admin vs user vs guest) — `HIGH`
Tags: `idor` `rbac` `horizontal-to-vertical` · Subagent: ID-E

Replay C's (admin/manager) object requests with A's session; replay A's object requests with a guest/viewer; access admin-owned objects (`/api/users/{admin_id}`) as A. Horizontal-to-vertical: A reads admin's object containing credentials/API keys (PortSwigger lab: *User ID controlled by request parameter with password disclosure*). Hand pure function-level checks (`/admin/*`) to `access-control`.
- **Fail:** lower role reads/modifies higher-role objects.
- **Refs:** `PS-AC` (horizontal to vertical privilege escalation) · `WSTG-ATHZ-04`

### ID-30 · Object reassignment via owner fields — `CRITICAL`
Tags: `idor` `mass-assignment` `ownership` · Subagent: ID-E

On your own object (A), set `owner_id`/`user_id`/`account_id`/`org_id`/`team_id` to B (push into victim's account — spam, phishing, storage abuse) or, on update/create, to pull: `PUT /api/projects/$A_PROJECT {"org_id": B_ORG}` and `POST /api/memberships {"user_id": A, "org_id": B_ORG, "role":"admin"}`.
- **Fail:** ownership/membership changes across accounts or tenants.
- **Refs:** `API3` · https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

### ID-31 · Second-order (indirect) IDOR — `HIGH`
Tags: `idor` `second-order` `stored-reference` · Subagent: ID-E

Store A's object ID inside one of B's own objects, then make the server dereference it later: B sets `avatar_file_id = A_FILE`, `default_address_id = A_ADDR`, `template_id = A_TEMPLATE`, `report.source_id = A_DATASET`; then B views/exports/prints its own object, or triggers an email/PDF/webhook that resolves the reference.
- **Fail:** A's data appears in B's rendered/exported object.
- **Refs:** `API1` · `WSTG-ATHZ-04`

### ID-33 · Array, wildcard, list and type-juggling identifiers — `HIGH`
Tags: `idor` `wildcard` `arrays` `hpp` · Subagent: ID-E

`id=*`, `id=%`, `id=_`, `id[]=B&id[]=A`, `{"id":[B,A]}`, `{"id":{"$in":[B,A]}}`, `{"id":{"$ne":0}}`, `id=B,A`, `id=B%26id%3DA`, `id=A%00`, `id=B;A`. `id_mutator.py` emits all.
- **Fail:** list/wildcard returns or acts on A's objects.
- **Refs:** `PS-AC` · https://portswigger.net/web-security/nosql-injection · `WSTG-ATHZ-04`

### ID-34 · Multi-step flows with authorization on one step only — `HIGH`
Tags: `idor` `multi-step` `workflow` · Subagent: ID-E

Checkout/confirm, approval, delete-confirmation, export-then-download, upload-then-attach, password/email change confirmations. Capture B's legitimate step 1 → step 2 → step 3, then replay the **later** step with A's object ID (PortSwigger lab: *Multi-step process with no access control on one step*).
- **Fail:** final step acts on A's object.
- **Refs:** `PS-AC` (multi-step processes) · `business-logic-vulns` skill

### ID-35 · Blind IDOR and leakage in redirects / errors / side effects — `MEDIUM`
Tags: `idor` `blind` `redirect-leak` · Subagent: ID-E

The response says "denied" but leaks anyway: body of a `302` redirect contains A's data (PortSwigger lab: *data leakage in redirect*), different errors for existing vs non-existing objects (`403` vs `404`), timing, counts (`"total": 1`), `ETag`/`Content-Length` that match A's object, or **side effects** (B's request triggers an email/notification to A, or changes A's object while returning 403).

```bash
curl -sk -H "$B_SESS" "$T/my-account?id=$A_ID" -D - -o $E/ID-35_body.txt; grep -i "a-user@your-domain.test" $E/ID-35_body.txt
```
- **Fail:** sensitive data in the denied/redirect response, or a write side effect occurs. Existence-only oracles are usually `INFO`.
- **Refs:** `PS-AC` (lab: User ID controlled by request parameter with data leakage in redirect) · `WSTG-ATHZ-04`

---

## Further reading (community)

- PortSwigger support: *Using Burp to test for insecure direct object references* — https://portswigger.net/support/using-burp-to-test-for-insecure-direct-object-references
- Aon Cyber Labs: *Finding more IDORs – tips and tricks* — https://www.aon.com/cyber-solutions/aon_cyber_labs/finding-more-idors-tips-and-tricks/
- *IDOR attack vectors, exploitation, bypasses and chains* (Notion) — https://www.notion.so/IDOR-Attack-vectors-exploitation-bypasses-and-chains-0b73eb18e9b640ce8c337af83f397a6b
- *Some ways to find more IDOR* — https://16521092.medium.com/some-ways-to-find-more-idor-da16c93954e5
- Burp extensions: https://github.com/PortSwigger/autorize · https://github.com/PortSwigger/auth-analyzer
- CWE-639: https://cwe.mitre.org/data/definitions/639.html

## Ledger template (`artifacts/idor/idor_checklist_35.tsv`)

```
check_id	status	severity	finding_id	evidence_path	notes
ID-01
...
ID-35
```
