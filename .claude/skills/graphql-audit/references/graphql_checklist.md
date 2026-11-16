# GraphQL Security Checklist

Class key: `passive` = JS, traffic, schema review. `bounded` = introspection, suggestions, small cost probes, error probes, APQ with `__typename`, markers, own-account authz comparisons. `authorized-only` = DoS-scale queries, brute force against real users, other users' mutations, subscription floods.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GQL-001 | Introspection | Introspection query reveals the full schema (types, queries, mutations, subscriptions, deprecated fields) | bounded | gql_probe.py full IntrospectionQuery; also `__type(name:"Query")` when `__schema` is blocked; GET and alternate transports |
| GQL-002 | Depth | No query depth limit (DoS potential) | bounded | gql_probe.py nested query at depths 3/6/9/12; accepted at 12 with no depth error = finding lead |
| GQL-003 | Batching | Array batching accepted: many operations per HTTP request bypass rate limits (login, OTP, coupon) | bounded | gql_probe.py batch of 5 `__typename`; for impact, batch own-login attempts only |
| GQL-004 | Aliases | Alias abuse: same field many times in one query bypasses per-request rate limits | bounded | gql_probe.py 10 aliases; impact with own login/OTP only |
| GQL-005 | Directives | Directive abuse: unknown directives disclose engine/schema in errors; repeated directives accepted (overloading); `@include/@skip` toggles bypass field checks; custom directives (`@debug`, `@auth`) exposed | bounded | gql_probe.py unknown directive and 10 repeated `@include(if:true)` |
| GQL-006 | Mutations | Mutation access control: mutations work anonymously, as low-privilege user, or on others' objects | bounded | gql_probe.py `--ops-file` with harmless own mutations (`--allow-mutations`); compare A, B, anonymous |
| GQL-007 | Subscriptions | Subscription security: anonymous subscriptions, per-topic authorization missing, cross-tenant events, CSWSH on the subscription socket | bounded | Schema subscription list; websocket-audit with graphql-ws framing |
| GQL-008 | Injection | Injection in arguments and variables (SQL, NoSQL, OS, SSRF via URL args, template) | bounded | gql_probe.py `--inject-query` markers; follow sqli/nosql-injection-audit/ssrf-audit rules |
| GQL-009 | Suggestions | Field suggestions ("Did you mean ...") leak schema when introspection is off | bounded | gql_probe.py typo fields on Query and known types; Clairvoyance to rebuild schema |
| GQL-010 | Errors | Error messages reveal internals: stack traces in `extensions.exception`, SQL, file paths, resolver names, backend URLs | bounded | gql_probe.py malformed documents and wrong variable types; error-handling-audit EH-010 |
| GQL-011 | DoS | DoS via deeply nested or complex queries (circular fragments, recursive types, huge `first:` arguments, field duplication) | authorized-only | Only with approval and a test window; report bounded evidence from GQL-002/GQL-014 otherwise |
| GQL-012 | IDOR | IDOR in queries and mutations: object IDs (incl. global/relay IDs, base64 `User:123`) of other accounts accepted | bounded | `--ops-file` with account B's IDs while authenticated as A; decode relay IDs and try neighbours of own IDs only for proof |
| GQL-013 | Field authz | Field-level authorization: sensitive fields (email, phone, role, tokens, internal notes) readable on other users' objects or by low-privilege roles | bounded | `--ops-file` selecting sensitive fields on B's objects as A and anonymous |
| GQL-014 | Complexity | No query cost/complexity limits (large `first`/`limit`, many fields, fragments) | bounded | gql_probe.py records whether moderate cost (alias × depth) is refused; large values authorized-only |
| GQL-015 | Persisted queries | Persisted query security: APQ lets clients register arbitrary queries; allowlist bypass by sending `query`; hash-only replays of privileged operations | bounded | gql_probe.py APQ check with `{__typename}` |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GQL-V-001 | Transport | GET queries or `application/x-www-form-urlencoded` / `text/plain` POSTs accepted (CSRF on mutations with cookies) | bounded | gql_probe.py transports; csrf-audit XSRF-019 |
| GQL-V-002 | IDE | GraphiQL, Playground, Altair, Voyager, Apollo Sandbox exposed in production | bounded | `--discover` |
| GQL-V-003 | Fragments | Circular fragments accepted (validation bypass) | authorized-only | Report only with approval |
| GQL-V-004 | Introspection bypass | Introspection blocked by regex but allowed with whitespace/newline (`__schema\n{`), GET, or `__type` | bounded | gql_probe.py variants |
| GQL-V-005 | Debug | Debug/tracing extensions enabled (`extensions.tracing`, Apollo `debug`, Hasura `x-hasura-*` headers honored) | bounded | Response extensions; Hasura `x-hasura-role` header with own token |
| GQL-V-006 | Federation | `_service { sdl }` and `_entities` exposed on Apollo Federation subgraphs (bypass gateway authz) | bounded | Query `_service{sdl}` on gateway and subgraphs |
| GQL-V-007 | Uploads | `Upload` scalar / multipart spec allows CSRF and file upload issues | bounded | file-upload-audit |
| GQL-V-008 | Deprecated | Deprecated fields still resolve without new checks | bounded | introspection `includeDeprecated: true` |
| GQL-V-009 | Rate limit | Rate limits per HTTP request only (combine with GQL-003/004) | bounded | Own login with batched wrong passwords (≤ 5) to show bypass |

## Engine notes (graphw00f-style hints)

| Engine | Hint |
|---|---|
| Apollo Server | `extensions.code: GRAPHQL_VALIDATION_FAILED`, `PERSISTED_QUERY_NOT_FOUND`, Apollo Sandbox landing page |
| graphql-js / express-graphql | `Syntax Error: Expected Name, found <EOF>.` |
| graphql-java | `Validation error (FieldUndefined@[...])`, `InvalidSyntax` |
| Hasura | `x-hasura-*` headers, `"code": "validation-failed"`, `/v1/graphql`, `/console` |
| Graphene (Python) | `Cannot query field "x" on type "Query".` with Django/Flask stack |
| HotChocolate (.NET) | `HC0011`, Banana Cake Pop IDE |
| gqlgen (Go) | `"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}` + Go errors |
| AWS AppSync | `x-amzn-requestid`, `"errorType"` |
| Shopify / GitHub (public) | Rate-limit cost fields in `extensions.cost` |

## Severity guide

| Finding | Typical rating |
|---|---|
| IDOR / field-level authz exposing PII or acting on others' objects | High–Critical |
| Mutation without auth or with low privilege | High–Critical |
| Batching/alias brute force of OTP or login proven on own account | Medium–High |
| Injection via arguments | High–Critical |
| Introspection enabled (public API with documented schema) | Informational |
| Introspection revealing hidden admin/internal operations | Low–Medium (higher with authz bugs) |
| No depth/complexity limits (bounded evidence only) | Low–Medium |
| Verbose errors with stack traces | Low–Medium |
| Arbitrary APQ registration bypassing an allowlist | Medium |

## Cross-references

| GQL row | Related rows |
|---|---|
| GQL-001 | api-security API-X-001 |
| GQL-009 | API-X-002 |
| GQL-003, GQL-004 | API-X-003, resource-exhaustion |
| GQL-002, GQL-011, GQL-014 | API-X-004 |
| GQL-012, GQL-013 | API-X-005, idor, access-control |
| GQL-008 | API-X-006, sqli, nosql-injection-audit |
| GQL-006 | API-X-007, access-control |
| GQL-007 | websocket-audit |
| GQL-010 | error-handling-audit EH-010 |
| GQL-V-001 | csrf-audit XSRF-019 |
