---
name: graphql-audit
description: Audit authorized GraphQL APIs across 15 checks — introspection exposing the full schema, missing query depth limits, batch query abuse and rate-limit bypass, alias abuse, directive abuse and overloading, mutation access control, subscription security, injection through arguments and variables, field-suggestion schema leaks, verbose error messages, DoS via deeply nested or complex queries (approval only), IDOR in queries and mutations, field-level authorization, query complexity limits, and persisted-query (APQ/allowlist) security — with a scope-gated probe that discovers endpoints, fingerprints the engine, tests GET/form/text-plain transport (CSRF), pulls and summarizes the schema (sensitive fields, dangerous mutations, subscriptions), checks suggestions, bounded depth/batch/alias/directive limits, error disclosure, APQ registration, marker injection in arguments, and compares the same operations across two own accounts and anonymous for authorization and IDOR. Triggers on "GraphQL", "/graphql", "introspection", "__schema", "GraphiQL", "Apollo", "Hasura", "batching", "alias", "depth limit", "persisted query", "APQ", "subscription", "graphql-ws", "clairvoyance", "InQL", "graphw00f", or when route_target.py routes operationName/variables/query parameters.
---

# GraphQL Security Audit (15 checks)

GraphQL puts the whole API behind one endpoint, so authorization must happen per resolver and per field, and cost must be limited per query rather than per request. Most findings fall into three groups: the schema leaks (introspection, suggestions, errors), cost controls are missing (depth, complexity, batching, aliases, directives), and authorization is inconsistent (mutations, fields, IDs, subscriptions).

- Checklist: `references/graphql_checklist.md` (GQL-001 to GQL-015, variants, engine notes, severity guide).
- Query templates: `references/graphql_queries.md` (introspection, depth, batching, aliases, directives, APQ, injection, subscriptions, CSRF transports).
- Tracker: `references/graphql_tracker.md`.
- `scripts/gql_probe.py`: endpoint discovery, engine fingerprint, transports, introspection with schema summary (`--schema-out`), suggestions, bounded depth/batch/alias/directive tests, error disclosure, APQ, argument injection markers (`--inject-query` with `FUZZ`), and authorization comparison (`--ops-file` run as account A, account B, and anonymous).
- Related: `api-security` (API-X-001 to API-X-007), `websocket-audit` (subscriptions over WebSocket), `idor`, `access-control`, `sqli`, `nosql-injection-audit`, `csrf-audit` (XSRF-019), `error-handling-audit` (EH-010), `resource-exhaustion`, `ssrf-audit` (URL arguments).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Find endpoints: JS bundles (`gql\``, `operationName`, `/graphql`), proxy history, and `gql_probe.py --discover` on each in-scope host (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`, `/graphiql`, `/playground`, `/altair`, `/console`, `/v1/explorer`).
3. Baseline and schema:

   ```bash
   python3 .agents/skills/graphql-audit/scripts/gql_probe.py --target example.com \
     --url https://api.example.com/graphql --header 'Authorization: Bearer OWN_A' \
     --schema-out artifacts/example.com/graphql_schema.json --out artifacts/example.com/graphql.json
   ```

   If introspection is off, use field suggestions (the probe reports "Did you mean") and Clairvoyance to rebuild the schema, plus operations seen in JS and traffic.
4. Load the schema into GraphQL Voyager or InQL to map types, sensitive fields, mutations, and ID arguments.
5. Authorization (GQL-006, GQL-012, GQL-013): write the operations to test into an ops file (one JSON object per line: `{"query": "...", "variables": {...}}`) using account B's object IDs, then:

   ```bash
   python3 .agents/skills/graphql-audit/scripts/gql_probe.py --target example.com --url https://api.example.com/graphql \
     --header 'Authorization: Bearer OWN_A' --auth-b 'Authorization: Bearer OWN_B' --ops-file ops.jsonl --skip-recon
   ```

   Mutations in the ops file run only with `--allow-mutations` and must be harmless operations on your own objects.
6. Injection (GQL-008): `--inject-query 'query { user(id: "FUZZ") { id } }'` sends quote, boolean, NoSQL, and template markers; follow up with sqli/nosql rules.
7. Cost controls (GQL-002, 003, 004, 005, 011, 014): the probe sends bounded tests (depth up to 12, 10 aliases, 5 batched operations, 10 repeated directives). Anything larger is authorized-only.
8. Subscriptions (GQL-007): list subscription fields from the schema; test auth and per-topic authorization over WebSocket with websocket-audit (`graphql-ws` framing).
9. Persisted queries (GQL-015): check APQ registration of arbitrary queries and whether an allowlist can be bypassed by sending `query` directly.
10. Save findings to `artifacts/<target>/graphql.json` and the tracker to `artifacts/<target>/graphql_tracker.md`.

## Classes

- `passive`: JS, traffic, and schema review.
- `bounded`: introspection, suggestions, small depth/alias/batch/directive probes, error probes, APQ check with `{__typename}`, marker injection, authorization comparisons with your own two accounts.
- `authorized-only`: large or recursive queries meant to measure DoS, brute force via batching/aliases against real users, mutations on other users' data, and subscription floods.

## Rules

- Never run destructive mutations (delete, transfer, role changes) on anything but your own disposable objects.
- Batching and alias tests use `__typename` or your own login only; never brute-force other users' credentials or OTPs.
- Stop if response times rise sharply during cost tests.

## Mitigation guidance for reports

- Disable introspection and suggestions in production (or restrict to authenticated staff); mask errors (no stack traces, no SQL).
- Depth limit, cost/complexity analysis, alias and batch limits, directive-count limits, timeouts, pagination maximums.
- Authorization in resolvers for every object and field (not only at the gateway); consistent checks for queries, mutations, and subscriptions.
- Rate limit per operation and per cost unit, not per HTTP request.
- Persisted query allowlist (reject unknown queries); APQ only with an allowlist or registration disabled for clients.
- Require `application/json` POST (no GET or form bodies for mutations) and CSRF protection when using cookies.
- Parameterized data access in resolvers; validate scalar inputs.

## Sources

OWASP GraphQL Cheat Sheet and WSTG-APIT-01, PortSwigger Web Security Academy GraphQL labs, Apollo/graphql-js/graphql-java/Hasura security docs, "GraphQL Batching Attack" research, graphw00f, InQL, Clairvoyance, GraphQL Cop, CWE-200, CWE-285, CWE-400, CWE-770.
