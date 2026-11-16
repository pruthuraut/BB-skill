---
name: idor
description: Audit authorized applications and APIs for Insecure Direct Object References / Broken Object Level Authorization across 35 checks — every identifier location (path, query, form, JSON, nested objects, headers, cookies, added parameters), identifier types (sequential, UUID v1/v4/nil, ObjectId, encoded base64/hex), wrapping and type-juggling values, HTTP methods and API versions, files, bulk operations, search/filter/pagination, invoices, messages, notifications, WebSockets, GraphQL, API-key scope, cross-application objects, object reassignment, second-order references, multi-step flows, and unpredictable-ID harvesting from archives and responses. Built on PortSwigger access-control/IDOR labs, OWASP WSTG-ATHZ-04, the OWASP IDOR Prevention and Authorization cheat sheets and OWASP API Security Top 10 (API1/API3 BOLA/BOPLA). Use with two or more self-owned accounts.
---

# IDOR / Broken Object Level Authorization

Prove that the server authorises **every object access against the caller's identity**, not against the identifier the caller supplies (CWE-639). The method is always the same: capture a request that touches an object owned by account **A**, replay it with account **B**'s credentials (and with none), and compare. What changes from check to check is *where* the identifier lives, *what form* it takes, and *which feature* the object belongs to.

Primary methodology sources:

- PortSwigger Web Security Academy — *Insecure direct object references*, *Access control vulnerabilities* (horizontal, horizontal-to-vertical, data leakage in redirect, unpredictable user IDs, multi-step processes), *Using Burp to test for IDOR*; GraphQL and WebSocket topics; Burp extensions **Autorize** and **Auth Analyzer**
- OWASP WSTG v4.2 **WSTG-ATHZ-04** Testing for Insecure Direct Object References; OWASP IDOR Prevention and Authorization cheat sheets; OWASP API Security Top 10 2023 **API1 BOLA**, **API3 BOPLA**
- RFC 9562 (UUID formats), research on predictable GUIDs (Dana Epp), UUIDv1 "sandwich" attacks, "IDORs with unpredictable IDs are valid vulnerabilities" (Joseph Thacker), Aon *Finding more IDORs*

## Authorization and safety boundary

- Pass the scope gate before any request.
- Test **between your own accounts only**: `A` and `B` (same role, different users), `C` (different role, e.g. viewer/admin/guest if obtainable), `A2` (a user in a second organisation/tenant). Every object you reference belongs to one of them.
- **Never enumerate real users' objects.** For sequential IDs, demonstrate with your own two objects (e.g., invoice 1041 owned by A, 1042 owned by B). If a request accidentally returns someone else's data, stop, do not store or reuse it, record only that it happened (status, size, redacted field names), and report.
- **Writes and deletes target only objects you own.** Create a throwaway object in B, then try to modify/delete it from A. `idor_replay.py` never sends `DELETE` and only replays non-GET methods with an explicit flag.
- Rate: interactive pace (≤ 2 req/s). Bulk/batch and pagination checks use small ranges containing your own IDs.
- Leak-source OSINT (Wayback, OTX, URLScan, Common Crawl, VirusTotal) sends the target domain to those services; use it only where the program allows passive recon, and treat discovered IDs of real users as **evidence of exposure, not test inputs**.

## Inputs

1. Proxy HAR for each account covering every feature (create, read, update, share, export, delete) — record A first, then B doing the same actions so you hold both accounts' object IDs
2. `artifacts/discovered_endpoints.txt`, `artifacts/discovered_parameters.json`, JS bundles from `jsrecon`, API specs from `api-security`
3. Historical URLs from `contentdiscovery` / `waymore` (`artifacts/urls_all.txt`) for ID harvesting
4. Role/tenant model from `access-control` (who should see what)

## Workflow

1. **Build the object inventory.** `python3 -I scripts/id_extract.py A.har B.har --urls artifacts/urls_all.txt > artifacts/idor/id_inventory.tsv` lists every identifier with its location (path/query/form/JSON path/header/cookie), type (int, UUID vN, ObjectId, base64, hex, hash) and decoded info (UUIDv1 timestamp, ObjectId time, nil/fixed UUIDs). Write `artifacts/idor/object_matrix.md`: object type → owner A id, owner B id, endpoints that read/write it, expected access rule.
2. **Automated cross-account replay.** `scripts/idor_replay.py` replays A's captured requests with B's session and with no session, flags responses that are the same/similar or that contain A's markers (email, name, IDs). Equivalent to Burp *Autorize*/*Auth Analyzer*; use those in parallel during manual browsing.
3. **Manual ledger.** Work through [references/checklist_35.md](references/checklist_35.md) with the subagent split below. Use `scripts/id_mutator.py` for value tricks (wrapping, encoding, type juggling, arrays, wildcards, UUID neighbours) and [references/idor_param_names.txt](references/idor_param_names.txt) for parameter addition.
4. **Confirm and classify.** Manually verify every automated hit (same-length responses are often error pages). Classify: read / write / delete / function; horizontal / vertical / cross-tenant; ID predictability (sequential, guessable, leaked, unpredictable).
5. **Report** artifacts and update `[ N / 35 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **ID-A** Identifier Discovery & Predictability | UUID vs sequential, encoded IDs, wrapping values, leaked UUIDs, UUID/ObjectId predictability, hidden ID parameters | 06, 07, 15, 16, 26, 27 |
| **ID-B** Identifier Locations | path, query, form body, JSON body, headers, cookies, parameter addition, nested objects | 01, 02, 03, 04, 05, 11, 14, 19 |
| **ID-C** Methods, Versions & Channels | HTTP methods, WebSockets, cross-application objects, API-key scope, API versions, format/extension switching, GraphQL, OAuth/integrations | 10, 12, 20, 24, 25, 28, 29, 32 |
| **ID-D** Feature-Specific Objects | files, bulk operations, search/filter, pagination, receipts/invoices, messages/comments, notification subscriptions | 09, 13, 17, 18, 21, 22, 23 |
| **ID-E** Roles, Writes & Indirect References | cross-role access, object reassignment, second-order IDOR, array/wildcard/type juggling, multi-step flows, blind IDOR and leakage in redirects | 08, 30, 31, 33, 34, 35 |

## Status values

- `PASS` — applicable, tested with A↔B (and unauthenticated where relevant), access correctly denied; evidence saved.
- `FINDING` — B (or anon) read/modified/deleted/acted on A's object; evidence saved.
- `INFO` — exposure without impact (object existence oracle with no data, non-sensitive public objects, IDs predictable but access enforced).
- `NOT_APPLICABLE` — feature/channel absent; evidence cited.
- `BLOCKED` — could not test (single account available, role/tenant unobtainable, feature behind payment).

An unpredictable identifier does **not** make an IDOR a `PASS`: if authorization is missing, it is a `FINDING`; record how an attacker would obtain the ID (check 16/26) to calibrate severity.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Write/delete/ATO on other users' objects (change email/password/phone, delete account, transfer ownership) | Critical |
| Read of sensitive PII/financial/health/auth data at scale with predictable or harvestable IDs | High–Critical |
| Cross-tenant read/write, admin object access by normal user | High–Critical |
| Read of limited/low-sensitivity data, or IDs that require a separate leak | Medium |
| Existence oracle / metadata only / non-sensitive objects | Low–Info |

Calibrate with the program's table and with the OWASP API1:2023 impact description.

## Helper scripts

```bash
S=.agents/skills/idor/scripts

# Offline: inventory identifiers in HARs / URL lists; decode UUID versions, v1 timestamps, ObjectIds, base64
python3 -I $S/id_extract.py artifacts/idor/A.har artifacts/idor/B.har --urls artifacts/urls_all.txt > artifacts/idor/id_inventory.tsv

# Offline: value mutations for one identifier (wrapping, encodings, juggling, arrays, wildcards, UUID neighbours)
python3 -I $S/id_mutator.py 1041 --other 1042
python3 -I $S/id_mutator.py e6e3422c-c82d-11ed-8761-3ff799965458

# Scope-gated: replay A's requests as B and anonymously; flag same/similar responses and A-marker leakage
python3 -I $S/idor_replay.py --target example.com --har artifacts/idor/A.har \
  --as-b 'Cookie: session=B_SESSION' --markers 'a-user@your-domain.test,A Firstname,1041' \
  --out artifacts/idor/replay_results.tsv
#   add --methods GET,POST,PUT,PATCH to include state-changing requests (only on objects you own; DELETE is never replayed)
```

Burp: **Autorize** (low-priv cookie replay on every request), **Auth Analyzer** (multi-session SAME/SIMILAR/DIFFERENT tags), **Param Miner**, **InQL** (GraphQL), WebSocket history + Repeater. CLI: `Arjun` / `fuzzparam` / `ffuf` with `references/idor_param_names.txt` for hidden ID parameters; `waymore` / `gau` for historical IDs.

## Required artifacts

- `artifacts/idor/id_inventory.tsv`, `artifacts/idor/object_matrix.md`
- `artifacts/idor/replay_results.tsv`
- `artifacts/idor/evidence/ID-XX_<short>.txt` (request/response pairs, redacted)
- `artifacts/idor/idor_checklist_35.tsv` — `check_id  status  severity  finding_id  evidence_path  notes`
- `artifacts/idor_vulnerability_matrix.json` (kept for compatibility with `access-control` / `recon-hunter`)
- `artifacts/idor_report.md` — findings by object type and impact, ID-acquisition path, false positives, `[ N / 35 ]`

## Related skills

- `access-control` — vertical privilege escalation, RBAC matrix, multi-tenant boundaries, workflow/state transitions (shares the object matrix; IDOR findings feed its impact analysis)
- `api-security` — BOLA/BFLA in REST/GraphQL specs, mass assignment (BOPLA)
- `linkparamdiscovery` / `jsrecon` — endpoints, hidden parameters and IDs embedded in JS
- `session-management` / `oauth-sso` — tokens and identities used as object keys (`sub`, org UUIDs in OAuth buttons)
- `business-logic` — race conditions on object state; export/report and file-handler skills for document IDORs

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, replays, WebSocket messages, parameter fuzzing, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.

## Extended checklist (added)

- File: `references/idor_extended.md` (Object reference variants across paths, bodies, files, and GraphQL).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
