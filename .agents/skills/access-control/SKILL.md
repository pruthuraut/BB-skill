---
name: access-control
description: Audit authorized applications for privilege escalation and broken function-level authorization across 37 checks — vertical (user→admin) and horizontal escalation, role manipulation in parameters / JWT claims / cookies, mass assignment, profile role changes, feature flags and toggle APIs, unprotected and URL-encoded admin routes, GraphQL mutations and field-level authorization, role-assignment races, multi-tenant and organisation-ID boundaries, team/group membership, API-gateway vs backend and UI vs API inconsistencies, method-override and content-type switching, backup/restore and import/export of role data, shared resources, referer/location-based controls, multi-step admin flows, privilege retention after demotion, invitations and delegation, impersonation, approval workflows, API-key scope, step-up auth, hidden debug/staff parameters, cache-layer leakage, and plan/entitlement bypass. Built on PortSwigger access-control, JWT, API-testing, GraphQL and race-condition material, OWASP WSTG-ATHZ-02/03, OWASP API5 (BFLA) / API3 (BOPLA) and the Authorization cheat sheet.
version: "2.0.0"
---

# `access-control` — Privilege Escalation & Function-Level Authorization

Determine whether a user can **do or see more than their role, tenant, plan, or relationship allows**. Object-level IDOR has its own skill ([`idor`](../idor/SKILL.md)); this skill covers *functions*, *roles*, *tenants*, *memberships*, *entitlements* and the architecture layers that enforce them.

Primary methodology sources:

- PortSwigger Web Security Academy — Access control (unprotected functionality, parameter-based, platform misconfiguration, horizontal-to-vertical, multi-step, referer-based, location-based), JWT attacks, API testing (mass assignment, HTTP methods, content types), GraphQL, Race conditions and *Smashing the state machine*, Web cache deception
- OWASP WSTG v4.2 **WSTG-ATHZ-02** (Bypassing Authorization Schema), **WSTG-ATHZ-03** (Privilege Escalation); OWASP Top 10 **A01:2021**; OWASP API Security Top 10 2023 **API5 BFLA**, **API3 BOPLA**; Authorization, Mass Assignment and GraphQL cheat sheets
- CWE-269 / CWE-285 / CWE-862 / CWE-863

## Authorization and safety boundary

- Pass the scope gate before any request.
- **Role ladder of self-owned accounts:** `anon`, `U1`/`U2` (normal users), `M` (manager/team-admin if the product has one), `ADM` (tenant/org admin — create your own org/workspace where self-service allows), `T2` (user in a second tenant you own). Never use or target staff/platform-admin accounts you were not given.
- Admin-function proofs must be **read-only or self-targeted**: list users of *your* org, change *your own* U2's role, toggle a feature in *your* workspace. Do not change global settings, other customers' data, billing, or anything that affects real users. If an admin panel turns out to be platform-wide (all customers), stop at the first read and report.
- State-changing requests are replayed only against your own tenant/objects. `role_matrix.py` never sends `DELETE` and needs an explicit flag for any non-GET method.
- Race tests (`race_burst.py`) are capped at 20 parallel requests and target your own role-assignment/invite flows only.
- Backup/restore and import tests use backups you exported from **your own** tenant; never import data belonging to someone else.

## Inputs

1. HAR captures per role (ADM first, exercising every admin feature; then U1 doing everything a user can)
2. Role/permission model: docs, pricing page (plans/entitlements), UI menus per role, API spec (`api-security`), JS route tables and feature-flag configs (`jsrecon`)
3. `artifacts/discovered_endpoints.txt` (admin/internal paths from `contentdiscovery`), `artifacts/idor/object_matrix.md`
4. Tokens per role (decode with `session-management/scripts/jwt_inspect.py`)

## Workflow

1. **Model the permission matrix.** For each function: which roles/plans/tenants should be allowed. Write `artifacts/access_control/permission_model.md` (source: docs, UI, API spec, ADM HAR).
2. **Automated role matrix.** `scripts/role_matrix.py` replays ADM's captured requests as every lower role and anonymously, then prints an allowed/denied matrix with mismatches against the model (PE-01/06/11/17/20).
3. **Tamper.** Generate role/flag/plan/method/content-type/path variations with `scripts/priv_mutator.py` and apply them per [references/checklist_37.md](references/checklist_37.md).
4. **Races and state.** `scripts/race_burst.py` (last-byte-synchronised burst) for role assignment, invite acceptance, demotion and approval flows (PE-13, PE-28, PE-31).
5. **Confirm, classify, report.** Verify each hit manually from the affected role's view; classify vertical / horizontal / cross-tenant / entitlement; update `[ N / 37 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **PE-A** Role & Identity Claims | role params, JWT claims, cookies, mass assignment, profile role change, API parameter tampering, hidden debug/staff params | 03, 04, 05, 07, 08, 09, 35 |
| **PE-B** Admin Surface & Request Tricks | vertical escalation, admin endpoint protection, direct admin URLs, URL-encoding bypasses, method override, content-type switching, referer/location-based controls | 01, 06, 11, 16, 18, 19, 26 |
| **PE-C** Architecture Layers | API gateway vs backend, UI vs API, GraphQL mutations and field-level auth, API-key/PAT scope, cache-layer leakage | 12, 17, 20, 32, 33, 36 |
| **PE-D** Tenancy, Membership & Sharing | horizontal escalation, multi-tenant boundaries, team/group membership, org-ID manipulation, shared resources, invitations/delegation, impersonation | 02, 14, 15, 21, 25, 29, 30 |
| **PE-E** Features, Data & State | feature flags, toggle APIs, role-assignment races, backup/restore, import/export, multi-step admin flows, privilege retention after demotion, approval workflows, step-up auth, plan/entitlement bypass | 10, 13, 22, 23, 24, 27, 28, 31, 34, 37 |

White-box items (centralised middleware, data-layer ownership binding, indirect reference maps, audit logging on authorization failures) are in the checklist appendix and use status `CONFIG_REVIEW` — they need source or configuration access.

## Status values

- `PASS` — applicable, executed for every relevant role pair, denial evidenced.
- `FINDING` — lower role/tenant/plan performed or viewed a higher-privileged function; evidence from the affected role saved.
- `INFO` — inconsistency without impact (admin UI route reachable but every API call denied; role name disclosed).
- `NOT_APPLICABLE` — no such feature/role/tenant model; evidence cited.
- `CONFIG_REVIEW` — requires source/config review (appendix items).
- `BLOCKED` — role or tenant not obtainable, feature behind sales/approval, scope limits.

A `200 OK` is not a finding by itself: confirm the action took effect (role changed, data returned, flag flipped) from a separate session.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Normal user / anon gains admin (tenant or platform) functions, or becomes admin via role/claim/flag/mass assignment/race | Critical |
| Cross-tenant admin or data access; impersonation of other users; restore/import granting roles | Critical |
| Manager → org-admin, invite/delegation beyond own level, privilege retained after removal | High |
| Paid-plan features without paying, read-only admin data (user lists, audit logs) | Medium–High |
| UI-only exposure, role disclosure, inconsistent errors | Low–Info |

## Helper scripts

```bash
S=.agents/skills/access-control/scripts

# Scope-gated: replay ADM's requests as each lower role + anon; allowed/denied matrix vs permission model
python3 -I $S/role_matrix.py --target example.com --har artifacts/access_control/ADM.har \
  --role 'U1=Cookie: session=U1' --role 'M=Cookie: session=M' --role 'T2=Authorization: Bearer T2' \
  --admin-markers 'Admin console,"role":"admin"' --out artifacts/access_control/role_matrix.tsv

# Offline: privilege tampering payloads (role/flag/plan fields, JWT claims, encoded admin paths, method/content-type)
# (Git Bash on Windows rewrites '/admin' args into Windows paths: prefix with MSYS_NO_PATHCONV=1)
python3 -I $S/priv_mutator.py --path /admin/users --json '{"name":"bbtest"}'

# Scope-gated: last-byte-synchronised parallel burst of one raw HTTP request (max 20), for PE-13/28/31
python3 -I $S/race_burst.py --target example.com --request artifacts/access_control/accept_invite.req --count 10
```

Burp: **Autorize** (low-priv replay), **Auth Analyzer**, **JWT Editor**, **InQL**, Repeater *send group in parallel* (single-packet attack), **Param Miner**. Shared tools: `session-management/scripts/jwt_inspect.py`, `idor/scripts/idor_replay.py`, `authbypass/scripts/bypass_matrix.sh` (path/header bypass matrix for one admin URL).

## Required artifacts

- `artifacts/access_control/permission_model.md`, `artifacts/access_control/role_matrix.tsv`
- `artifacts/access_control/evidence/PE-XX_<short>.txt`
- `artifacts/access_control/access_control_checklist_37.tsv` — `check_id  status  severity  finding_id  evidence_path  notes`
- `artifacts/privilege_escalation_report.md` — findings by role transition, chains, false positives, `[ N / 37 ]`
- `artifacts/authorization_remediation.md` — optional remediation notes (central policy, deny-by-default)

## References in this skill

- [references/checklist_37.md](references/checklist_37.md) — all checks with commands, pass/fail and sources, plus the white-box appendix
- [references/idor_and_privilege_reproduction_playbook.md](references/idor_and_privilege_reproduction_playbook.md) — KYC-state IDOR and multi-tenant boundary case studies

## Related skills

- `idor` — object-level authorization (PE-02 hands off here); shares `artifacts/idor/object_matrix.md`
- `authbypass` — unauthenticated bypasses (X-Original-URL, method switching, path normalisation, registration mass assignment)
- `session-management` — JWT forging primitives (SM-21…30) for PE-04; privilege retention via sessions (SM-34)
- `oauth-sso` — scope escalation (OA-07), SSO group/role mapping
- `api-security` — API inventory, BFLA in specs, GraphQL; `business-logic` — races and workflow states

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, role changes, replays, races, imports, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.
