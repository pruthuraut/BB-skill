---
name: target-router
description: Smart start for any target. Reads techfingerprint output, headers, page source, parameter names, and URL lists, then decides which audit skills and checklist rows apply (CMS, framework, server, SaaS key, parameter types like url/file/id/redirect). Triggers on "what should I test", "route this target", "smart start", "which skills apply", "auto-detect", or when a fingerprint or param list is available after recon. Passive planning only; never sends requests.
---

# Target Router

Turn recon output into a test plan. The router does not touch the network. It matches what recon already found against checklist tables in every skill's `references/` folder and prints which skills to start, which rows apply, and the class of each row.

## When to use

- After `techfingerprint` or `recon-hunter` writes results to `artifacts/`.
- When a target shows a technology (for example Jenkins, Grafana, Nginx, WordPress) or a parameter (for example `url=`, `file=`, `id=`, `redirect=`).
- When the scope type is unknown: the router reads `scope.txt` if you pass `--workspace` and `--target`.

## Procedure

1. Confirm scope. `scripts/scope_check.sh TARGET` must pass before any active step. The router can run it for you with `--check-scope`.
2. Collect inputs (any subset):
   - Fingerprint: techfingerprint output, `httpx -tech-detect` output, raw response headers, or saved HTML.
   - Parameters: parameter names from `linkparamdiscovery` or `arjun`, one per line.
   - URLs: crawled URL list; the router parses query strings.
3. Run the plan:

   ```
   python3 scripts/route_target.py --target example.com --workspace ~/Documents/bugbounty \
     --fingerprint artifacts/example.com/techfingerprint.txt \
     --params artifacts/example.com/params.txt --urls artifacts/example.com/urls.txt
   ```

   Add `--json` to save the plan as `artifacts/<target>/route_plan.json`.
4. Start skills in the order printed:
   - `passive` rows run automatically inside scope.
   - `bounded` rows run automatically inside scope with the limits listed in each skill (rate limit, own accounts, OOB host).
   - `authorized-only` rows are listed for the user and run only after explicit approval for that specific check.
5. Record each row's outcome in the skill's checklist (0 to N complete) and save findings to `artifacts/`.

## Parameter routes

The router maps parameter names to skills. The full table is `PARAM_ROUTES` in `scripts/route_target.py`. Examples:

| Parameter names | Skill started |
|---|---|
| url, uri, dest, fetch, webhook, image, proxy | ssrf-audit |
| redirect, return, next, continue, goto | open-redirect-and-header-injection |
| file, path, template, include, page, doc | path-traversal, server-side-injection (SSTI) |
| id, query, q, search, sort, order | sqli, idor |
| role, admin, isAdmin, tenant, org_id | access-control |
| token, jwt, session | session-management |
| upload, attachment, avatar | file-upload-audit |
| price, amount, quantity, coupon | business-logic |

## Technology routes

The router indexes every table under `.agents/skills/*/references/` that has `Product` and `Class` columns. A product matches when its name or alias appears in the fingerprint text. Matched rows point to the reference file and the skill that owns them. Classes:

- `passive`: header, body, or known-path check only.
- `bounded`: a few safe requests with stated limits.
- `authorized-only`: needs explicit approval for that check.

## Scope playbook

The scope type selects a playbook in `recon-hunter/references/scope_playbooks.md`:

- **large**: scope says any asset of the organization.
- **medium**: wildcard scope such as `*.target.com`.
- **small**: one host or endpoint.

## Outputs

- `artifacts/<target>/route_plan.json` (when `--json` is used)
- Matched rows per skill in the plan, referenced by ID (for example `TS-CMS-004`)

## Rules

- Passive planning only. The router never sends traffic.
- A match is a lead, not a finding. Verify version or behaviour before reporting.
- Never run exploit code from a checklist row. Version checks and safe verifications are the default.
