# Subagent 06: Subdomain Takeover & Dangling Resource Auditing

## Role

Route the subdomain inventory into the dedicated [`subdomain-takeover`](../../subdomain-takeover/SKILL.md) workflow and return its normalized findings to `subdomainenum`.

The parent enumeration checklist retains its original two items:

- **Check 25:** Audit discovered subdomains for takeover conditions.
- **Check 28:** Audit dangling CNAME dependencies.

Those parent items expand into the takeover skill's independent [50-check verification ledger](../../subdomain-takeover/references/checklist_50.md). Do not report this as 52 enumeration checks; the 50 takeover rows are a nested coverage ledger for Checks 25 and 28.

## Inputs

- `artifacts/live_subdomains.txt`
- `artifacts/resolved_subdomains.json`
- Raw DNS evidence from passive, brute-force, permutation, and SRV discovery

Include DNS-resolving hosts even when HTTP probing marked them inactive. Takeover discovery must cover CNAME, NS, MX, A/AAAA, SRV, provider alias/flattening, TXT, CAA, wildcard behavior, and multi-hop chains.

## Execution contract

1. Confirm the target names are authorized for active DNS and bounded HTTP verification.
2. Invoke `subdomain-takeover` and complete all 50 ledger rows.
3. Preserve raw DNS chains and repeated HTTP/TLS evidence.
4. Treat Nuclei, Subjack, provider error strings, NXDOMAIN, and generic 404/403 responses as candidate signals only.
5. Do not register, bind, create, upload, email, or otherwise claim a resource.
6. Merge only `LIKELY` findings into the parent report's vulnerability section. Put `CANDIDATE` and informational stale-record findings in separate triage sections.

## Required outputs

- `artifacts/takeover_dns_inventory.jsonl`
- `artifacts/takeover_cname_chains.tsv`
- `artifacts/takeover_candidates.tsv`
- `artifacts/takeover_checklist_50.tsv`
- `artifacts/subdomain_takeover_report.md`
- `artifacts/subagent_06_takeover_report.md` — concise parent-pipeline summary linking the evidence above

The parent summary must never say “zero vulnerable assets” merely because an automated scanner returned no matches. State completed coverage, unavailable checks, and unresolved candidates explicitly.
