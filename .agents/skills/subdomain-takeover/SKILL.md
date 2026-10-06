---
name: subdomain-takeover
description: Audit authorized domains for subdomain takeover risk across 50 dangling DNS and decommissioned SaaS/cloud conditions. Use after subdomain enumeration when CNAME, NS, MX, A/AAAA, SRV, ALIAS/ANAME, TXT, or CAA records may reference abandoned resources. Performs non-destructive verification only and never claims resources, intercepts traffic, or registers provider names.
---

# Subdomain Takeover

Determine whether DNS controlled by the target delegates traffic or trust to a resource that is no longer allocated and may be claimable by another provider customer. A provider-branded 404, NXDOMAIN, or scanner match is a candidate—not proof by itself.

## Authorization and safety boundary

Require explicit authorization for active DNS and HTTP verification. This skill may resolve records, follow DNS chains, retrieve public HTTP/TLS responses, and run takeover-detection templates at a bounded rate.

Do not create buckets, apps, sites, tenants, CDN distributions, DNS zones, mailboxes, repositories, or custom-domain bindings. Do not send or receive email, alter DNS, upload proof files, add verification tokens, create provider accounts, or use provider signup/UI/API flows to test whether a name can be claimed. Those actions require separate explicit authorization from the asset owner and provider and are outside this skill.

## Inputs

Prefer existing reconnaissance artifacts:

1. `artifacts/resolved_subdomains.json`
2. `artifacts/live_subdomains.txt`
3. A user-supplied in-scope hostname list

Include names that no longer answer HTTP; takeover candidates often have valid DNS but no live web service. Preserve full CNAME chains and all NS, MX, SRV, A/AAAA, TXT, CAA, and provider-specific alias evidence.

If only `live_subdomains.txt` is available, record a coverage limitation: HTTP-dead or previously observed names absent from that file were not assessed. Do not mark those unknown assets as passing.

## Verification workflow

1. **Build the DNS graph.** Resolve every record type relevant to delegation or service binding. Follow CNAMEs until the terminal A/AAAA response, NXDOMAIN, SERVFAIL, empty answer, or loop. Record authoritative nameservers and TTLs.
2. **Identify dangling edges.** Queue terminal NXDOMAINs, unresolvable delegated NS/MX/SRV targets, provider-owned endpoints returning an unbound-resource response, and A/AAAA records associated with released infrastructure. Do not infer claimability from DNS failure alone.
3. **Collect bounded application evidence.** Request HTTP and HTTPS for the original hostname, preserving status, headers, redirect chain, body hash, title, TLS certificate names, and a short provider fingerprint. Repeat once to rule out transient errors.
4. **Cross-check current provider behavior.** Use current Nuclei takeover templates and the provider's authoritative custom-domain documentation. Provider behavior changes; stale fingerprint lists must not decide findings.
5. **Run the 50-check ledger.** Read [references/checklist_50.md](references/checklist_50.md), execute every applicable check, and mark each `PASS`, `CANDIDATE`, `LIKELY`, `NOT_APPLICABLE`, or `BLOCKED` with an evidence path.
6. **Apply the evidence threshold.** Report a likely takeover only when the target controls the DNS record, its terminal dependency is provider-owned or delegated, the resource is demonstrably unbound/decommissioned, and current provider behavior indicates another tenant could bind that exact name. For the provider-behavior element, record an authoritative documentation or maintained-template URL/version, retrieval date, the exact relevant rule, and whether exact-host binding is documented or merely inferred. An inference cannot promote a finding to `LIKELY`. Without all four elements, report a candidate or informational hygiene issue.

## Evidence rules

- Generic `404`, `403`, TLS mismatch, or NXDOMAIN responses are insufficient.
- A Nuclei/Subjack match is a lead requiring manual DNS-chain and provider validation.
- TXT, CAA, Bing, and Google verification leftovers are normally hygiene signals, not standalone takeover vulnerabilities.
- Dangling A/AAAA records show stale routing; claimability requires evidence that the exact address can be reallocated and bound by an unrelated tenant.
- NS delegation has zone-wide impact. Validate parent delegation and child nameserver status without registering a zone or nameserver.
- MX findings must not be validated by sending, receiving, or intercepting mail.
- Wildcard DNS expands affected names but does not create claimability without a dangling terminal provider resource.
- Use one finding ID when multiple ledger checks describe the same dependency, and cross-reference it from each row rather than duplicating a vulnerability.

## Suggested collection commands

Adapt paths and rate limits to the authorized scope:

```bash
dnsx -list artifacts/live_subdomains.txt -a -aaaa -cname -ns -mx -txt -srv -caa \
  -resp -json -rate-limit 100 -output artifacts/takeover_dns_inventory.jsonl

nuclei -list artifacts/live_subdomains.txt -t http/takeovers/ \
  -rate-limit 20 -jsonl -output artifacts/takeover_nuclei_candidates.jsonl
```

Do not automatically label scanner output as verified.

## Required artifacts

- `artifacts/takeover_dns_inventory.jsonl`
- `artifacts/takeover_cname_chains.tsv`
- `artifacts/takeover_http_evidence/`
- `artifacts/takeover_candidates.tsv`
- `artifacts/takeover_checklist_50.tsv`
- `artifacts/subdomain_takeover_report.md`

The final report must distinguish exploitable takeover risk, likely-but-unclaimed conditions, false positives, informational stale records, and checks that could not be completed.
