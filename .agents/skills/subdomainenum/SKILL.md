---
name: subdomainenum
description: Master reconnaissance skill for exhaustive 50-point subdomain enumeration, passive OSINT scraping, active multi-resolver brute-forcing, wildcard handling, and takeover auditing based on Jason Haddix's TBHM v4.
metadata:
  version: "1.0.0"
  author: "Bug Bounty Multi-Agent Skills Framework"
  compatibility:
    - Antigravity / Gemini CLI
    - Claude Code
    - Cursor IDE
    - OpenAI Codex / OpenCode
    - DeepSeek
---

# `subdomainenum` — Universal Subdomain Enumeration Skill

## Overview
`subdomainenum` is a production-grade offensive reconnaissance skill designed to execute an exhaustive **50-point subdomain enumeration audit**. It implements the methodology from Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)*, paired with automated multi-agent task distribution to eliminate token fatigue, shallow scans, and hallucinations.

```
                                [ TARGET ROOT DOMAIN ]
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
   │  Subagent 01    │           │  Subagent 02    │           │  Subagent 04    │
   │  Passive OSINT  │           │  Dorking & Code │           │  JS & Content   │
   │  & CT Logs      │           │  Cyberspace     │           │  Discovery      │
   │  (18 Checks)    │           │  (9 Checks)     │           │  (5 Checks)     │
   └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
            │                             │                             │
            └─────────────────────────────┼─────────────────────────────┘
                                          ▼
                               ┌─────────────────────┐
                               │ Raw Discovery Pool  │
                               └──────────┬──────────┘
                                          ▼
                               ┌─────────────────────┐
                               │  Subagent 03        │
                               │  Active DNS, Brute  │
                               │  Wildcards & MassDNS│
                               │  (8 Checks)         │
                               └──────────┬──────────┘
                                          ▼
            ┌─────────────────────────────┴─────────────────────────────┐
            ▼                                                           ▼
   ┌─────────────────┐                                         ┌─────────────────┐
   │  Subagent 05    │                                         │  Subagent 06    │
   │  DNS & Infra,   │                                         │  Subdomain      │
   │  Cloud & SPF    │                                         │  Takeover Audit │
   │  (8 Checks)     │                                         │  (50 Checks)    │
   └────────┬────────┘                                         └────────┬────────┘
            │                                                           │
            └─────────────────────────────┬─────────────────────────────┘
                                          ▼
                         [ FINAL VERIFIED ARTIFACTS ]
                         • live_subdomains.txt
                         • resolved_subdomains.json
                         • takeovers_report.md
                         • internal_ip_leaks.txt
                         • 50_checklist_audit.md (50/50 Done)
```

---

## The 8 Specialized Subagents

To maintain maximum depth, accuracy, and operational granularity, tasks are partitioned into 8 focused subagents:

1. **[Subagent 01: Passive OSINT & Certificate Transparency](subagents/subagent_01_passive_scraping.md)**
   *Checks: 01, 02, 03, 04, 06, 07, 08, 09, 10, 11, 12, 13, 24, 34, 39, 43, 44, 47*
2. **[Subagent 02: Search Engine Dorking & Cyberspace Engines](subagents/subagent_02_dorking_cyberspace.md)**
   *Checks: 14, 15, 16, 30, 32, 33, 48, 49, 50*
3. **[Subagent 03: Active DNS Resolution, Bruting, Permutations & Wildcards](subagents/subagent_03_active_dns_brute.md)**
   *Checks: 05, 17, 18, 19, 20, 26, 27, 45*
4. **[Subagent 04: JavaScript Crawling, Content Discovery & Mobile Artifacts](subagents/subagent_04_js_content_mobile.md)**
   *Checks: 21, 31, 35, 41, 42*
5. **[Subagent 05: DNS Records, SPF/DMARC, Cloud Infra & Network Auditing](subagents/subagent_05_infra_dns_cloud.md)**
   *Checks: 22, 23, 29, 36, 37, 38, 40, 46*
6. **[Subagent 06: Subdomain Takeover & Dangling Resource Auditing](subagents/subagent_06_takeover_verification.md)**
   *Parent checks: 25 and 28; expands into the dedicated [50-check takeover audit](../subdomain-takeover/SKILL.md).*
7. **[Subagent 07: DNS Fuzzing with SecLists](subagents/subagent_07_dns_fuzzing.md)**
   *Supplemental coverage: checks 17, 18, and 19 with explicit SecLists progression and wildcard validation.*
8. **[Subagent 08: Virtual Host Discovery with SecLists](subagents/subagent_08_vhost_discovery.md)**
   *Supplemental coverage: shared-origin Host-header discovery with learned response baselines and SNI-aware verification.*

For methodology and reference playbooks, consult:
- [API Keys Configuration Reference](references/api_keys_config.md)
- [Jason Haddix TBHM Lecture Methodology & Attack Surface Pipeline Playbook](references/haddix_lecture_recon_playbook.md)

---

## Master Orchestration Workflow

When this skill is triggered for a target (`TARGET_DOMAIN="example.com"`):

### Phase 1: Environment & Credential Ingestion
1. Verify API provider config (`~/.config/subfinder/provider-config.yaml` or environment variables: `$SECURITYTRAILS_API_KEY`, `$SHODAN_API_KEY`, `$CENSYS_API_ID`, `$GITHUB_TOKEN`, `$FOFA_KEY`, etc.).
2. Generate a fresh, high-throughput resolver list:
   ```bash
   dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
   ```
3. Initialize the artifact output workspace: `mkdir -p artifacts/`.

---

### Phase 2: Parallel Passive Harvesting (Subagents 01, 02, 04)
Run passive discovery concurrently without touching target network assets:
* **Invoke Subagent 01**: CT logs (`crt.sh`, Facebook CT, Google CT, CertSpotter), Passive aggregators (`subfinder`, `amass`, `assetfinder`, `findomain`, `chaos`, `recon.dev`, `bufferover`), Historical archives (`wayback`, `commoncrawl`), and Threat Intel (`virustotal`, `shodan`, `censys`, `securitytrails`).
* **Invoke Subagent 02**: Automated Dorking loops (`Google -www`, `Bing`, `Yahoo`, `DDG`, `sublist3r`), Cyberspace engines (`FOFA`, `ZoomEye`), Code repository leaks (`GitHub`, `GitLab`), and Developer forums (`StackOverflow`).
* **Invoke Subagent 04**: Client-side JavaScript bundles (`katana`, `SubDomainizer`, `waybackurls`), `robots.txt`, `sitemap.xml`, and decompiled mobile packages (APK/IPA).

**Consolidation:**
```bash
cat artifacts/subagent_01_passive_results.txt \
    artifacts/subagent_02_dorking_results.txt \
    artifacts/subagent_04_js_content_results.txt | \
    sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:upper:]' '[:lower:]' | \
    grep -E "\.${TARGET_DOMAIN}$" | sort -u > artifacts/passive_seed_candidates.txt
```

---

### Phase 3: Active DNS Resolution, Bruting & Wildcards (Subagent 03)
* **Check Authoritative Nameservers:** Test AXFR on all NS servers (`dig axfr @ns target`).
* **Check DNSSEC:** Audit NSEC records for zone walking (`ldns-walk`).
* **Wildcard DNS Detection:** Query random nonce domain (`rand-check-xxxx.target`). If it resolves, flag wildcard IP for filtering.
* **Multi-Resolver Brute-Force:** Run `shuffledns` or `massdns` using TBHM `commonspeak2` / `all.txt`.
* **SRV Records:** Enumerate service locators (`dnsrecon -t srv`).
* **Permutation / Alteration:** Feed verified passive and brute-force findings into target-aware `alterx` patterns. Generate bounded prefix/suffix, environment, region, numeric, and multi-level variations; remove already-known names; then resolve the delta with wildcard filtering before merging it into the live inventory. Use [the permutation runner](scripts/run_permutations.sh) for reproducible artifacts.
* **Unified Resolution via `dnsx`:**
  ```bash
  dnsx -l artifacts/passive_seed_candidates.txt \
    -r resolvers.txt \
    -wd ${TARGET_DOMAIN} \
    -a -cname -resp \
    -json -o artifacts/resolved_subdomains.json

  jq -r '.host' artifacts/resolved_subdomains.json | sort -u > artifacts/live_subdomains.txt
  ```

For dedicated SecLists-based DNS fuzzing, invoke Subagent 07 and merge only independently resolved, wildcard-filtered names.

For permutation expansion, run Subagent 03 only after the first resolution pass has produced a useful seed set. Begin with names actually observed for the target, enrich from their labels, and use the smallest relevant SecLists tier. Estimate and cap candidate volume before resolution; a large generic wordlist multiplied across every pattern is not automatically better coverage.

### Phase 3B: Virtual Host Discovery (Subagent 08, when authorized)

Run only when the destination IP/origin is explicitly in scope. Learn the default response from multiple random Host headers, derive FFUF match/filter settings from stable response signatures, and verify outliers with SNI-aware requests. Keep DNS-dark vhosts separate from DNS-resolved subdomains.

### Phase 3C: Final HTTP Service Probing (required when authorized)

After DNS collection and scope filtering are complete, run one final HTTPx pass across the authorized, resolved hostname inventory. Never feed raw passive candidates or excluded hosts directly into this stage. Preserve JSONL metadata and raw responses, then derive a deduplicated hostname list from successful HTTP responses; this is the canonical HTTP-live handoff for later web and takeover workflows. DNS-resolving but HTTP-silent names must remain in the DNS inventory because takeover analysis cannot rely only on web-live hosts.

Use the repository runner for deterministic paths and safety checks:

```bash
.agents/skills/subdomainenum/scripts/run_httpx_probe.sh \
  --authorized \
  --input artifacts/live_subdomains.txt \
  --output-dir artifacts/httpx_probe
```

The runner probes HTTP ports 80, 8080, 8000, 8888, and 3000 plus HTTPS ports 443, 8443, and 9443. It records status, content length, title, technology, server, IP, CDN, redirect location, and favicon hash; follows at most three redirects; filters likely error pages; caps the rate at 50 requests/second with 25 workers; uses an eight-second timeout and two retries; emits JSONL; and stores raw responses. Record the HTTPx version, exact command, input hash/count, exclusions applied, start/end time, exit status, JSONL line count, unique responsive URLs, and unique responsive hostnames in `run_metadata.txt`.

Required outputs:

- `artifacts/httpx_probe/httpx.jsonl` — canonical structured probe output
- `artifacts/httpx_probe/responses/` — stored raw HTTP responses
- `artifacts/httpx_probe/live_urls.txt` — deduplicated responsive URLs
- `artifacts/httpx_probe/live_hosts.txt` — deduplicated responsive hostnames
- `artifacts/httpx_probe/run_metadata.txt` — reproducibility and scope record
- `artifacts/httpx_probe/httpx.stderr.log` — progress, statistics, and errors

Do not replace `live_subdomains.txt` with `live_hosts.txt`: the former means DNS-resolving, while the latter means an HTTP service responded on at least one selected port.

---

### Phase 4: Infrastructure & Network Auditing (Subagent 05)
* **Mail Records:** Parse SPF `include:` / `a:` records and DMARC `rua=mailto:` tags.
* **Internal IP Leaks:** Audit resolved records for RFC 1918 space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
* **Cloud Asset Enumeration:** Audit AWS S3 buckets, Azure Blobs, GCP Storage.
* **TLS Certificate SAN Parsing:** Connect to port 443/8443 and extract Subject Alternative Names.
* **Favicon MurmurHash3:** Generate hash and correlate across Shodan.

---

### Phase 5: Takeover & Dangling Resource Auditing (Subagent 06)
Invoke the dedicated [subdomain-takeover skill](../subdomain-takeover/SKILL.md). Complete its 50-row ledger across CNAME, NS, MX, A/AAAA, SRV, ALIAS/ANAME, TXT, CAA, wildcard, chain, and provider-specific conditions. Scanner matches remain candidates until DNS control, dangling state, and current provider binding behavior align; never claim a resource during routine verification.

---

### Phase 6: Final Audit Report & 50-Check Verification
Update the tracking matrix in:
[Checklist 50 Tracker](references/checklist_50_tracker.md)

Compile executive output:
* `artifacts/live_subdomains.txt` — Deduplicated, resolved live subdomains.
* `artifacts/resolved_subdomains.json` — Enriched metadata (A, CNAME, IPs, CDNs).
* `artifacts/httpx_probe/httpx.jsonl` — Final multi-port HTTP service probe metadata.
* `artifacts/httpx_probe/live_hosts.txt` — Canonical HTTP-responsive hostname handoff.
* `artifacts/internal_ip_leaks.txt` — Discovered internal RFC 1918 addresses.
* `artifacts/takeovers_report.md` — Verified takeover vulnerabilities with proof-of-concept steps.
* `artifacts/audit_summary_report.md` — Executive 50/50 completion summary.

---

## Universal Cross-Platform Execution

This skill is structured to work across any modern LLM coding assistant:
* **Antigravity / Gemini CLI:** Discovered automatically via `.agents/skills/subdomainenum/SKILL.md`.
* **Claude Code:** Linked directly via `CLAUDE.md` and `.claude/skills/subdomainenum/SKILL.md`.
* **Cursor IDE:** Integrated via `.cursorrules` and `.cursor/rules/subdomainenum.mdc`.
* **Codex / OpenCode / DeepSeek:** Referenced through `AGENTS.md`.
