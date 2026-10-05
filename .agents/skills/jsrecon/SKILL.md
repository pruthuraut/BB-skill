---
name: jsrecon
description: Master JavaScript reconnaissance, de-minification, source map unpacking, deep secret mining, and endpoint discovery skill for bug bounty hunting based on TBHM and modern offensive JS pipelines.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `jsrecon` — Master Bug Bounty JavaScript Reconnaissance Skill

## Overview
`jsrecon` is an end-to-end, multi-agent offensive JavaScript reconnaissance, de-minification, and source map recovery skill. It operates in **Zero-Redundancy Mode** by automatically inheriting previously discovered assets from [`subdomainenum`](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/subdomainenum/SKILL.md) (`live_subdomains.txt`) and [`contentdiscovery`](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/SKILL.md) / [`linkparamdiscovery`](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/SKILL.md) (`all_discovered_urls.txt`, `js_files.txt`), only performing gap-filling crawling when running standalone. It formats dense code with `js-beautify`, unpacks original TypeScript/React source trees from `.js.map` files, runs a 60+ secret regex catalog alongside TruffleHog, and extracts all internal API routes, body keys, and query parameters.

```
       [ PRIOR ARTIFACTS: live_subdomains.txt, all_discovered_urls.txt, js_files.txt ]
                                         │
                                (Zero-Redundancy Reuse)
                                         │
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │ Subagent 01: Artifact Ingestion & Gap-Fill    │
                 │ (Inherit prior crawl, live probe via HTTPx,   │
                 │  parallel download into artifacts/js_raw/)    │
                 └───────────────────────┬───────────────────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
                 [ live_js_urls.txt ]            [ data_endpoints.txt ]
                         │                       (.json & .xml routes)
                         ▼
        ┌─────────────────────────────────────────────────┐
        │ Subagent 02: Beautification & Source Map Unpack │
        │ (js-beautify, .js.map probe, unminify TS source)│
        └────────────────────────┬────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
  ┌─────────────────────────────┐ ┌─────────────────────────────┐
  │ Subagent 03: Secrets & TH   │ │ Subagent 04: Deep Endpoints │
  │ (60+ Regex Suite, TruffleHog│ │ (6-Way Endpoint Extraction,  │
  │ Verified Provider Scanning) │ │  Parameters, Router Tables) │
  └──────────────┬──────────────┘ └──────────────┬──────────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
        ┌─────────────────────────────────────────────────┐
        │ Subagent 05: Runtime Hooking & Alerting         │
        │ (fetch/XHR console hooks, DOM sinks, Slack alert│
        └────────────────────────┬────────────────────────┘
                                 ▼
                     [ CONSOLIDATED ARTIFACTS ]
                     • live_js_urls.txt
                     • artifacts/js_recon/source_unpacked/ (Raw Source)
                     • secrets_findings.txt & trufflehog_verified.txt
                     • ALL_FINAL_ENDPOINTS.txt
                     • parameters_discovered.json
```

---

## The 5 Specialized Subagents

1. **[Subagent 01: Multi-Source JavaScript Harvesting, Extension Sorting & Parallel Downloads](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/subagents/subagent_01_harvest_download.md)**
   *Focus:* Wildcard subdomain resolution, active crawling (`katana`, `hakrawler`), historical scraping (`gau`, `waybackurls`), deterministic extension sorting (`.js`, `.json`, `.xml`, parameters), live verification via `httpx`, and content-hashed local caching.
2. **[Subagent 02: Automated De-Minification & Source Map (.map) Reconstruction](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/subagents/subagent_02_beautify_sourcemap.md)**
   *Focus:* Formatting with `js-beautify`, source map detection (`//# sourceMappingURL=`, `SourceMap:` headers, direct `.map` probing), unpacking complete developer source trees into `source_unpacked/`, and harvesting `TODO`/`FIXME` notes.
3. **[Subagent 03: High-Fidelity Secrets, Token Mining & TruffleHog Verification](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/subagents/subagent_03_secrets_trufflehog.md)**
   *Focus:* 60+ regex detection catalog (AWS, GCP, Firebase, Stripe, Slack, Discord, JWT, GitHub, Twilio, OpenAI, Anthropic, Private Keys) and live cryptographic secret verification using TruffleHog.
4. **[Subagent 04: Deep Endpoint Extraction, Parameter Mining & Architectural Analysis](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/subagents/subagent_04_endpoints_params.md)**
   *Focus:* The 6-Way endpoint extraction suite (Absolute, Keywords, Dynamic `${id}`, Raw URLs, React/Vue Router routes, and CDN cleaning), body parameter mining (`userId`, `role`, `isAdmin`), and query string harvesting.
5. **[Subagent 05: Dynamic Runtime Hooking, DOM Sinks & Notification Dispatch](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/subagents/subagent_05_runtime_dom_alerting.md)**
   *Focus:* In-browser console monkeypatching for `window.fetch()` and `XMLHttpRequest`, client-side DOM XSS sink auditing (`innerHTML`, `eval()`, `dangerouslySetInnerHTML`), postMessage listeners, and Slack/Discord alerting via `slackcat`.

---

## Standalone Pipeline Scripts
- **[jsx_pipeline.sh](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/scripts/jsx_pipeline.sh)** — High-throughput parallel bash pipeline supporting multi-target harvesting, beautification, 60+ pattern scanning, and TruffleHog.
- **[js_analyzer.py](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/scripts/js_analyzer.py)** — Cross-platform Python script for AST extraction, source map unpacking, and endpoint classification.

---

## Reference Guides
- **[Master JavaScript Secret Regex Catalog](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/references/secret_regex_catalog.md)**
- **[Endpoint Analysis & Triage Matrix](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/references/endpoint_analysis_matrix.md)**
- **[Browser Console Snippets for Dynamic Recon](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/references/browser_console_snippets.md)**

---

## Standard Output Artifacts
Each execution writes to `artifacts/js_recon/<domain>/`:
- `urls_all.txt` & `live_js_urls.txt` — Harvested and live-verified JavaScript URLs.
- `data_endpoints_all.txt` — Isolated `.json` and `.xml` API endpoints.
- `parameterized_urls_all.txt` — Endpoints containing query parameters.
- `js_raw/` & `js_beautified/` — Locally cached and de-minified JavaScript files.
- `source_unpacked/` — Reconstructed original developer source trees unpacked from `.js.map`.
- `secrets_findings.txt` — Matched credentials and high-value tokens.
- `tools/trufflehog_verified_findings.txt` — Cryptographically verified active credentials.
- `ALL_FINAL_ENDPOINTS.txt` — Deduplicated, CDN-cleaned application endpoints.
- `parameters_body.txt` & `parameters_query.txt` — Extracted request parameters.
