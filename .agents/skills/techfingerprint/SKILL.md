---
name: techfingerprint
description: Master technology profiling skill for exhaustive 40-point web stack detection, CDN/WAF identification, modern frontend SPA heuristics, backend runtime probing, and API architecture discovery (Swagger, GraphQL, Actuators).
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `techfingerprint` — Universal Technology Fingerprinting Skill

## Overview
`techfingerprint` is a production-grade attack surface profiling skill designed to execute an exhaustive **40-point technology fingerprinting audit**. It identifies the exact web stack (web servers, reverse proxies, WAFs, CDNs, JavaScript UI frameworks, backend languages, application frameworks, CMS platforms, and API architectures) to prioritize high-value vulnerability research.

```
                              [ TARGET URL / HOST ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Core Profilers │          │  Edge, CDN,     │          │  Frontend SPAs  │
  │  Headers/Cookies│          │  WAF & Hosting  │          │  & Frameworks   │
  │  (8 Checks)     │          │  (5 Checks)     │          │  (9 Checks)     │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
  ┌─────────────────┐                                       ┌─────────────────┐
  │  Subagent 04    │                                       │  Subagent 05    │
  │  Backend Stacks │                                       │  CMS & API      │
  │  Runtimes & Debug│                                      │  Architecture   │
  │  (10 Checks)    │                                       │  (8 Checks)     │
  └────────┬────────┘                                       └────────┬────────┘
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT ARTIFACTS ]
                       • technology_profile.json
                       • discovered_swagger.txt
                       • exposed_actuators.txt
                       • graphql_introspection.txt
                       • checklist_40_tracker.md (40/40 Complete)
```

---

## The 5 Specialized Subagents

1. **[Subagent 01: Core Web Profilers, Headers, Cookies & Meta Tags](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/subagents/subagent_01_core_headers_cookies.md)**
   *Checks: 01, 02, 03, 04, 05, 06, 07, 16*
2. **[Subagent 02: Infrastructure, Edge CDNs, WAFs & Network Services](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/subagents/subagent_02_infra_edge_waf.md)**
   *Checks: 14, 15, 17, 18, 20*
3. **[Subagent 03: Modern Frontend Frameworks & Single Page Applications](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/subagents/subagent_03_frontend_spa_frameworks.md)**
   *Checks: 09, 10, 11, 12, 33, 34, 35, 36, 37, 38*
4. **[Subagent 04: Backend Runtimes, Server Frameworks & Enterprise Stacks](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/subagents/subagent_04_backend_runtimes_stacks.md)**
   *Checks: 13, 26, 27, 28, 29, 30, 31, 32, 39, 40*
5. **[Subagent 05: CMS & API Architecture Profiling (GraphQL, Swagger, REST)](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/subagents/subagent_05_cms_api_architecture.md)**
   *Checks: 08, 19, 21, 22, 23, 24, 25*

---

## Master Orchestration Workflow

When this skill is executed against a target (`TARGET_URL="https://example.com"`):

### Phase 1: Core Profiling & Header Intelligence (Subagent 01)
* Run `httpx -tech-detect`, `whatweb`, and `webanalyze`.
* Extract `Server`, `X-Powered-By`, and framework-specific cookies (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`).
* Parse HTML meta generator tags and invoke BuiltWith API if available.

### Phase 2: Edge CDN, WAF & Infrastructure Auditing (Subagent 02)
* Check Cloudflare headers (`cf-ray`, `__cf_bm`).
* Check CNAME chains for CDN providers (CloudFront, Fastly, Akamai, Azure CDN).
* Run `wafw00f` to discover active WAF defenses and block behaviors.
* Resolve IP address to ASN and WHOIS hosting provider.
* Run `fingerprintx` to identify non-standard open port daemons.

### Phase 3: Frontend Framework & SPA Discovery (Subagent 03)
* Scan rendered DOM and scripts for React (`_reactRootContainer`, React DevTools).
* Scan for Next.js SSR (`<script id="__NEXT_DATA__">`, `buildId`).
* Scan for Angular (`ng-version`, `ng-app`, `_nghost`).
* Scan for Vue.js (`__vue__`, `data-v-` scoped attributes) and Nuxt.js (`__NUXT__`).
* Detect Gatsby, Svelte, Ember.js, and Meteor runtime configurations.

### Phase 4: Backend Runtimes, Frameworks & Admin Panels (Subagent 04)
* Trigger deliberate 404/500 errors to inspect stack traces.
* Check for exposed Laravel debuggers (`/_debugbar`, `/telescope`, `/horizon`).
* Probe for Django admin panel (`/admin/login/`, `csrfmiddlewaretoken`).
* Check for Spring Boot Actuator endpoints (`/actuator/health`, `/actuator/env`).
* Detect ASP.NET ViewState, PHP headers, Express headers, Flask Werkzeug consoles, and FastAPI docs (`/docs`, `/redoc`).

### Phase 5: CMS & Interactive API Discovery (Subagent 05)
* Audit CMS platforms via WPScan, Joomscan, and Droopescan.
* Check WordPress REST API endpoints (`/wp-json/wp/v2/users`).
* Detect API Gateway headers (`X-Amzn-Trace-Id`, `Kong`, `Envoy`).
* Probe Swagger / OpenAPI interactive documentation endpoints (`/swagger-ui.html`, `/openapi.json`).
* Probe GraphQL endpoints (`/graphql`), check for exposed GraphiQL Playgrounds, and execute introspection queries.

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
* `artifacts/technology_profile.json` — Consolidated structured profile.
* `artifacts/waf_report.txt` — Detected WAF protections.
* `artifacts/discovered_swagger.txt` — Exposed interactive API documentation.
* `artifacts/exposed_actuators.txt` — Exposed Spring Boot Actuators or debug endpoints.
* `artifacts/graphql_introspection.txt` — Confirmed GraphQL introspection results.
* `artifacts/checklist_40_tracker.md` — 40/40 completed verification matrix.
