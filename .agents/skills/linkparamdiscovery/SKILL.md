---
name: linkparamdiscovery
description: Master link, parameter, and client-side endpoint discovery skill for exhaustive 40-point web crawling, JavaScript AST analysis, source map recovery, hidden parameter fuzzing, and real-time protocol auditing based on TBHM v4.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `linkparamdiscovery` — Universal Link & Parameter Discovery Skill

## Overview
`linkparamdiscovery` is a comprehensive offensive discovery skill designed to execute an exhaustive **40-point link and parameter audit**. It analyzes client-side routing, extracts hidden input parameters, uncovers real-time streaming protocols (WebSockets, SSE), unpacks JavaScript source maps, and discovers functional workflows (file uploads, webhooks, exports, batch APIs) based on Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)*.

```
                              [ TARGET URL / HOST ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Crawlers &     │          │  JS Mining, AST │          │  Parameter      │
  │  Linked Discover│          │  & Source Maps  │          │  Mining & Forms │
  │  (5 Checks)     │          │  (8 Checks)     │          │  (7 Checks)     │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
  ┌─────────────────┐                                       ┌─────────────────┐
  │  Subagent 04    │                                       │  Subagent 05    │
  │  Real-time, WS, │                                       │  API Formats,   │
  │  SSE & Events   │                                       │  SSO & Workflows│
  │  (6 Checks)     │                                       │  (14 Checks)    │
  └────────┬────────┘                                       └────────┬────────┘
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT ARTIFACTS ]
                       • discovered_parameters.json
                       • hidden_admin_routes.txt
                       • exposed_sourcemaps.txt
                       • postmessage_handlers.txt
                       • workflow_endpoints.txt
                       • checklist_40_tracker.md (40/40 Complete)
```

---

## The 5 Specialized Subagents

1. **[Subagent 01: Automated Crawlers & Linked Discovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/subagents/subagent_01_crawlers_linked_discovery.md)**
   *Checks: 01, 02, 03, 10, 25*
   *Tools:* `katana`, `hakrawler`, `gospider`, client-side HashRouter extraction, and `iframe` harvesting.
2. **[Subagent 02: JavaScript Mining, AST Analysis & Source Maps](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/subagents/subagent_02_js_mining_sourcemaps.md)**
   *Checks: 04, 05, 09, 15, 16, 17, 18, 39*
   *Tools:* `LinkFinder`, `JSParser`, `.js.map` source map recovery (`sourcemapper`), AST constants parsing, and React/Vue/Angular router tables.
3. **[Subagent 03: Parameter Mining, Fuzzing & Form Extraction](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/subagents/subagent_03_parameter_mining_forms.md)**
   *Checks: 06, 07, 08, 23, 24, 31, 36, 37*
   *Tools & Wordlists:* `paramspider`, `arjun` using `wordlists/params.txt`, path parameter normalization (`/{id}`), HTML `<form>` hidden input parsing, Referer leak analysis, search filters, and pagination parameters.
4. **[Subagent 04: Real-time, Streaming, WebSockets & Event Handlers](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/subagents/subagent_04_realtime_websockets_events.md)**
   *Checks: 11, 12, 13, 14, 30, 40*
   *Focus:* WebSocket endpoints (`ws://`, `wss://`, `/socket.io/`), Server-Sent Events (`text/event-stream`), long-polling routines, microservice gateway headers, and cross-origin `postMessage` listener validation.
5. **[Subagent 05: API Formats, Legacy Gateways & Functional Workflows](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/subagents/subagent_05_api_formats_workflows.md)**
   *Checks: 19, 20, 21, 22, 26, 27, 28, 29, 32, 33, 34, 35, 38*
   *Focus & Wordlists:* REST API versioning (`/v1/` vs `/v2/`), SOAP WSDL (`wad.txt`, `svc.txt`), XML-RPC (`system.listMethods`), SAML/OAuth redirect flows, webhooks, file uploads, data exports, and batch/bulk operations.

---

## Master Orchestration Workflow

When this skill is executed against a target (`TARGET_URL="https://example.com"`):

### Phase 1: Automated Crawling & Link Extraction (Subagent 01)
* Run headless crawling via `katana` with JavaScript rendering and automated form completion.
* Run `hakrawler` with depth 3.
* Extract client-side SPA hash routes (`#/admin`, `#/profile`).
* Parse all `iframe` and `embed` elements.

### Phase 2: JavaScript Bundle Static Analysis & Source Maps (Subagent 02)
* Download all unique client-side JavaScript bundles.
* Run `LinkFinder` and `JSParser` to extract hidden API paths.
* Probe for exposed `.js.map` files and unpack original source code trees.
* Extract React / Vue / Angular route tables and identify unlinked admin/debug endpoints.
* Parse hardcoded secrets, constants, and API keys.

### Phase 3: Input & Parameter Discovery (Subagent 03)
* Mine historical parameter occurrences using `paramspider`.
* Run `arjun` parameter fuzzing on high-value endpoints using `wordlists/params.txt`.
* Normalize dynamic path parameters (`/items/{uuid}`).
* Parse HTML forms and extract hidden parameters (`<input type="hidden">`).
* Audit search filters and pagination parameters (`offset`, `limit`, `cursor`).

### Phase 4: Real-time & Cross-Origin Protocol Auditing (Subagent 04)
* Extract WebSocket endpoints (`wss://`) and frame message structures.
* Check for Server-Sent Events (`/events`, `/stream`).
* Map microservices routing topologies from proxy headers.
* Audit all `window.addEventListener("message", ...)` handlers for missing origin validation.

### Phase 5: Functional Workflows & Authentication Flows (Subagent 05)
* Fuzz API versions (`/v1/`, `/v2/`, `/v0/`).
* Probe SOAP WSDL services using `wad.txt` and `svc.txt`.
* Audit XML-RPC methods via `system.listMethods`.
* Extract OAuth/SAML redirect parameters (`redirect_uri=`).
* Identify webhook destinations, file upload endpoints, export routines, and batch APIs.

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
* `artifacts/discovered_parameters.json` — Consolidated input parameter inventory.
* `artifacts/hidden_admin_routes.txt` — Admin and debug routes discovered in JS.
* `artifacts/exposed_sourcemaps.txt` — Recovered original source code mappings.
* `artifacts/postmessage_handlers.txt` — Cross-origin postMessage listener audit.
* `artifacts/workflow_endpoints.txt` — Webhooks, uploads, exports, and batch APIs.
* `artifacts/checklist_40_tracker.md` — 40/40 completed verification matrix.
