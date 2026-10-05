---
name: api-security
description: Master API Security and Documentation auditing skill for systematic assessment of OpenAPI/Swagger exposure, GraphQL vulnerabilities, BOLA/BFLA, mass assignment, and gateway defense based on TBHM and OWASP API Top 10.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `api-security` — Universal API & Swagger Security Auditing Skill

## Overview
`api-security` is an offensive API architecture and implementation evaluation skill designed to execute a **25-point audit** against the OWASP API Security Top 10 vulnerabilities. It targets interactive Swagger/OpenAPI exposure, GraphQL introspection and complexity abuses, Broken Object-Level Authorization (BOLA), Broken Function-Level Authorization (BFLA), mass assignment, and gateway policy flaws based on TBHM and repository notes (`Swagger API/`, `API Exploitation/`).

```
                              [ API ENDPOINT / GATEWAY ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Schema &       │          │  GraphQL        │          │  BOLA, BFLA &   │
  │  Documentation  │          │  Security       │          │  Mass Assignment│
  │  (Checks 01-05) │          │  (Checks 06-10) │          │  (Checks 11-17) │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │  Subagent 04    │
                               │  Defensive      │
                               │  Gateway Models │
                               │  (Checks 18-25) │
                               └────────┬────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT REPORT ]
                       • api_security_audit_report.json
                       • swagger_graphql_analysis.md
                       • gateway_policy_remediations.md
                       • api_security_checklist_tracker.md (25/25 Done)
```

---

## The 4 Specialized Subagents

1. **[Subagent 01: Documentation & Schema Discovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/subagents/subagent_01_swagger_schema_discovery.md)**
   *Checks: 01, 02, 03, 04, 05*
   *Focus:* Interactive Swagger UI (`/swagger-ui.html`), OpenAPI JSON specs (`/openapi.json`), Postman collections, SOAP WSDL files, undocumented shadow APIs, and deprecated API versions (`/v1/`).
2. **[Subagent 02: GraphQL Security & Query Architecture](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/subagents/subagent_02_graphql_security.md)**
   *Checks: 06, 07, 08, 09, 10*
   *Focus:* GraphQL introspection exposure, query depth and complexity limits, query batching DoS, field suggestion information leaks, and mutation authorization.
3. **[Subagent 03: Object & Function Authorization (BOLA/BFLA)](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/subagents/subagent_03_bola_bfla_authorization.md)**
   *Checks: 11, 12, 13, 14, 15, 16, 17*
   *Focus:* Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), Mass Assignment in JSON bodies, HTTP method overriding (`X-HTTP-Method-Override`), Content-Type negotiation flaws, resource limits, and excessive data exposure.
4. **[Subagent 04: Defensive API Gateways & Token Security](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/subagents/subagent_04_defensive_api_gateways.md)**
   *Checks: 18, 19, 20, 21, 22, 23, 24, 25*
   *Focus:* API key validation and scope enforcement, JWT signature security (`alg: none` defenses), CORS gateway configurations, strict request schema validation, gateway bypass prevention, rate limiting headers, and audit logging.

---

## Master Orchestration Workflow

When auditing API endpoints and documentation:
1. **Discover API Schemas:** Probe for OpenAPI, Swagger, Postman, and WSDL documentation.
2. **Evaluate Schema Strictness:** Verify that the API gateway enforces strict JSON schema validation, rejecting unlisted properties.
3. **Audit GraphQL Controls:** Disable introspection in production, enforce max query depth (e.g. 5 levels), and block batch request exhaustion.
4. **Test BOLA & Mass Assignment:** Validate that object IDs in paths/bodies are strictly verified against session identity and that administrative flags cannot be bound.
5. **Formulate Defensive Policies:** Provide gateway policy definitions (Kong plugins, AWS API Gateway schema validators, Envoy rate limits, and CORS configurations).

---

## Standard Output Artifacts
* `artifacts/api_security_audit_report.json` — Comprehensive audit matrix of all tested API endpoints.
* `artifacts/swagger_graphql_analysis.md` — Schema analysis and introspection exposure assessment.
* `artifacts/gateway_policy_remediations.md` — Configuration hardening for API gateways and WAFs.
* `artifacts/api_security_checklist_tracker.md` — Complete 25-point verification record.
