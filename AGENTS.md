# AGENTS.md — Universal Bug Bounty Multi-Agent Framework

This document specifies the agent architecture, roles, and execution workflows for automated offensive reconnaissance, technology fingerprinting, content discovery, parameter mining, credential attacks, authentication bypass, session management, OAuth/SSO, SSRF auditing, broken access control, business logic, API security, and resource exhaustion.

## System Mission
Execute complete, deterministic, and high-fidelity attack surface mapping and vulnerability auditing across granular verification checks, preventing false positives and missed assets by dividing work across specialized subagents.

---

## Agent Directory & Capabilities

### Phase 1: Reconnaissance & Attack Surface Mapping
1. **`recon-hunter` (Master 16-Phase Pipeline)** — `.agents/skills/recon-hunter/SKILL.md`
   - *Architecture:* Continuous end-to-end unauthenticated recon-to-bug pipeline coordinating all Phase 1-3 skills with strict Severity Kill Rules, 60s PoC curls, and Coverage Ledger.
2. **`subdomainenum` (50 Checks)** — `.agents/skills/subdomainenum/SKILL.md`
   - *Subagents (8):* Passive Scraping, Search Dorking, Active DNS Bruting & Wildcards, JS/Mobile Assets, Cloud Infra & SPF/DMARC, Subdomain Takeover Verification, SecLists DNS Fuzzing, and calibrated Virtual Host Discovery.
3. **`techfingerprint` (40 Checks)** — `.agents/skills/techfingerprint/SKILL.md`
   - *Subagents (5):* Core Profilers & Cookies, Edge CDN & WAF, Frontend SPAs & Frameworks, Backend Runtimes & Debuggers, CMS & API Architecture.
4. **`contentdiscovery` (50 Checks)** — `.agents/skills/contentdiscovery/SKILL.md`
   - *Subagents (6):* Recursive Fuzzers & Crawlers, Historical JS & OSINT, Well-Known & Identity, Sensitive Files & Backups, Debug Logs & API Docs, Admin Consoles & DevOps.
5. **`linkparamdiscovery` (40 Checks)** — `.agents/skills/linkparamdiscovery/SKILL.md`
   - *Subagents (5):* Automated Crawlers & Linked Discovery, JS Mining & Source Maps, Parameter Mining & Forms, Real-time WebSockets & SSE, API Formats & Workflows.
6. **`jsrecon` (Comprehensive JS De-Minification & Secret Pipeline)** — `.agents/skills/jsrecon/SKILL.md`
   - *Subagents (5):* Multi-Source Harvesting & Downloads, Automated Beautification & Source Map Recovery, 60+ Secret Patterns & TruffleHog, Deep 6-Way Endpoint & Param Extraction, Dynamic Runtime Hooking & Alerting.
7. **`cloud-supplychain` (Cloud Storage, Org Secrets & Dependency Confusion)** — `.agents/skills/cloud-supplychain/SKILL.md`
   - *Subagents (3):* Cloud Storage & Buckets (S3/GCS/Azure/Firebase), Organization & Public Repo Secret Hunting, Supply Chain & Dependency Confusion.
8. **`network-portscan` (Full TCP Port & Service Discovery)** — `.agents/skills/network-portscan/SKILL.md`
   - *Pipeline:* Inherits authorized live subdomains, scans ports 1–65535 with Naabu/Nmap/Masscan, and validates discovered services with targeted Nmap probes.
9. **`subdomain-takeover` (50 Checks)** — `.agents/skills/subdomain-takeover/SKILL.md`
   - *Pipeline:* Audits dangling DNS and decommissioned cloud/SaaS bindings with non-destructive evidence thresholds and a complete 50-row coverage ledger.
10. **`server-config-audit` (102 Checks)** + merged: `tls-audit` — `.agents/skills/server-config-audit/SKILL.md`
   - *Pipeline:* Audits web-server defaults, modules, consoles, security headers, and HTTP/2 controls with passive, bounded, credential-gated, mutation-gated, and lab-only execution classes.

### Phase 2: Authentication & Access Control Auditing
11. **`credentialattacks` (40 Checks)** — `.agents/skills/credentialattacks/SKILL.md`
   - *Subagents (5):* Password Policies & Encodings, Brute-Force & Rate Limiting, Reset Flows & Takeover Risks, 2FA/MFA Bypass & OTP, Client-Side Transport & Sessions.
12. **`authbypass` (40 Checks)** — `.agents/skills/authbypass/SKILL.md`
   - *Subagents (6):* Injections & Semantic Bypasses, Protocol & Middleware Headers, Registration/Mass Assignment & Identity Collisions, Verification/OTP & Account Takeovers, Enumeration & Defensive Controls, Stored Input in Identity Fields & Public Forms.
13. **`session-management` (40 Checks)** — `.agents/skills/session-management/SKILL.md`
   - *Subagents (5):* Token Generation & Exposure, Session Lifecycle (fixation/logout/timeout), Cookie Attributes & Transport, Binding & Cross-Channel (WebSocket/CSRF/refresh), JWT Deep Testing.
14. **`oauth-sso` (50 Checks)** — `.agents/skills/oauth-sso/SKILL.md`
   - *Subagents (6):* Redirect URI & Front-Channel Leakage, State/CSRF & Account Linking, Code/Token & Client Security, OpenID Connect & SSO Session, SAML, Enterprise Directory Auth (Kerberos/NTLM/LDAP).

### Phase 3: Vulnerability & Application Logic Auditing
15. **`ssrf-audit` (55 Checks)** — `.agents/skills/ssrf-audit/SKILL.md`
    - *Subagents (6):* Entry Points & Discovery, Document & Media Renderers, Filter Bypass: IP Formats & DNS, Filter Bypass: Parsers/Redirects & Rebinding, Cloud & Container Metadata, Internal Network/Protocols & Impact (O/R/S/W/N execution classes; white-box appendix WB-1..8).
16. **`idor` (35 Checks)** — `.agents/skills/idor/SKILL.md`
    - *Subagents (5):* Identifier Discovery & Predictability, Identifier Locations, Methods/Versions & Channels, Feature-Specific Objects, Roles/Writes & Indirect References.
17. **`access-control` (37 Checks)** — `.agents/skills/access-control/SKILL.md`
    - *Subagents (5):* Role & Identity Claims, Admin Surface & Request Tricks, Architecture Layers (gateway/UI/GraphQL/cache/API keys), Tenancy/Membership & Sharing, Features/Data & State (flags, races, backup/import, demotion, approvals, entitlements).
18. **`path-traversal` (39 Checks)** — `.agents/skills/path-traversal/SKILL.md`
    - *Subagents (5):* Traversal Sequences & Encodings, Validation Bypass & Platform Specifics, Feature Sinks, Inclusion & Archives, Target Files & Impact (R/S/W/X execution classes).
19. **`sqli` (50 Checks)** — `.agents/skills/sqli/SKILL.md`
    - *Subagents (5):* Injection Point Discovery, Detection Techniques (UNION/error/boolean/time/OOB/inference), Query-Context Injection (ORDER BY/LIMIT/LIKE/IN/identifiers/ORM/second-order), Filter & WAF Bypass, DBMS-Specific & Impact (D/P/S/W/X execution classes).
20. **`xss` (60 Checks)** — `.agents/skills/xss/SKILL.md`
    - *Subagents (6):* Reflection Surfaces, Stored/Blind & Rendering Pipelines, DOM/Frameworks & Cross-Origin (postMessage, clobbering, prototype pollution, XSSI/JSONP), Element & Event Vectors, URL/Navigation & Scriptless, Bypass/CSP & Impact (R/E/S/B/I execution classes).
    - *Subagents (4):* Pricing & Financial Parameter Manipulation, Multi-Step Workflows & State Machines, Concurrency & Race Conditions (TOCTOU), Defensive Business Rules.
21. **`api-security` (25 Checks)** — `.agents/skills/api-security/SKILL.md`
    - *Subagents (4):* Documentation & Schema Discovery (Swagger/WSDL), GraphQL Security & Query Limits, Object & Function Authorization (BOLA/BFLA), Defensive API Gateways.
22. **`resource-exhaustion` (25 Checks)** — `.agents/skills/resource-exhaustion/SKILL.md`
    - *Subagents (4):* Destructive Action Re-Authentication, Velocity Controls & Form Limits, Payload & Memory Bounds, Backend Queue & Storage Protections.

---

## Extended Skills and Routing (added)

Smart start: `scripts/route_target.py` reads recon artifacts (fingerprints, parameters, URLs) and prints the skills and checklist rows to start. It is passive and never sends traffic. Matches are leads. Verify before reporting.

| Skill | Role | Checklist file |
|---|---|---|
| `target-router` | Planning and routing | `scripts/route_target.py` (indexes all `references/` tables) |
| `tech-stack-audit` | Product exposure and version checks (about 470 checks) | `references/cms-ecommerce.md`, `frameworks-languages.md`, `devops-containers.md`, `monitoring-databases-queues.md`, `identity-network-iot.md`, `enterprise-collab-erp.md` |
| `saas-third-party-exposure` | Vendor tags and client-side keys | `references/saas_tags_and_keys.md` |
| `open-redirect-and-header-injection` | Redirects, CRLF, Host header | `references/redirect_and_crlf.md` |
| `server-side-injection` | SSTI, command injection, XXE, NoSQL, LDAP, deserialization | `references/ssti_cmdi_xxe_nosql_ldap_deser.md` |
| `csrf-audit` + merged: `csrf-and-headers-audit`, `clickjacking-audit` | CSRF, clickjacking, headers, CSP | `references/csrf_clickjacking_headers.md` |
| `request-smuggling-audit` + merged: `http-protocol-cache` | Smuggling, HTTP/2, cache, WAF | `references/smuggling_cache_h2.md` |
| `client-side-js-security` + merged: `postmessage-audit`, `websocket-audit` | Prototype pollution, postMessage, storage, service workers, WebSockets | `references/prototype_postmessage_storage_sw.md` |
| `file-upload-audit` | Upload handling (UP-* and FU-001 to FU-020) | `references/upload_checks.md`, `upload_vuln_checklist.md`; `scripts/upload_testfiles.py` |
| `email-security-audit` | SPF, DKIM, DMARC, CAA, BIMI, MX hygiene, mail forms, SMTP enumeration (MAIL + EM-001 to EM-025) | `references/spf_dkim_dmarc.md`, `email_checklist_extended.md`; `scripts/email_dns_audit.py` |
| `ssti-audit` | Server-side template injection: engine matrix, injection points, blind SSTI | `references/ssti_checklist.md`; probe tool `scripts/ssti_probe.py` |
| `command-injection-audit` | OS command injection: separators, substitution, blind and OOB, source sinks | `references/cmdi_checklist.md`; `scripts/cmdi_probe.py`, `scripts/sink_scan.py` |
| `nosql-injection-audit` | NoSQL operator and syntax injection (MongoDB and similar) | `references/nosql_checklist.md`; `scripts/nosql_probe.py` |
| `ldap-injection-audit` | LDAP filter injection | `references/ldap_checklist.md`; `scripts/ldap_probe.py` |
| `xml-xxe-audit` + merged: `soap-api-audit` | XML injection, XXE, XInclude, XSLT, XPath | `references/xxe_checklist.md`; `scripts/xxe_probe.py`, `scripts/xml_parser_scan.py` |
| `business-logic-vulns` + merged: `business-logic`, `race-conditions` | 20 business logic checks: price, quantity, currency, discounts, referrals, races, double spend, payment bypass, transfers, quotas, workflow/state, refunds, trials, feature flags, tiers, verification | `references/logic_vuln_checklist.md`; tracker `references/logic_vuln_tracker.md` |
| `business-logic-vulns` + merged: `business-logic`, `race-conditions` | 15 race checks + "only N times" limit sweep (OTP resend, invites, votes, coupons, teams) | `references/race_checklist.md`; tracker `references/race_tracker.md`; probe `scripts/race_probe.py` |
| `csrf-audit` + merged: `csrf-and-headers-audit`, `clickjacking-audit` | Deep CSRF: 20 core checks, bypass matrix, PoC templates, reports and writeups | `references/csrf_checklist.md`, `csrf_poc_templates.md`, `csrf_reports_and_writeups.md`; `scripts/csrf_probe.py`, `scripts/csrf_token_analyze.py` |
| `cors-audit` | Deep CORS: 15 core checks, bypass origin matrix, impact chains, concepts, PoCs, tools and writeups | `references/cors_checklist.md`, `cors_concepts.md`, `cors_poc_templates.md`, `cors_reports_and_tools.md`; `scripts/cors_probe.py` |
| `csrf-audit` + merged: `csrf-and-headers-audit`, `clickjacking-audit` | Clickjacking: 10 core checks, variants and bypasses, PoC templates | `references/clickjacking_checklist.md`, `clickjacking_poc_templates.md`; `scripts/clickjack_check.py` |
| `client-side-js-security` + merged: `postmessage-audit`, `websocket-audit` | postMessage listeners and senders: origin/source checks, sinks, wildcard targets, iframes, extensions | `references/postmessage_checklist.md`, `postmessage_poc_templates.md`; `scripts/pm_scan.py` |
| `file-download-audit` | File download and access: traversal, listing, MIME, disposition, auth, IDOR, cloud URLs, sensitive files, symlinks, PDF generation | `references/download_checklist.md`; `scripts/download_check.py` |
| `server-config-audit` + merged: `tls-audit` | TLS/SSL configuration: 20 checks plus extras | `references/tls_checklist.md`; `scripts/tls_quick.py`, `scripts/tls_map_testssl.py` |
| `crypto-audit` | Cryptographic implementation: 15 checks plus variants, black-box procedures | `references/crypto_checklist.md`; `scripts/crypto_scan.py`, `scripts/cipher_analyze.py` |
| `request-smuggling-audit` + merged: `http-protocol-cache` | HTTP request smuggling: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, chains, WAF and cache impact, variants | `references/smuggling_checklist.md`, `smuggling_poc_templates.md`; `scripts/smuggle_timing.py` |
| `cache-poisoning-audit` | Web cache poisoning and deception: unkeyed inputs, normalization, deception, CPDoS, CDN notes | `references/cache_checklist.md`, `cache_poc_templates.md`; `scripts/cache_probe.py` |
| `cloud-container-audit` | Cloud storage, metadata via SSRF, Docker/Kubernetes/etcd exposure, IAM, functions, databases, queues, CDN | `references/cloud_container_checklist.md`, `metadata_endpoints.md`, `iam_privesc.md`; `scripts/cloud_exposure_check.py` |
| `data-exposure-audit` | Sensitive data in pages, JS, files, headers, cookies, storage, API responses, URLs, Referer | `references/data_exposure_checklist.md`, `browser_storage_dump.md`; `scripts/exposure_scan.py`, `scripts/api_pii_scan.py` |
| `error-handling-audit` | Error disclosure, enumeration differentials, error pages, API status codes, GraphQL errors | `references/error_handling_checklist.md`; `scripts/error_probe.py` |
| `client-side-js-security` + merged: `postmessage-audit`, `websocket-audit` | WebSocket auth, CSWSH, Origin, tampering, replay, IDOR, injection, rate limits, session, downgrade | `references/websocket_checklist.md`, `websocket_poc_templates.md`; `scripts/ws_probe.py` |
| `graphql-audit` | GraphQL schema exposure, cost controls, authorization, injection, subscriptions, persisted queries | `references/graphql_checklist.md`, `graphql_queries.md`; `scripts/gql_probe.py` |
| `api-security` (extended) | API auth/authz AA-001 to AA-025 and injection AI-001 to AI-015 | `references/api_auth_checklist.md`, `api_injection_checklist.md`; `scripts/api_probe.py` |
| `rest-api-audit` | REST CRUD authz lifecycle, methods, HEAD/OPTIONS, headers, status codes, HATEOAS, pagination, sort/filter, versions | `references/rest_checklist.md`; `scripts/rest_probe.py` |
| `xml-xxe-audit` + merged: `soap-api-audit` | SOAP/WSDL, SOAPAction, XML injection, XXE, WS-Security, replay, faults, encoding, namespaces | `references/soap_checklist.md`, `soap_templates.md`; `scripts/soap_probe.py` |
| `grpc-audit` | gRPC reflection, auth, protobuf, transport (TLS/h2c/gRPC-Web), metadata, deadlines, credentials | `references/grpc_checklist.md`, `grpc_commands.md`; `scripts/grpc_probe.py` |
| `google-dorking-osint` | Passive search-engine and OSINT recon: 49 dorks, third-party leak sites, Wayback, GitHub code search | `references/dork_checklist.md`, `dork_extras.md`; `scripts/dork_gen.py`, `scripts/dork_triage.py` |
| `jsrecon` (extended) | JavaScript analysis JSA-001 to JSA-050: secrets, routes, sinks, frameworks, browser APIs, storage, workers, CSP/Trusted Types gadgets, third-party scripts | `references/js_analysis_checklist.md`; `scripts/js_analyzer.py`, `scripts/js_sink_audit.py` |

Existing skills gained extension files (listed in each `SKILL.md` under "Extended checklist (added)"). Class policy applies to every row: `passive` and `bounded` run in scope with stated limits, and `authorized-only` needs explicit approval for that check.

## Authorization Gate (all agents and subagents)
No agent or subagent assumes a target is authorized. Before any active step, the target must pass `scripts/scope_check.sh TARGET_DOMAIN`, which requires `~/Documents/bugbounty/TARGET_DOMAIN/scope.txt` with `authorized-by:`, `date:`, and in-scope lines. A target named in a prompt is not authorization. Runners that accept `--target` run the same gate and refuse to start when it fails.

## Field Reproduction Playbooks (Synthesized from Reports & Lectures)
The framework includes actionable step-by-step reproduction playbooks extracted from real-world bug bounty findings and the TBHM lecture series:
- **Authentication & Session:** `.agents/skills/authbypass/references/session_puzzling_and_otp_playbook.md` — Session Puzzling, Response Manipulation ATO, and HPP OTP routing.
- **Credential Attacks & Rate Limits:** `.agents/skills/credentialattacks/references/otp_rate_limiting_and_dos_playbook.md` — OTP rate-limiting bypass via IP headers and SMS financial exhaustion.
- **SSRF & Cloud Metadata:** `.agents/skills/ssrf-audit/references/realworld_ssrf_reproduction_guide.md` — Image proxy SSRF, AWS IMDSv1 extraction, and internal port scanning timing deltas.
- **Business Logic Flaws:** `.agents/skills/business-logic-vulns/references/merged/business-logic/references/realworld_logic_flaws_playbook.md` — Comment/portal HTML injection, invite email abuse, and state machine skipping.
- **Access Control & IDOR:** `.agents/skills/access-control/references/idor_and_privilege_reproduction_playbook.md` — Horizontal IDOR in KYC states and multi-tenant boundary tampering.
- **CI/CD & DevOps Exposure:** `.agents/skills/contentdiscovery/references/cicd_devops_exposure_playbook.md` — Jenkins workspace & credentials store leakage, Jira CVE-2019-14994, and EXIF geolocation leaks.
- **Recon & Attack Surface:** `.agents/skills/subdomainenum/references/haddix_lecture_recon_playbook.md` — Jason Haddix TBHM Lectures 1–8 scoping, dorking, and JS pipeline.

---

## Unified Wordlists & Payloads Directory (`wordlists/`)
All wordlists, dictionaries, and payload files are consolidated into `wordlists/` and indexed in `wordlists/README.md`:
- **Directory Paths & Fuzzing:** `wordlists/MiniFuzz.txt`, `wordlists/God-Fuzz.txt`, `wordlists/XMLFuzz.txt`, `wordlists/needstobefixed.txt`
- **Parameters:** `wordlists/params.txt`
- **APIs & Web Services:** `wordlists/api.txt`, `wordlists/API-FUZZ.txt`, `wordlists/SwaggerAPI.txt`, `wordlists/wad.txt`, `wordlists/svc.txt`
- **Sensitive Files & Configs:** `wordlists/env.txt`, `wordlists/dotfiles.txt`, `wordlists/config.txt`, `wordlists/webconfig.txt`, `wordlists/git_config.txt`, `wordlists/zip.txt`, `wordlists/sql.txt`, `wordlists/log.txt`, `wordlists/keys.txt`, `wordlists/web-inf.txt`
- **CMS & Administration:** `wordlists/WPfuzz.txt`, `wordlists/wp-content.txt`, `wordlists/phpmyadmin.txt`, `wordlists/adminer.txt`, `wordlists/JiraFuzz.txt`, `wordlists/JIra-Domains.txt`
- **Payloads & Bypasses:** `wordlists/OR-Payloads.txt`, `wordlists/windows-lfi.txt` (used by `path-traversal`), `wordlists/sqltesting.txt`, `wordlists/sqlbypass.txt` (used by `sqli`)

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
- `artifacts/live_subdomains.txt`
- `artifacts/resolved_subdomains.json`
- `artifacts/technology_profile.json`
- `artifacts/discovered_endpoints.txt`
- `artifacts/sensitive_files.txt`
- `artifacts/exposed_admin_panels.txt`
- `artifacts/discovered_parameters.json`
- `artifacts/cloud_storage_findings.txt`
- `artifacts/org_secrets_findings.json`
- `artifacts/dep_confusion_candidates.txt`
- `artifacts/network_portscan/`
- `artifacts/takeover_checklist_50.tsv`
- `artifacts/subdomain_takeover_report.md`
- `artifacts/server_config/`
- `artifacts/recon_hunter_ranked_report.txt`
- `artifacts/credential_audit_report.json`
- `artifacts/auth_bypasses_confirmed.txt`
- `artifacts/authbypass/authbypass_checklist_40.tsv`
- `artifacts/session/session_checklist_40.tsv`
- `artifacts/session_management_report.md`
- `artifacts/oauth/oauth_checklist_50.tsv`
- `artifacts/oauth_sso_report.md`
- `artifacts/ssrf/surface_map.md`, `artifacts/ssrf/probe*.tsv`, `artifacts/ssrf/listener_hits.jsonl`, `artifacts/ssrf/cleanup.md`
- `artifacts/ssrf/ssrf_checklist_55.tsv`
- `artifacts/ssrf_report.md`
- `artifacts/idor_vulnerability_matrix.json`
- `artifacts/idor/idor_checklist_35.tsv`
- `artifacts/idor_report.md`
- `artifacts/access_control/access_control_checklist_37.tsv`
- `artifacts/privilege_escalation_report.md`
- `artifacts/path_traversal/path_traversal_checklist_39.tsv`
- `artifacts/path_traversal_report.md`
- `artifacts/sqli/sink_map.md`
- `artifacts/sqli/probe_*.tsv`, `artifacts/sqli/probe_*_verdicts.json`
- `artifacts/sqli/sqli_checklist_50.tsv`
- `artifacts/sqli_report.md`
- `artifacts/xss/reflection_map.md`, `artifacts/xss/reflect*.tsv`, `artifacts/xss/dom_sinks.tsv`, `artifacts/xss/xssi/xssi.tsv`
- `artifacts/xss/stored_payloads.md`, `artifacts/xss/blind_hits.jsonl`
- `artifacts/xss/xss_checklist_60.tsv`
- `artifacts/xss_report.md`
- `artifacts/business_logic_flaws_report.json`
- `artifacts/api_security_audit_report.json`
- `artifacts/resource_exhaustion_audit_report.json`
