# AGENTS.md — Universal Bug Bounty Multi-Agent Framework

This document specifies the agent architecture, roles, and execution workflows for automated offensive reconnaissance, technology fingerprinting, content discovery, parameter mining, credential attacks, authentication bypass, SSRF auditing, broken access control, business logic, API security, and resource exhaustion.

## System Mission
Execute complete, deterministic, and high-fidelity attack surface mapping and vulnerability auditing across granular verification checks, preventing false positives and missed assets by dividing work across specialized subagents.

---

## Agent Directory & Capabilities

### Phase 1: Reconnaissance & Attack Surface Mapping
1. **`recon-hunter` (Master 16-Phase Pipeline)** — `.agents/skills/recon-hunter/SKILL.md`
   - *Architecture:* Continuous end-to-end unauthenticated recon-to-bug pipeline coordinating all Phase 1-3 skills with strict Severity Kill Rules, 60s PoC curls, and Coverage Ledger.
2. **`subdomainenum` (50 Checks)** — `.agents/skills/subdomainenum/SKILL.md`
   - *Subagents (6):* Passive Scraping, Search Dorking, Active DNS Bruting & Wildcards, JS/Mobile Assets, Cloud Infra & SPF/DMARC, Subdomain Takeover Verification.
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

### Phase 2: Authentication & Access Control Auditing
8. **`credentialattacks` (40 Checks)** — `.agents/skills/credentialattacks/SKILL.md`
   - *Subagents (5):* Password Policies & Encodings, Brute-Force & Rate Limiting, Reset Flows & Takeover Risks, 2FA/MFA Bypass & OTP, Client-Side Transport & Sessions.
9. **`authbypass` (30 Checks)** — `.agents/skills/authbypass/SKILL.md`
   - *Subagents (5):* Injections & Semantic Bypasses, Protocol & Middleware Headers, Registration & Mass Assignment, Verification & Account Takeovers, Enumeration & Defensive Controls.

### Phase 3: Vulnerability & Application Logic Auditing
10. **`ssrf-audit` (25 Checks)** — `.agents/skills/ssrf-audit/SKILL.md`
    - *Subagents (4):* Attack Surface Identification, Cloud Metadata (IMDSv1/v2) & Internal Nets, Parser Differentials & Encodings, Defensive Architecture & DNS Pinning.
11. **`access-control` (25 Checks)** — `.agents/skills/access-control/SKILL.md`
    - *Subagents (4):* Horizontal IDOR & BOLA, Vertical Privilege Escalation, Multi-Tenant Isolation, Defensive Authorization Models.
12. **`business-logic` (25 Checks)** — `.agents/skills/business-logic/SKILL.md`
    - *Subagents (4):* Pricing & Financial Parameter Manipulation, Multi-Step Workflows & State Machines, Concurrency & Race Conditions (TOCTOU), Defensive Business Rules.
13. **`api-security` (25 Checks)** — `.agents/skills/api-security/SKILL.md`
    - *Subagents (4):* Documentation & Schema Discovery (Swagger/WSDL), GraphQL Security & Query Limits, Object & Function Authorization (BOLA/BFLA), Defensive API Gateways.
14. **`resource-exhaustion` (25 Checks)** — `.agents/skills/resource-exhaustion/SKILL.md`
    - *Subagents (4):* Destructive Action Re-Authentication, Velocity Controls & Form Limits, Payload & Memory Bounds, Backend Queue & Storage Protections.

---

## Field Reproduction Playbooks (Synthesized from Reports & Lectures)
The framework includes actionable step-by-step reproduction playbooks extracted from real-world bug bounty findings and the TBHM lecture series:
- **Authentication & Session:** `.agents/skills/authbypass/references/session_puzzling_and_otp_playbook.md` — Session Puzzling, Response Manipulation ATO, and HPP OTP routing.
- **Credential Attacks & Rate Limits:** `.agents/skills/credentialattacks/references/otp_rate_limiting_and_dos_playbook.md` — OTP rate-limiting bypass via IP headers and SMS financial exhaustion.
- **SSRF & Cloud Metadata:** `.agents/skills/ssrf-audit/references/realworld_ssrf_reproduction_guide.md` — Image proxy SSRF, AWS IMDSv1 extraction, and internal port scanning timing deltas.
- **Business Logic Flaws:** `.agents/skills/business-logic/references/realworld_logic_flaws_playbook.md` — Comment/portal HTML injection, invite email abuse, and state machine skipping.
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
- **Payloads & Bypasses:** `wordlists/OR-Payloads.txt`, `wordlists/windows-lfi.txt`, `wordlists/sqltesting.txt`, `wordlists/sqlbypass.txt`

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
- `artifacts/recon_hunter_ranked_report.txt`
- `artifacts/credential_audit_report.json`
- `artifacts/auth_bypasses_confirmed.txt`
- `artifacts/ssrf_vulnerability_report.json`
- `artifacts/idor_vulnerability_matrix.json`
- `artifacts/business_logic_flaws_report.json`
- `artifacts/api_security_audit_report.json`
- `artifacts/resource_exhaustion_audit_report.json`
