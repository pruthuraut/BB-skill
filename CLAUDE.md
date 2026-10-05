# Claude Code Assistant Guidelines: Bug Bounty & Vulnerability Skills Framework

This repository contains multi-agent skills implementing Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)* and specialized vulnerability auditing workflows derived from local repository notes.

## Available Skills & Agents

### Reconnaissance & Surface Discovery
1. **`recon-hunter` (Master 16-Phase Pipeline):** `.agents/skills/recon-hunter/SKILL.md` (Automated Recon-to-Bug Engine)
2. **`subdomainenum` (50 Checks):** `.agents/skills/subdomainenum/SKILL.md`
3. **`techfingerprint` (40 Checks):** `.agents/skills/techfingerprint/SKILL.md`
4. **`contentdiscovery` (50 Checks):** `.agents/skills/contentdiscovery/SKILL.md`
5. **`linkparamdiscovery` (40 Checks):** `.agents/skills/linkparamdiscovery/SKILL.md`
6. **`jsrecon` (JS Mining & Secrets):** `.agents/skills/jsrecon/SKILL.md`
7. **`cloud-supplychain` (Cloud & Dependency Confusion):** `.agents/skills/cloud-supplychain/SKILL.md`

### Authentication & Credential Security
8. **`credentialattacks` (40 Checks):** `.agents/skills/credentialattacks/SKILL.md`
9. **`authbypass` (30 Checks):** `.agents/skills/authbypass/SKILL.md`

### Vulnerability & Logic Auditing
10. **`ssrf-audit` (25 Checks):** `.agents/skills/ssrf-audit/SKILL.md` (SSRF, IMDSv1/v2, DNS Rebinding, Egress Controls)
11. **`access-control` (25 Checks):** `.agents/skills/access-control/SKILL.md` (Horizontal IDOR, Vertical Privilege Escalation, BOLA)
12. **`business-logic` (25 Checks):** `.agents/skills/business-logic/SKILL.md` (Price Manipulation, Race Conditions, State Machine Bypasses)
13. **`api-security` (25 Checks):** `.agents/skills/api-security/SKILL.md` (Swagger/OpenAPI Exposure, GraphQL Security, CORS)
14. **`resource-exhaustion` (25 Checks):** `.agents/skills/resource-exhaustion/SKILL.md` (Rate Limiting, Form Flooding, Destructive Action Re-Auth)

## Environment Setup & Tooling
- Run `./setup.sh` to install all required Go, Python, and system dependencies automatically.
- Consult [SETUP.md](file:///c:/Users/rautp/Documents/BBskill/SETUP.md) for full tool installation commands, provider configs, and health-check verification.

## Standard Execution Rules
- Always divide auditing across specialized subagents to preserve context fidelity.
- Update tracking checklists from 0 to N complete during assessments.
- Reference specialized wordlists under `wordlists/` (indexed in `wordlists/README.md`).
- Save all structured findings to `artifacts/`.
