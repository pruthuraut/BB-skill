---
name: access-control
description: Master Broken Access Control (BAC) and Insecure Direct Object Reference (IDOR) auditing skill for systematic evaluation of horizontal IDOR, vertical privilege escalation, multi-tenant boundaries, and authorization architecture based on TBHM Module 14.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `access-control` — Universal Broken Access Control & IDOR Auditing Skill

## Overview
`access-control` is an offensive access control and authorization evaluation skill designed to execute a **25-point audit** against Broken Object-Level Authorization (BOLA), Insecure Direct Object References (IDOR), vertical privilege escalation, and multi-tenant isolation breaches. It incorporates Jason Haddix's *TBHM Module 14 (IDOR Tips and Tricks)* and core HackerOne disclosure patterns (`Broken Access Control/IDOR WRITEUP.txt`).

```
                              [ API ENDPOINT / OBJECT ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Horizontal     │          │  Vertical       │          │  Multi-Tenant   │
  │  IDOR & BOLA    │          │  Privilege Esc. │          │  Isolation      │
  │  (Checks 01-07) │          │  (Checks 08-11) │          │  (Checks 12-16) │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │  Subagent 04    │
                               │  Defensive      │
                               │  Auth Models    │
                               │  (Checks 17-25) │
                               └────────┬────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT REPORT ]
                       • idor_vulnerability_matrix.json
                       • privilege_escalation_report.md
                       • authorization_remediation.md
                       • bac_checklist_tracker.md (25/25 Done)
```

---

## The 4 Specialized Subagents

1. **[Subagent 01: Horizontal IDOR & Object-Level Authorization](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/access-control/subagents/subagent_01_horizontal_idor.md)**
   *Checks: 01, 02, 03, 04, 05, 06, 07*
   *Focus:* Sequential integer IDs, UUID validation, read/update/delete object tampering between equal-tier users, parameter pollution (`id=1&id=2`), and nested JSON object references.
2. **[Subagent 02: Vertical Privilege Escalation & Role Boundaries](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/access-control/subagents/subagent_02_vertical_privilege_escalation.md)**
   *Checks: 08, 09, 10, 11*
   *Focus:* Administrative endpoint reachability from unprivileged accounts, HTTP method switching bypasses, role-based access control (RBAC) consistency, and user profile role parameter tampering (`role=admin`).
3. **[Subagent 03: Multi-Tenant Isolation & Shared Resources](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/access-control/subagents/subagent_03_multitenant_isolation.md)**
   *Checks: 12, 13, 14, 15, 16*
   *Focus:* Organization ID (`org_id`, `company_id`) tampering, cross-tenant workspace invites, static attachment authorization, CSV/PDF report tenant leakage, and batch/bulk array validation.
4. **[Subagent 04: Defensive Authorization Models & Code Hardening](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/access-control/subagents/subagent_04_defensive_authorization_models.md)**
   *Checks: 17, 18, 19, 20, 21, 22, 23, 24, 25*
   *Focus:* State machine transitions, GraphQL field-level resolvers, API token scoping, centralized middleware enforcement, database-layer query ownership (`WHERE user_id = :id`), indirect reference maps, and security audit logging.

For real-world case studies and step-by-step reproduction instructions on KYC verification and multi-tenant tampering, consult:
- [Real-World IDOR & Access Control Vulnerability Playbook](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/access-control/references/idor_and_privilege_reproduction_playbook.md)

---

## Master Orchestration Workflow

When auditing an application codebase or endpoint matrix:
1. **Model Identities & Roles:** Define test accounts across multiple tiers (Tenant A User, Tenant A Admin, Tenant B User, Anonymous).
2. **Matrix Endpoint Testing:** Map all endpoints passing object identifiers in paths (`/users/{id}`), query strings (`?document_id=`), or JSON bodies (`{"ticket_id": 123}`).
3. **Verify Contextual Ownership:** Ensure the backend enforces ownership binding in the query layer rather than assuming valid authentication implies authorization.
4. **Test Bulk & State Transitions:** Ensure batch updates validate every array element and that workflow states cannot be forced.
5. **Formulate Defensive Patches:** Provide code-level remediations using centralized authorization policies (e.g. Casbin, Pundit, Spring Security `@PreAuthorize`, or Prisma ownership filters).

---

## Standard Output Artifacts
* `artifacts/idor_vulnerability_matrix.json` — Matrix of endpoints tested and authorization results.
* `artifacts/privilege_escalation_report.md` — Verified vertical and horizontal privilege escalation findings.
* `artifacts/authorization_remediation.md` — Code-level patches and database query isolation patterns.
* `artifacts/bac_checklist_tracker.md` — Complete 25-point verification record.
