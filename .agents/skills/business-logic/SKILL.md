---
name: business-logic
description: Master Business Logic and Workflow Integrity auditing skill for systematic assessment of pricing manipulation, multi-step workflow circumvention, concurrency race conditions, and state machine integrity based on TBHM Modules 10 & 11.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `business-logic` — Universal Business Logic & Workflow Security Skill

## Overview
`business-logic` is a business process and workflow security auditing skill designed to execute a **25-point assessment** against financial manipulation, step-skipping, concurrency race conditions (TOCTOU), and state machine violations. It operationalizes Jason Haddix's *TBHM Module 10 (The Big Questions)* & *Module 11 (Application Heat Mapping)* alongside real-world bounty writeups (`Business Logics/`).

```
                              [ BUSINESS TRANSACTION ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Pricing &      │          │  Workflow &     │          │  Concurrency &  │
  │  Financial Flaws│          │  State Machine  │          │  Race Conditions│
  │  (Checks 01-05) │          │  (Checks 06-10) │          │  (Checks 11-20) │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │  Subagent 04    │
                               │  Defensive      │
                               │  Business Rules │
                               │  (Checks 21-25) │
                               └────────┬────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT REPORT ]
                       • business_logic_flaws_report.json
                       • workflow_bypass_analysis.md
                       • idempotency_concurrency_fixes.md
                       • business_logic_checklist_tracker.md (25/25 Done)
```

---

## The 4 Specialized Subagents

1. **Subagent 01: Pricing & Financial Parameter Manipulation**
   *Checks: 01, 02, 03, 04, 05*
   *Focus:* Server-side authoritative price lookups, negative quantities, integer boundary truncation, multi-currency conversion rounding, and fee/tax/shipping parameter tampering.
2. **Subagent 02: Multi-Step Workflows & State Machine Transitions**
   *Checks: 06, 07, 08, 09, 10, 20*
   *Focus:* Checkout step sequencing (bypassing payment directly to fulfillment), webhook HMAC signature validation, illegal order status transitions, cart tampering post-authorization, and cancellation reset states.
3. **Subagent 03: Concurrency, Rate Limits & Quota Integrity**
   *Checks: 11, 12, 13, 14, 15, 16, 17, 18, 19*
   *Focus:* Single-use coupon code race conditions (Turbo Intruder), wallet/gift-card double-spending, discount stacking logic, referral reward duplication, quota reset boundary timing, and license seat over-allocation.
4. **Subagent 04: Defensive Business Rules & Concurrency Controls**
   *Checks: 21, 22, 23, 24, 25*
   *Focus:* Authoritative server-side state models, database ACID transactions with row-level locks (`SELECT FOR UPDATE`), `Idempotency-Key` header enforcement, distributed Redis locks (Redlock), and anomaly detection monitoring.

For step-by-step reproduction instructions on rich text comment injection, email invitation abuse, and state machine skipping, consult:
- [Real-World Business Logic Flaws & Workflow Integrity Playbook](references/realworld_logic_flaws_playbook.md)

---

## Master Orchestration Workflow

When auditing an application's business processes:
1. **Map Critical Value Paths:** Trace financial transactions, credits, quotas, license seats, and state transitions.
2. **Audit Request Trust Boundaries:** Verify that prices, discounts, and order statuses are strictly derived from server-side database records.
3. **Analyze Concurrency:** Send parallel requests to single-use endpoints (coupon application, balance withdrawal) to test for Time-of-Check to Time-of-Use (TOCTOU) race conditions.
4. **Test Step Order & State Enums:** Attempt out-of-order execution across multi-step wizards.
5. **Formulate Architectural Remediations:** Provide database-level row locking patterns, idempotency key designs, and state machine validation logic.

---

## Standard Output Artifacts
* `artifacts/business_logic_flaws_report.json` — Detailed list of business logic and workflow weaknesses.
* `artifacts/workflow_bypass_analysis.md` — Sequence diagrams and state machine evaluations.
* `artifacts/idempotency_concurrency_fixes.md` — Code-level fixes for race conditions and ACID compliance.
* `artifacts/business_logic_checklist_tracker.md` — Complete 25-point verification record.

## Authorization Gate (applies to every run)

Before any active step (DNS queries beyond public resolution, HTTP requests, port scans, fuzzing, authenticated or state-changing requests, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.
