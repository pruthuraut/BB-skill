---
name: resource-exhaustion
description: Master application resource exhaustion and velocity control auditing skill for assessing rate limiting, form flood prevention, sensitive action re-authentication, and denial of service mitigations.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `resource-exhaustion` — Application Resource & Velocity Control Auditing Skill

## Overview
`resource-exhaustion` is a specialized vulnerability auditing skill designed to evaluate application resilience against resource exhaustion, unconstrained form flooding, missing re-authentication on destructive actions, and application-layer denial of service (DoS). It translates real-world submission reports and rate-limiting audit patterns into a deterministic **25-point assessment**.

```
                           [ CLIENT REQUESTS / INPUTS ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Destructive    │          │  Velocity &     │          │  Payload &      │
  │  Re-Authentication         │  Form Limits    │          │  Memory Bounds  │
  │  (Checks 01-02, │          │  (Checks 03-05, │          │  (Checks 06-11) │
  │   23-24)        │          │   19-22)        │          │                 │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │  Subagent 04    │
                               │  Infrastructure │
                               │  & Queue Limits │
                               │  (Checks 12-18, │
                               │   25)           │
                               └────────┬────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT REPORT ]
                       • resource_exhaustion_audit_report.json
                       • velocity_mitigation_plan.md
                       • exhaustion_checklist_tracker.md (25/25 Done)
```

---

## The 4 Specialized Subagents

1. **Subagent 01: Destructive Action Re-Authentication & State Safety**
   *Checks: 01, 02, 23, 24*
   *Focus:* Verifying mandatory credential re-validation (password / MFA) prior to permanent account deletion or project destruction, concurrency locking, and soft-delete retention policies.
2. **Subagent 02: Velocity Controls & Form Flooding Mitigations**
   *Checks: 03, 04, 05, 19, 20, 21, 22*
   *Focus:* Rate-limiting on public feedback forms, abuse report flooding, resume upload velocity, `HTTP 429 Too Many Requests` responses with `Retry-After`, `X-Forwarded-For` validation, and progressive CAPTCHA triggers.
3. **Subagent 03: Payload Boundaries & Memory Exhaustion Controls**
   *Checks: 06, 07, 08, 09, 10, 11*
   *Focus:* Strict request body byte limits, maximum multipart upload size enforcement, pixel-flood image decompression limits, archive decompression safety, XML external entity disabling, and ReDoS regex safety.
4. **Subagent 04: Backend Capacity, Queue & Database Protections**
   *Checks: 12, 13, 14, 15, 16, 17, 18, 25*
   *Focus:* Database pagination maximum limits, batch operation array size caps, asynchronous background worker queue throttles, disk storage quotas, cache TTL eviction, Slowloris HTTP timeouts, and header size restrictions.

---

## Standard Output Artifacts
* `artifacts/resource_exhaustion_audit_report.json` — Comprehensive audit matrix of all evaluated endpoints and rate-limiting behaviors.
* `artifacts/velocity_mitigation_plan.md` — Defensive architecture recommendations and token-bucket / leaky-bucket configurations.
* `artifacts/exhaustion_checklist_tracker.md` — Complete 25-point verification record.
