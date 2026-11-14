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

## Authorization Gate (applies to every run)

Before any active step (DNS queries beyond public resolution, HTTP requests, port scans, fuzzing, authenticated or state-changing requests, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.
