---
name: ssrf-audit
description: Master Server-Side Request Forgery (SSRF) and Cloud Metadata auditing skill for systematic identification of remote URL fetchers, parser differentials, cloud IMDS exposure, and egress architecture review based on TBHM Module 15.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `ssrf-audit` — Universal Server-Side Request Forgery Auditing Skill

## Overview
`ssrf-audit` is a specialized vulnerability auditing skill designed to execute a thorough **25-point assessment** against Server-Side Request Forgery (SSRF), internal network pivoting, and cloud instance metadata service (IMDS) exposures. It translates Jason Haddix's *TBHM Module 15 (SSRF Tips and Tricks)* and core repository research (`9thADV-SSRF1.txt`, `SSRF-Basic.txt`) into structured defensive workflows.

```
                              [ REMOTE URL / FETCHER ]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  Subagent 01    │          │  Subagent 02    │          │  Subagent 03    │
  │  Attack Surface │          │  Cloud Metadata │          │  Parser Diff.   │
  │  Identification │          │  & Internal Nets│          │  & Encodings    │
  │  (Checks 01-05) │          │  (Checks 06-12) │          │  (Checks 13-17) │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                               ┌─────────────────┐
                               │  Subagent 04    │
                               │  Defensive      │
                               │  Architecture   │
                               │  (Checks 18-25) │
                               └────────┬────────┘
                                        ▼
                       [ CONSOLIDATED AUDIT REPORT ]
                       • ssrf_vulnerability_report.json
                       • cloud_imds_exposure_risks.md
                       • remediation_architecture.md
                       • ssrf_checklist_tracker.md (25/25 Done)
```

---

## The 4 Specialized Subagents

1. **[Subagent 01: Attack Surface Identification & Ingestion Points](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/subagents/subagent_01_surface_identification.md)**
   *Checks: 01, 02, 03, 04, 05, 21*
   *Focus:* Identifying query/body parameters (`url=`, `dest=`, `feed=`, `source=`), webhook registrations, PDF/HTML converters, image import pipelines, OpenGraph preview generators, and blind OOB listeners.
2. **[Subagent 02: Cloud Metadata & Internal Network Exposure](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/subagents/subagent_02_cloud_metadata_internal_nets.md)**
   *Checks: 06, 07, 08, 09, 10, 11, 12*
   *Focus:* Auditing AWS IMDSv1 vs IMDSv2 token enforcement, GCP `Metadata-Flavor: Google` requirement, Azure IMDS headers, Kubernetes etcd / Kubelet APIs, Docker sockets, and RFC 1918 segmentation.
3. **[Subagent 03: Parser Differentials, Encodings & Scheme Restriction](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/subagents/subagent_03_parser_differentials_schemes.md)**
   *Checks: 13, 14, 15, 16, 17*
   *Focus:* URI scheme restriction (disabling `gopher://`, `file://`, `dict://`), URL parser differentials between validator and client, alternative IP encodings (decimal, hex, octal, IPv6 mapped IPv4), and 301/302 redirect following behavior.
4. **[Subagent 04: Defensive Architecture, DNS Pinning & Egress Controls](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/subagents/subagent_04_defensive_architecture.md)**
   *Checks: 18, 19, 20, 22, 23, 24, 25*
   *Focus:* DNS Rebinding resilience, resolution IP pinning, strict hostname allowlisting, network egress firewall rules, forward proxy isolation, body/content-type limits, and internal mutual TLS.

For step-by-step reproduction instructions and parser differential cheat sheets, consult:
- [Real-World SSRF, Cloud Metadata & Port Scanning Reproduction Guide](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/references/realworld_ssrf_reproduction_guide.md)

---

## Master Orchestration Workflow

When auditing an application codebase or endpoint for SSRF:
1. **Trace URL Ingestion:** Map every feature accepting remote URLs (PDF generators, import tools, webhooks).
2. **Evaluate Schema & Parser Restraints:** Confirm that non-HTTP schemes are rejected and that URL parsing libraries do not desynchronize.
3. **Inspect Resolution & Validation:** Ensure the destination IP address is resolved and verified against private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`) *before* opening the network socket.
4. **Audit Cloud Host Hardening:** Check if workloads running in cloud environments (AWS EC2, ECS, GCP, Azure) enforce IMDSv2 with token hops restricted to 1.
5. **Recommend Defensive Patches:** Provide concrete architectural controls (dedicated forward egress proxy, IP pinning code patterns, and network firewall policies).

---

## Standard Output Artifacts
* `artifacts/ssrf_vulnerability_report.json` — Detailed inventory of identified SSRF vectors.
* `artifacts/cloud_imds_exposure_risks.md` — Cloud metadata protection analysis.
* `artifacts/remediation_architecture.md` — Patching guidelines, DNS pinning routines, and egress firewall rules.
* `artifacts/ssrf_checklist_tracker.md` — Complete 25-point verification record.
