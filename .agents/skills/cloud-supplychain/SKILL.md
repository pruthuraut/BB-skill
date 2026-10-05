---
name: cloud-supplychain
description: Master cloud storage bucket discovery, Firebase database auditing, GitHub organization secret hunting, and npm dependency confusion assessment skill based on TBHM and modern offensive supply-chain methodologies.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `cloud-supplychain` — Universal Cloud Storage, Org Secrets & Dependency Confusion Skill

## Overview
`cloud-supplychain` is an offensive reconnaissance and asset assessment skill designed to evaluate perimeter cloud assets, unauthenticated storage containers, public organization repositories, and software package supply chains. It audits AWS S3, Google Cloud Storage (GCS), Azure Blob containers, Firebase Realtime Databases, corporate GitHub/GitLab orgs, and internal package registry namespaces.

```
                                 [ TARGET ORGANIZATION / APEX ]
                                                │
             ┌──────────────────────────────────┼──────────────────────────────────┐
             ▼                                  ▼                                  ▼
    ┌─────────────────┐                ┌─────────────────┐                ┌─────────────────┐
    │  Subagent 01    │                │  Subagent 02    │                │  Subagent 03    │
    │  Cloud Storage  │                │  Org Secret     │                │  Dependency     │
    │  & Buckets      │                │  Hunting        │                │  Confusion      │
    │  (S3, GCS, Blob)│                │  (GitHub/GitLab)│                │  (NPM Registry) │
    └────────┬────────┘                └────────┬────────┘                └────────┬────────┘
             │                                  │                                  │
             └──────────────────────────────────┼──────────────────────────────────┘
                                                ▼
                                   [ CONSOLIDATED ARTIFACTS ]
                                   • cloud_buckets_verified.txt
                                   • firebase_databases.txt
                                   • org_secrets_verified.json
                                   • dependency_confusion_candidates.txt
                                   • supply_chain_checklist_tracker.md
```

---

## The 3 Specialized Subagents

1. **[Subagent 01: Cloud Storage & Unauthenticated Database Auditing](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/cloud-supplychain/subagents/subagent_01_cloud_buckets_s3_gcs_azure.md)**
   *Focus:* Multi-cloud bucket name permutation guessing (AWS S3, Google Cloud Storage, Azure Blob Storage) from apex domain, brand keywords, and environment prefixes; unauthenticated ListObjects extraction; and Firebase Realtime Database shallow querying (`/.json?shallow=true`).
2. **[Subagent 02: Organization & Public Repository Secret Hunting](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/cloud-supplychain/subagents/subagent_02_org_secret_hunting.md)**
   *Focus:* Corporate GitHub and GitLab organization footprinting, multi-repo enumeration via GitHub CLI (`gh repo list`), TruffleHog GitHub org scanning with cryptographic verification, Gitleaks commit history audits, and NoseyParker regex extraction.
3. **[Subagent 03: Supply Chain & Dependency Confusion Auditing](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/cloud-supplychain/subagents/subagent_03_dependency_confusion.md)**
   *Focus:* Mining discovered web manifests (`package.json`, `requirements.txt`, `composer.json`), extracting private internal dependency packages, querying public registries (npm, PyPI) for HTTP 404 unallocated namespaces, and verifying internal naming conventions to eliminate false positives.

---

## Master Orchestration Workflow

When this skill is executed for a target (`TARGET_DOMAIN="example.com"`, `ORG_NAME="example-corp"`):
1. **Permutation Generation:** Generate multi-cloud bucket candidates using target domain roots, prefixes (`dev-`, `staging-`, `assets-`, `cdn-`), and suffixes (`-prod`, `-backup`).
2. **Bucket Probing:** Query AWS S3, GCS, and Azure Blob REST APIs. Isolate public `ListBucketResult` XML responses from `AccessDenied` responses.
3. **Firebase RTDB Probing:** Query Firebase RTDB endpoints with `?shallow=true` to verify unauthenticated JSON reads without downloading massive datasets.
4. **Org Repository Auditing:** Query public organization repositories for cryptographic secrets using TruffleHog and Gitleaks.
5. **Dependency Confusion Analysis:** Collect all dependencies from recon `package.json` files and check public npm registry availability.

---

## Severity Kill Rules (Triage Standards)
- **KILL** — S3 / GCS / Azure bucket exists but `ListObjects` returns HTTP 403 `AccessDenied` (bucket name discovery alone is not a vulnerability).
- **KILL** — Dependency confusion package name that does not strictly match internal proprietary namespace patterns or is already reserved publicly.
- **KILL** — Public organization repository containing only public open-source project code without company credentials, internal hostnames, or private tokens.
- **KEEP** — Publicly readable bucket containing sensitive documents, PII, backups, or source code.
- **KEEP** — Firebase database returning unauthenticated records via `/.json?shallow=true`.
- **KEEP** — Internal dependency name returning HTTP 404 on `registry.npmjs.org` with clear internal company naming prefix.

---

## Standard Output Artifacts
- `artifacts/cloud_storage_findings.txt` — Confirmed public S3, GCS, Azure buckets, and Firebase DBs.
- `artifacts/org_secrets_findings.json` — Verified credentials in organization repositories.
- `artifacts/dep_confusion_candidates.txt` — Confirmed unclaimed internal packages on npm.
- `artifacts/cloud_supplychain_report.md` — Consolidated assessment report.
