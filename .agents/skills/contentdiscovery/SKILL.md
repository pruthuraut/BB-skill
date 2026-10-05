---
name: contentdiscovery
description: Master content & URL discovery skill for exhaustive 50-point directory/file fuzzing, sensitive data leak auditing (.env, .git, backups), administrative console probing, and API endpoint extraction using TBHM v4 and tailored wordlists.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# `contentdiscovery` — Universal Content & URL Discovery Skill

## Overview
`contentdiscovery` is an offensive content enumeration and endpoint discovery skill designed to execute an exhaustive **50-point content discovery audit**. It implements Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)*, integrating smart recursive fuzzing (`ffuf`, `feroxbuster`, `dirsearch`), historical URL mining (`gau`, `waybackurls`), JavaScript endpoint extraction (`katana`), sensitive file auditing (`.env`, `.git`, backups, database dumps), and enterprise/DevOps portal probing using tailored wordlists from `wordlists/` and `wordlists/`.

```
                                [ TARGET HOST / URL ]
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
   │  Subagent 01    │           │  Subagent 02    │           │  Subagent 03    │
   │  Fuzzers &      │           │  Historical     │           │  Well-Known,    │
   │  Crawlers       │           │  JS & OSINT     │           │  SEO & Identity │
   │  (4 Checks)     │           │  (5 Checks)     │           │  (8 Checks)     │
   └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
            │                             │                             │
            └─────────────────────────────┼─────────────────────────────┘
                                          ▼
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
   │  Subagent 04    │           │  Subagent 05    │           │  Subagent 06    │
   │  Sensitive Files│           │  Debug, Logs    │           │  Admin Panels   │
   │  Backups & Git  │           │  & API Docs     │           │  & DevOps Cons. │
   │  (12 Checks)    │           │  (5 Checks)     │           │  (16 Checks)    │
   └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
            │                             │                             │
            └─────────────────────────────┴─────────────────────────────┘
                                          ▼
                         [ FINAL CONSOLIDATED ARTIFACTS ]
                         • discovered_endpoints.txt
                         • sensitive_files.txt
                         • exposed_admin_panels.txt
                         • leaked_secrets.txt
                         • checklist_50_tracker.md (50/50 Done)
```

---

## The 6 Specialized Subagents

1. **[Subagent 01: High-Speed Recursive Fuzzers & Crawlers](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_01_fuzzers_crawlers.md)**
   *Checks: 01, 02, 03, 04*
   *Wordlists:* `wordlists/MiniFuzz.txt`, `wordlists/God-Fuzz.txt`.
2. **[Subagent 02: Historical Crawling, JS Extraction & Public OSINT Leaks](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_02_historical_js_osint.md)**
   *Checks: 22, 23, 24, 25, 26*
   *Methodology:* Archive mining (`gau`, `waybackurls`), live JS bundle crawling (`katana`), dev subdomain mapping, and Google Docs/Sheets dorking.
3. **[Subagent 03: Well-Known, SEO & Identity Federation Discovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_03_wellknown_identity_seo.md)**
   *Checks: 05, 06, 07, 46, 47, 48, 49, 50*
   *Focus:* `robots.txt`, `sitemap.xml`, `security.txt`, OpenID Connect schemas, OAuth discovery, Android `assetlinks.json`, and iOS universal links.
4. **[Subagent 04: Sensitive Files, Source Leaks, Backups & Credentials](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_04_sensitive_files_backups.md)**
   *Checks: 08, 09, 10, 11, 12, 13, 14, 27, 28, 29, 30, 31*
   *Wordlists:* `env.txt`, `dotfiles.txt`, `git_config.txt`, `zip.txt`, `sql.txt`, `config.txt`, `webconfig.txt`, `yaml.txt`.
5. **[Subagent 05: Debug Endpoints, Test Files & API Documentation](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_05_debug_logs_api_docs.md)**
   *Checks: 15, 16, 17, 18, 34*
   *Wordlists:* `log.txt`, `phpunit.txt`, `api.txt`.
6. **[Subagent 06: Admin Consoles, DevOps Panels & Enterprise Portals](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/subagents/subagent_06_admin_devops_portals.md)**
   *Checks: 19, 20, 21, 32, 33, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45*
   *Wordlists:* `phpmyadmin.txt`, `adminer.txt`, `WPfuzz.txt`, `JiraFuzz.txt`.

For detailed wordlist categorization and real-world reproduction playbooks, see:
- [Wordlists Guide & Resource Mapping](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/references/wordlists_guide.md)
- [CI/CD, DevOps Exposure & Information Disclosure Playbook](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/references/cicd_devops_exposure_playbook.md)

---

## Master Orchestration Workflow

When auditing a target (`TARGET_URL="https://example.com"`):

### Phase 1: Passive & Structural Harvesting (Subagents 02, 03)
* Query archives via `waybackurls` and `gau`.
* Extract endpoints from live JavaScript bundles (`katana -jc`).
* Parse `robots.txt` Disallowed entries and `sitemap.xml`.
* Audit `/.well-known/openid-configuration`, `security.txt`, and mobile link schemas.
* Search for publicly indexed Google Spreadsheets/Docs.

### Phase 2: Active Recursive Fuzzing (Subagent 01)
* Run `ffuf` with recursion depth 2 and smart status code filtering (`-mc 200,301,302,401,403 -ac`) using `MiniFuzz.txt`.
* Run `dirsearch` with multiple extensions (`php,asp,aspx,jsp,html,json,txt`).

### Phase 3: Critical Exposures & Sensitive File Hunting (Subagent 04)
* Fuzz for `.env` and `.env.local` using `wordlists/env.txt`.
* Probe for exposed `.git/HEAD` and `.git/config` using `git_config.txt`.
* Fuzz for database dumps (`.sql`, `.db`) using `sql.txt`.
* Fuzz for backup archives (`.zip`, `.tar.gz`) using `zip.txt`.
* Check for Dockerfiles, `package.json`, and `.htpasswd`.

### Phase 4: Debug Routines, Logs & Telemetry (Subagent 05)
* Fuzz for log files (`error.log`, `access.log`) using `wordlists/log.txt`.
* Probe for `/debug`, `/trace`, `/healthz`, and Prometheus `/metrics`.
* Check for PHPUnit test files (`wordlists/phpunit.txt`) and `phpinfo.php`.
* Fuzz for API documentation using `api.txt`.

### Phase 5: Administration Consoles & Middleware Portals (Subagent 06)
* Fuzz for database managers (phpMyAdmin, Adminer).
* Fuzz for CMS panels (WordPress `wp-admin`, Joomla).
* Probe default DevOps ports: Grafana (`:3000`), Kibana (`:5601`), Airflow (`:8080`), RabbitMQ (`:15672`), Solr (`:8983`), MinIO (`:9001`).
* Audit enterprise middleware consoles: Tomcat (`/manager/html`), JBoss, WebLogic, WebSphere.
* Fuzz Atlassian Jira (`/secure/admin/`) and Confluence (`/admin/`) using `JiraFuzz.txt`.

---

## Standard Output Artifacts
Each run populates the `artifacts/` folder:
* `artifacts/discovered_endpoints.txt` — Deduplicated list of valid HTTP 200/301 endpoints.
* `artifacts/sorted_categories/` — URL Categorization directory:
  - `api_urls.txt` (REST, GraphQL, Swagger, OpenAPI, JSON)
  - `admin_urls.txt` (Admin, Dashboard, Staff, Portals, Management)
  - `debug_urls.txt` (Debug, Actuator, Metrics, Health, Profiler, PHPinfo)
  - `db_urls.txt` (phpMyAdmin, Adminer, SQL dumps, database backups)
  - `php_urls.txt` (PHP scripts, legacy handlers, installation files)
  - `auth_urls.txt` (Login, Registration, 2FA, Password Reset, OAuth, SSO)
  - `sensitive_urls.txt` (Config files, .env, .git, backup archives)
  - `upload_urls.txt` (File upload, avatar, and attachment endpoints)
  - `idor_urls.txt` (Parameterized ID routes for IDOR / BOLA testing)
  - `params_urls.txt` (Parameterized query URLs for injection fuzzing)
* `artifacts/sensitive_files.txt` — Discovered `.env`, `.git`, backup archives, and database dumps.
* `artifacts/exposed_admin_panels.txt` — Reachable administrative consoles and DevOps dashboards.
* `artifacts/checklist_50_tracker.md` — Complete 50/50 audit verification matrix.
