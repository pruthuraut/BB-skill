# Unified Bug Bounty Wordlists & Payloads Directory (`wordlists/`)

This directory serves as the centralized, high-performance wordlist repository accessible across all agents and skills. All non-wordlist files (lecture notes, report drafts, writeups, and documentation) have been pruned, leaving exclusively structured fuzzing lists, dictionary lists, and payload files.

---

## Wordlist Categorization Index

### 1. General Path & Directory Bruting
- `MiniFuzz.txt` (121 KB, 5,935 entries) — Fast recursive directory crawling.
- `God-Fuzz.txt` (18.7 MB, 1,343,503 entries) — Exhaustive directory and endpoint brute-forcing.
- `XMLFuzz.txt` (55.5 MB, 2,270,059 entries) — Massive endpoint and XML file fuzzing list.
- `needstobefixed.txt` (1.18 MB, 59,712 entries) — Common legacy files, scripts, and hidden paths.
- `reallysafe-not.txt` (51 KB, 1,674 entries) — Critical path traversal and dangerous admin routes.

### 2. Parameters & Form Inputs
- `params.txt` (24 KB, 2,583 entries) — Core HTTP query and body parameter names for parameter discovery.

### 3. API & Web Service Fuzzing
- `api.txt` (13 KB, 588 entries) — REST API routes and versioned endpoints (`/api-docs/`, `/api/v1/`).
- `API-FUZZ.txt` (14.2 MB, 448,998 entries) — Deep REST API parameter and path fuzzing.
- `SwaggerAPI.txt` (48.5 MB, 953,018 entries) — Comprehensive OpenAPI/Swagger endpoint paths.
- `wad.txt` (1 KB, 73 entries) — Web application descriptor and WSDL services.
- `svc.txt` (5.8 KB, 276 entries) — WCF and SOAP `.svc` service discovery.
- `peoplesoft.txt` (408 B, 58 entries) — PeopleSoft web service endpoints.
- `phpunit.txt` (40 KB, 623 entries) — Exposed PHPUnit test runner paths.

### 4. Technology & Extension Specific Paths
- **ASP.NET / IIS:** `aspx.txt` (631 entries), `asp.txt` (34 entries), `ashx.txt` (33 entries), `asmx.txt` (132 entries), `asax.txt` (2 entries).
- **PHP:** `php.txt` (12,903 entries) — PHP scripts, debug files, and handlers.
- **Perl & CGI:** `cgi-bin.txt` (90 entries), `cgi-files.txt` (1,192 entries), `perl-files.txt` (742 entries).
- **Static & Documents:** `htm.txt` (1,524 entries), `pdfs.txt` (16,646 entries), `iso.txt` (185 entries), `apk.txt` (40 entries).

### 5. Sensitive Files, Configs & Cloud Leaks
- `env.txt` (12 KB, 590 entries) — Environment variables (`.env`, `.env.local`, `.docker/.env`).
- `dotfiles.txt` (18 KB, 1,344 entries) — Hidden Unix/Linux dotfiles (`.htaccess`, `.htpasswd`, `.DS_Store`).
- `htaccess` (479 B, 33 entries) — Apache configuration variations.
- `config.txt` (1 KB, 48 entries) & `webconfig.txt` (1.7 KB, 89 entries) — Application and server configuration files (`web.config`).
- `csproj.txt` (26 entries) & `properties-files.txt` (39 entries) — Project configuration files.
- `yaml.txt` (113 entries) & `k8s.txt` (56 entries) — Docker Compose and Kubernetes manifest names.
- `ec2.txt` (22 entries) — AWS EC2 cloud-init, metadata, and provisioning file paths.
- `git_config.txt` (49 entries) — Exposed Git repository files (`.git/config`, `.git2/config`).
- `zip.txt` (71 KB, 3,956 entries) — Backup archives (`_backup.zip`, `data.zip`, `site.tar.gz`).
- `sql.txt` (12 KB, 534 entries) — Database dumps (`.sql`, backup SQL dumps).
- `log.txt` (108 KB, 4,628 entries) — Application, server, and debug logs (`access.log`, `error.log`).
- `keys.txt` (7 entries) & `npmrc.txt` (51 entries) — SSL keys (`ca-key.pem`) and npm auth tokens (`.npmrc`).
- `web-inf.txt` (2.9 KB, 77 entries) — Java EE `WEB-INF/web.xml` and struts config paths.

### 6. CMS & Admin Portals
- `WPfuzz.txt` (409 KB, 6,570 entries), `wp-content.txt` (5,542 entries), `wordpress-random.txt` (169 entries) — WordPress core, plugins, themes, and admin logins.
- `phpmyadmin.txt` (199 entries), `PhpMyAdmin_PHPmyadmin.txt` (199 entries), `adminer.txt` (194 entries), `honey.txt` (1,786 entries) — Database administration portals and honeypot routes.
- `JiraFuzz.txt` (22 entries) & `JIra-Domains.txt` (8,206 entries) — Atlassian Jira fuzzing endpoints and target domain lists.

### 7. Payloads & Vulnerability Testing
- `OR-Payloads.txt` (26 KB, 858 entries) — Open redirect parameter payloads.
- `windows-lfi.txt` (518 KB, 6,610 entries) — Windows Local File Inclusion (LFI) traversal paths.
- `sqltesting.txt` (44 KB, 736 entries) — SQL injection syntax error and fuzzing probes.
- `sqlbypass.txt` (1.7 KB, 78 entries) — SQL authentication bypass payloads and characters.
