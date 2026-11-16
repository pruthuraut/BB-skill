# Sensitive Exposure, Directory Listing, Error Pages, and Config Leaks (extension)

Class key: `passive` = status line, headers, and body grep only. `bounded` = a fixed short list of paths per host with rate limits. Download files only when the program allows and never publish secrets; redact in reports.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| EXP-001 | Git | `.git/HEAD` and `.git/config` reachable | passive | GET `/.git/HEAD`; if 200 with `ref:`, report exposure (dump only if approved) |
| EXP-002 | Git | Full history recoverable (git-dumper) | authorized-only | Approved download into a new directory; scan for secrets |
| EXP-003 | Env files | `.env`, `.env.local`, `.env.backup`, `/backend/.env` | passive | GET status; if 200, record key names only, redact values |
| EXP-004 | Config | `config.php`, `wp-config.php.bak`, `web.config`, `web.config.bak`, `appsettings.json` | passive | GET status and first bytes only |
| EXP-005 | Backups | `backup.zip`, `db.sql`, `site.tar.gz`, `backup/` | bounded | HEAD request on each path (no download) |
| EXP-006 | Listings | Directory listing enabled ("Index of") | bounded | GET directory paths found in crawl; grep title |
| EXP-007 | Listings | Default directories `/bin/`, `/bak/`, `/backup/`, `/uploads/` listing | bounded | Same as EXP-006 |
| EXP-008 | Robots and sitemap | Hidden paths disclosed in robots.txt and sitemap.xml | passive | GET robots.txt and sitemap.xml; list Disallow paths for testing |
| EXP-009 | Subversion | `/.svn/entries` and `/.svn/wc.db` | passive | GET status |
| EXP-010 | Mercurial / Bazaar | `/.hg/`, `/.bzr/` | passive | GET status |
| EXP-011 | IDE and editor | `.DS_Store`, `.idea/workspace.xml`, `.vscode/`, `*.swp` | passive | GET status |
| EXP-012 | Logs | `error.log`, `debug.log`, `access.log`, `npm-debug.log` | passive | GET status; record path only |
| EXP-013 | Admin panels | Common admin paths (`/admin`, `/administrator`, `/manager/html`, `/phpmyadmin`) | passive | GET status and title; no login attempts |
| EXP-014 | Spring Boot | `/actuator`, `/actuator/env`, `/actuator/heapdump` | passive | GET `/actuator` index; never download heapdump |
| EXP-015 | Swagger / OpenAPI | `/swagger-ui.html`, `/v2/api-docs`, `/openapi.json` | passive | GET status |
| EXP-016 | phpinfo | `phpinfo.php`, `info.php`, `?=PHPE9568F34...` | passive | GET status and grep for phpinfo title |
| EXP-017 | Server status | `/server-status`, `/server-info` | passive | GET status |
| EXP-018 | Debug endpoints | `/debug/`, `/__debug`, `/_profiler`, `/trace.axd` | passive | GET status |
| ERR-001 | Error pages | Stack trace or framework name on malformed request | bounded | One malformed request per endpoint; grep trace patterns |
| ERR-002 | Error pages | Internal path or hostname in error | bounded | Same request; grep for file paths |
| ERR-003 | Error pages | SQL error text | bounded | Single quote in own input; grep SQL error signatures (no extraction) |
| ERR-004 | Error pages | Version in 404 body | passive | Random path; grep versions |
| ERR-005 | Numeric overflow | `id=99999999999` triggers verbose error | bounded | One request |
| DATA-001 | API responses | Fields not shown in UI (password_hash, tokens, internal IDs) | bounded | Own account API response, compare with UI |
| DATA-002 | Public resources | Public S3 or Firebase data listing | bounded | See cloud-supplychain |
| DATA-003 | Cookies | Sensitive data in cookie values (base64 JSON) | passive | Decode own cookie and review fields |
| DATA-004 | Exported files | Full DB dumps or CSV in public path | bounded | HEAD and status only |
