# Google Dorking and OSINT Checklist (GD, 49 checks)

`T` = the in-scope domain (for example `example.com`). Class key: `passive` = search engine and third-party pages only. `bounded` = opening/status-checking hits on in-scope hosts. `authorized-only` = downloading data beyond proof, using credentials, joining third-party workspaces.

Every row is passive to run. The "Safe verification" column describes what to do with a hit.

## Exposed files by type (GD-001 to GD-013)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GD-001 | Documents | `site:T filetype:pdf` — internal reports, contracts, manuals, metadata (authors, software, internal paths) | passive | Open from search cache only if needed; check metadata with `exiftool`; note sensitive content, do not redistribute |
| GD-002 | Spreadsheets | `site:T filetype:xlsx` (also `xls`, `csv`) — user lists, pricing, PII, credentials | passive | Confirm exposure by title/size; data-exposure-audit DE-016 rules for PII |
| GD-003 | Documents | `site:T filetype:docx` (also `doc`, `pptx`, `odt`) — internal procedures, network diagrams | passive | Metadata and title review |
| GD-004 | Text | `site:T filetype:txt` — notes, credentials, robots/humans.txt variants, exported data | passive | data_exposure verification (redacted first line) |
| GD-005 | Logs | `site:T filetype:log` — application/server logs with tokens, IPs, stack traces | passive | Status/size check (dork_triage.py --verify); DE-011 |
| GD-006 | Database | `site:T filetype:sql` — database dumps and schema files | passive | Status/size only; never download a dump (DE-009) |
| GD-007 | Env | `site:T filetype:env` — `.env` files with secrets | passive | Status + redacted key names (DE-008); report for rotation |
| GD-008 | Config | `site:T filetype:yml` (also `yaml`) — CI configs, docker-compose, k8s manifests, app configs | passive | Look for secrets and internal hosts; DE-008 |
| GD-009 | JSON | `site:T filetype:json` — API responses, configs, keys, manifests, source maps | passive | DE-002/DE-003 classification |
| GD-010 | XML | `site:T filetype:xml` — sitemaps, WSDL, configs, backups | passive | WSDL → xml-xxe-audit (SOAP); configs → DE-008 |
| GD-011 | Conf | `site:T filetype:conf` — server/app configs (nginx, apache, app) | passive | DE-008; server-config-audit context |
| GD-012 | Cfg | `site:T filetype:cfg` — device/app configs | passive | DE-008 |
| GD-013 | Backups | `site:T filetype:bak` (also `old`, `backup`, `swp`, `zip`, `tar.gz`) — backup copies of source/config | passive | Status/size only (DE-009) |

## Titles and listings (GD-014 to GD-017)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GD-014 | Listings | `site:T intitle:"index of"` — directory listings (backups, uploads, logs) | passive | Status check; list folder names only (file-download-audit FD-002) |
| GD-015 | Dashboards | `site:T intitle:"dashboard"` — monitoring/admin dashboards (Grafana, Kibana, Jenkins) | passive | Note product/version; auth required? (tech-stack-audit) |
| GD-016 | Admin | `site:T intitle:"admin"` — admin panels | passive | Reachability and auth only; never try credentials |
| GD-017 | Login | `site:T intitle:"login"` — login portals (SSO, legacy, staff, partner) | passive | Map auth surfaces for authbypass/credentialattacks |

## Sensitive URL paths (GD-018 to GD-033)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GD-018 | Admin | `site:T inurl:admin` | passive | Auth boundary check (access-control) |
| GD-019 | Login | `site:T inurl:login` | passive | Auth surface map |
| GD-020 | Dashboards | `site:T inurl:dashboard` | passive | Auth boundary check |
| GD-021 | Config | `site:T inurl:config` | passive | DE-008 |
| GD-022 | API | `site:T inurl:api` — API hosts, versions, documented endpoints | passive | Feed api-security / rest-api-audit |
| GD-023 | Upload | `site:T inurl:upload` — upload forms and uploaded files | passive | file-upload-audit / file-download-audit |
| GD-024 | Debug | `site:T inurl:debug` — debug pages, profilers, stack traces | passive | server-config-audit SMC-006 |
| GD-025 | Test | `site:T inurl:test` — test pages and environments | passive | Hosts → subdomainenum; pages → contentdiscovery |
| GD-026 | Staging | `site:T inurl:staging` — staging environments (weaker controls, real data) | passive | Confirm in scope before testing |
| GD-027 | Dev | `site:T inurl:dev` — development hosts and paths | passive | Confirm in scope before testing |
| GD-028 | VCS | `site:T inurl:.git` — exposed git metadata | passive | DE-010 status check; never clone without approval |
| GD-029 | Env | `site:T inurl:.env` | passive | DE-008 |
| GD-030 | WordPress | `site:T inurl:wp-admin` (also `wp-content`, `wp-json`) | passive | tech-stack-audit WordPress rows |
| GD-031 | phpMyAdmin | `site:T inurl:phpmyadmin` | passive | Reachability and version only |
| GD-032 | Swagger | `site:T inurl:swagger` (also `api-docs`, `openapi`) | passive | api-security AA-015 |
| GD-033 | GraphQL | `site:T inurl:graphql` (also `graphiql`, `playground`) | passive | graphql-audit |

## Secrets and errors in page text (GD-034 to GD-039)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GD-034 | Secrets | `site:T intext:"password"` (combine with `filetype:` or `inurl:` to cut noise) | passive | Read snippet; verify page; report credentials for rotation |
| GD-035 | Secrets | `site:T intext:"api key"` (also `"api_key"`, `"apikey"`) | passive | Classify public vs secret (saas-third-party-exposure) |
| GD-036 | Secrets | `site:T intext:"secret"` (also `"client_secret"`, `"secret_key"`) | passive | DE-003 |
| GD-037 | Secrets | `site:T intext:"token"` (also `"access_token"`, `"bearer"`) | passive | DE-003; tokens in URLs → DE-018 |
| GD-038 | Cache | `site:T cache:` — Google cache was retired (2024); use Wayback: `web.archive.org/web/*/T/*` and the CDX API for removed pages | passive | Archived copies of now-removed sensitive pages (`dork_gen.py` writes the Wayback links) |
| GD-039 | Errors | `site:T "error" "sql"` (also `"syntax error"`, `"mysql_fetch"`, `"ORA-"`, `"SQLSTATE"`, `"Warning: pg_"`) | passive | error-handling-audit EH-002; sqli on the parameter |

## Third-party leaks (GD-040 to GD-049)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GD-040 | Pastebin | `site:pastebin.com T` (also `ghostbin`, `paste.ee`, `hastebin`, `justpaste.it`, `rentry.co`) | passive | Record paste URL/date; credentials → report, never use |
| GD-041 | GitHub | `site:github.com T password` | passive | Prefer GitHub code search (extras); confirm repo owner relation |
| GD-042 | GitHub | `site:github.com T api_key` | passive | Same; classify key type |
| GD-043 | GitHub | `site:github.com T secret` | passive | Same |
| GD-044 | GitHub | `site:github.com T token` | passive | Same |
| GD-045 | Gist | `site:gist.github.com T` | passive | Same |
| GD-046 | Stack Overflow | `site:stackoverflow.com T` — internal code, hostnames, stack traces, credentials posted by staff | passive | Record question URL and what leaks |
| GD-047 | Trello | `site:trello.com T` — public boards with credentials, roadmaps, internal links | passive | Public boards only; never request access |
| GD-048 | Slack | `site:slack.com T` — public workspace names, shared files, invite links | passive | Do not join workspaces; report exposure of invite links or files |
| GD-049 | Notion | `site:notion.so T` (also `site:notion.site T`) — public pages with internal docs | passive | Public pages only |

## Cross-references

| GD rows | Related |
|---|---|
| GD-004 to GD-014, GD-028, GD-029 | data-exposure-audit DE-007 to DE-011, contentdiscovery |
| GD-015 to GD-020, GD-030, GD-031 | tech-stack-audit, access-control, authbypass |
| GD-022, GD-032, GD-033 | api-security, rest-api-audit, graphql-audit |
| GD-025 to GD-027 | subdomainenum |
| GD-034 to GD-037 | data-exposure-audit DE-003, saas-third-party-exposure |
| GD-039 | error-handling-audit, sqli |
| GD-040 to GD-049 | cloud-supplychain (GitHub orgs), recon-hunter OSINT-001 |
