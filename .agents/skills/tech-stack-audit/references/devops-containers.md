# DevOps, CI/CD, Source Control, Containers, Orchestration, Secrets

Class key: see cms-ecommerce.md.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-DO-001 | Jenkins | Unauthenticated access to /script, /api/json, /scriptText | passive | GET each path, record status without submitting scripts |
| TS-DO-002 | Jenkins | Script console reachable without auth (RCE surface) | passive | Status of /script only; do not run Groovy |
| TS-DO-003 | Jenkins | Credentials or secrets visible in build console logs | bounded | GET lastBuild/consoleText on jobs you own, grep for secret patterns |
| TS-DO-004 | Jenkins | CVE-2018-1000861 Stapler routing RCE (<2.138.2 LTS, <2.153) | passive | Version from X-Jenkins header; no exploit |
| TS-DO-005 | Jenkins | Groovy sandbox bypass CVE-2019-1003000 / 1003001 | passive | Plugin version check |
| TS-DO-006 | Jenkins | Pre-auth CLI deserialization CVE-2016-0792 | passive | Version check |
| TS-DO-007 | Jenkins | Update-center XSS/CSRF CVE-2023-27898 | passive | Version check |
| TS-DO-008 | Jenkins | Agent-to-controller file read CVE-2024-43044; CLI file read CVE-2024-23897 | passive | Version check (Core <2.471 / <2.441) |
| TS-DO-009 | Jenkins | Agent-to-controller bypass CVE-2021-21685 to 21694 | passive | Version check (<2.319) |
| TS-DO-010 | GitLab | Public projects, groups, or snippets exposed | bounded | Anonymous GET /api/v4/projects?visibility=public (count only) |
| TS-DO-011 | GitLab | SSRF through import/webhook (CVE-2021-22214) | passive | Version check |
| TS-DO-012 | GitLab | ExifTool RCE CVE-2021-22205 (11.9 to 13.10.2) | passive | Version check |
| TS-DO-013 | GitLab | Password reset via unverified secondary email CVE-2023-7028 (16.1.0 to 16.7.1) | passive | Version check |
| TS-DO-014 | GitLab | GitHub import RCE CVE-2022-2884 (14.6 to 15.1.1) | passive | Version check |
| TS-DO-015 | GitLab CI/CD | Pipeline variables exposed or leaked from forks | authorized-only | Requires approved access; API review only |
| TS-DO-016 | GitLab CI/CD | Public job artifacts with secrets | bounded | Anonymous artifact list on public projects you are testing |
| TS-DO-017 | GitLab CI/CD | Unprotected pipeline trigger tokens | authorized-only | Requires approved review |
| TS-DO-018 | Gitea / Forgejo | Open registration and public repo exposure | bounded | GET /user/sign_up, /explore/repos status |
| TS-DO-019 | Gogs | Argument injection RCE CVE-2024-39930 | passive | Version check |
| TS-DO-020 | Gitblit | Default admin credentials | authorized-only | Requires approved credential test |
| TS-DO-021 | Gerrit | Anonymous repo and REST access | bounded | GET /projects/, /a/config/server/info anonymous |
| TS-DO-022 | Gitiles | Anonymous repository browsing | bounded | GET /gitiles/ anonymous |
| TS-DO-023 | Bitbucket | Pre-auth RCE CVE-2022-36804 | passive | Version check |
| TS-DO-024 | SonarQube | Public project reports exposed; default admin admin/admin | bounded | Anonymous GET /api/projects/search; credential test only if approved |
| TS-DO-025 | Nexus Repository | Default admin admin/admin123; EL injection RCE CVE-2019-7238 and CVE-2020-10199 | authorized-only | Version check; credential test only if approved |
| TS-DO-026 | JFrog Artifactory | Anonymous repository list and auth bypass CVE-2021-29506 | bounded | GET /artifactory/api/repositories anonymous |
| TS-DO-027 | Harbor | Anonymous /v2/_catalog and API projects | bounded | GET /v2/_catalog and /api/v2.0/projects status |
| TS-DO-028 | Docker Registry | Anonymous image catalog and pull | bounded | GET /v2/_catalog status only (no image pulls) |
| TS-DO-029 | Docker daemon API | Exposed 2375 or 2376 | passive | GET /version (no container create/exec) |
| TS-DO-030 | Kubernetes Dashboard | Unauthenticated dashboard | passive | GET dashboard root status |
| TS-DO-031 | Kubernetes API | Anonymous access on 6443 or 8080 | passive | GET /version and /api status (no listing secrets) |
| TS-DO-032 | Kubelet | Anonymous API on 10250 | passive | GET /pods status; do not exec |
| TS-DO-033 | etcd | Unauthenticated access on 2379 | passive | GET /version status |
| TS-DO-034 | ArgoCD | Exposed API or default admin password | authorized-only | Anonymous GET /api/version; credential test only if approved |
| TS-DO-035 | HashiCorp Consul | Unauthenticated HTTP API, KV, catalog | bounded | GET /v1/catalog/services anonymous |
| TS-DO-036 | HashiCorp Vault | Unsealed status and exposed root token | passive | GET /v1/sys/health status (never use tokens found) |
| TS-DO-037 | Portainer | Admin UI on 9000/9443 with weak credentials | passive | GET UI status; credential test only if approved |
| TS-DO-038 | Traefik | Dashboard without auth; Docker socket exposure | passive | GET /dashboard/ and /api/rawdata status |
| TS-DO-039 | Kong | Admin API on 8001 exposed | passive | GET /status and / on 8001 status |
| TS-DO-040 | Apache APISIX | Admin API on 9180 exposed; CVE-2022-24112, CVE-2022-29266 | passive | GET admin route status; version check |
| TS-DO-041 | Envoy | Admin endpoint on 9901 | passive | GET /server_info status |
| TS-DO-042 | TeamCity | Auth bypass and RCE CVE-2024-27198 | passive | Version check |
| TS-DO-043 | Subversion | .svn metadata exposed | passive | GET /.svn/entries status |
| TS-DO-044 | Phabricator | Exposed diffusion and maniphest | bounded | Anonymous GET of /diffusion/ and /maniphest/ |
| TS-DO-045 | GitBook | Public spaces leaking internal docs | bounded | Anonymous GET of published space |
| TS-DO-046 | Hashnode / Duda / GitHub Pages | Dangling custom domain (takeover) | passive | See subdomain-takeover provider_fingerprints.md |
| TS-DO-047 | Netlify / Vercel / Heroku / Render / Railway / Glitch / Replit | Env files, metadata, or deploy keys exposed | passive | GET /.env, /Procfile; headers for platform |
| TS-DO-048 | Airflow | Web UI default credentials; DAG code execution for authenticated users | authorized-only | Anonymous GET /health; credential test only if approved |
| TS-DO-049 | Sidekiq Web | Unauthenticated queue UI | passive | GET /sidekiq status and page title |
| TS-DO-050 | Flowise | Unauthenticated API exposing workflows and keys | bounded | GET /api/v1/chatflows anonymous status |
| TS-DO-051 | MLflow | Unauthenticated experiments and artifacts | bounded | GET /api/2.0/mlflow/experiments/search anonymous |
| TS-DO-052 | Mirth Connect | Java deserialization CVE-2023-43208 | passive | Version check |
| TS-DO-053 | Cacti / Pandora FMS / Nagios / Zabbix | Covered in monitoring-logging.md | passive | See that file |
| TS-DO-054 | Git repository (.git) exposed | Full source and history recoverable | passive | GET /.git/HEAD and /.git/config status (see contentdiscovery exposure file) |
| TS-DO-055 | OpenAM / ForgeRock | Jato deserialization CVE-2021-35464 | passive | Version check |
| TS-DO-056 | Metabase | Setup token abuse CVE-2023-38646 | passive | Version check |
