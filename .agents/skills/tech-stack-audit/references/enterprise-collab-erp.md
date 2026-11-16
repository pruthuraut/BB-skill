# Enterprise, Collaboration, ERP/CRM, BI, Helpdesk, LMS, Industry Apps

Class key: see cms-ecommerce.md.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-ENT-001 | Microsoft Exchange / OWA | ProxyLogon CVE-2021-26855 and ProxyShell CVE-2021-34473 | passive | Version check (build number) |
| TS-ENT-002 | Microsoft Exchange / OWA | Password spray exposure, lockout and MFA review | authorized-only | Policy review; spraying only if approved |
| TS-ENT-003 | Microsoft 365 | Tenant endpoints reveal SharePoint/Exchange availability | passive | DNS and portal endpoint status (no login) |
| TS-ENT-004 | Confluence | OGNL RCE CVE-2022-26134 (1.3.0 to 7.18.0) | passive | Version check (footer or /login.action) |
| TS-ENT-005 | Confluence | Broken access control allowing admin creation CVE-2023-22515 (8.0.0 to 8.5.1) | passive | Version check |
| TS-ENT-006 | Confluence | Setup auth bypass CVE-2023-22518 | passive | Version check |
| TS-ENT-007 | Confluence | Anonymous spaces and pages | bounded | Anonymous GET of space home pages |
| TS-ENT-008 | Jira | User enumeration via /rest/api/2/user/search | bounded | Anonymous request; record count only |
| TS-ENT-009 | Jira | Public project exposure | bounded | Anonymous /browse/<KEY> status |
| TS-ENT-010 | Jira | SSTI CVE-2019-11581 contact admin form | passive | Version check |
| TS-ENT-011 | Jira | Seraph auth bypass CVE-2022-0540; path traversal CVE-2021-26086 | passive | Version check |
| TS-ENT-012 | SharePoint | Anonymous document libraries | bounded | Anonymous list request |
| TS-ENT-013 | SAP NetWeaver | RECON CVE-2020-6287 (LM Configuration Wizard); exposed ICM admin | passive | Version and path status only |
| TS-ENT-014 | ManageEngine ADSelfService Plus | Auth bypass to RCE CVE-2021-40539; custom action scripts CVE-2022-28810 | passive | Version check |
| TS-ENT-015 | ManageEngine ServiceDesk | SQLi RCE CVE-2021-44077 | passive | Version check |
| TS-ENT-016 | ManageEngine (multi) | SAML pre-auth RCE CVE-2022-47966 | passive | Version check |
| TS-ENT-017 | Zoho ManageEngine | Default admin credentials | authorized-only | Credential test only if approved |
| TS-ENT-018 | Odoo | Database manager at /web/database/manager reachable | passive | GET status (do not create/restore) |
| TS-ENT-019 | ERPNext / Frappe | Desk exposure and bench/console endpoints | passive | GET /login, /console status |
| TS-ENT-020 | Dolibarr | PHP file creation CVE-2023-30253 | passive | Version check |
| TS-ENT-021 | Kintone | Guest spaces without access control | bounded | GET /k/guest/ anonymous |
| TS-ENT-022 | Mendix | Runtime REST and XAS endpoints exposed | bounded | Anonymous GET /rest/ and /xas/ status |
| TS-ENT-023 | OutSystems | Environment URLs and ServiceCenter exposed | passive | GET /ServiceCenter/ status |
| TS-ENT-024 | ServiceNow | Input validation bypass CVE-2024-4879 | passive | Version or patch level check |
| TS-ENT-025 | SugarCRM | Email template RCE CVE-2023-22952 | passive | Version check |
| TS-ENT-026 | Workday | Exposed API endpoint and auth configuration | passive | Tenant endpoint status |
| TS-ENT-027 | NetSuite | SuiteScript RESTlets and SuiteTalk anonymous access | bounded | Anonymous GET on documented endpoints |
| TS-ENT-028 | osTicket | Public portal leaks tickets | bounded | Anonymous ticket view on own test ticket |
| TS-ENT-029 | Zammad | Admin panel exposed | passive | GET /#admin status (SPA) |
| TS-ENT-030 | Freshdesk / Freshworks CRM / Zendesk | Widget and API keys exposed; webhook SSRF | passive | Grep client JS; webhook review only |
| TS-ENT-031 | TeamViewer | Partner integration scripts reveal configuration | passive | Grep scripts |
| TS-ENT-032 | Cloudera | Hue and Cloudera Manager reachable | passive | GET 8888 and 7180 status |
| TS-ENT-033 | Qlik Sense / Tableau / Looker / Power BI | Views and embed URLs exposed without auth | bounded | Anonymous GET of embed URLs found in page source |
| TS-ENT-034 | Metabase | Setup token and public dashboards | bounded | GET /api/session/properties; public dashboard list |
| TS-ENT-035 | Streamlit | App config and data source exposure | bounded | GET app page anonymous |
| TS-ENT-036 | OpenEMR | Authentication bypass and file read CVE-2018-15139 | passive | Version check |
| TS-ENT-037 | OpenEMR | Patient records accessible without authentication | bounded | Anonymous GET of record URL; record count only, no PHI copied |
| TS-ENT-038 | Mirth Connect | See devops-containers.md TS-DO-052 | passive | See that file |
| TS-ENT-039 | Bonita BPM | Auth bypass and RCE CVE-2022-25237 | passive | Version check |
| TS-ENT-040 | erxes | Unauthenticated GraphQL mutations | bounded | Introspection and anonymous mutation schema review (no writes) |
| TS-ENT-041 | JumpServer | Password reset and command execution CVE-2023-42820 | passive | Version check |
| TS-ENT-042 | JumpCloud | LDAP and RADIUS exposure | passive | Port check |
| TS-ENT-043 | Mattermost | Open registration and unauthenticated API | bounded | GET /api/v4/config/client anonymous |
| TS-ENT-044 | Rocket.Chat | SAML bypass CVE-2023-28314 | passive | Version check |
| TS-ENT-045 | Nextcloud | Public share token predictability and permissions | bounded | Review own public share link format |
| TS-ENT-046 | Redmine | Public projects exposing data | bounded | Anonymous GET /projects.json |
| TS-ENT-047 | DokuWiki | ACL @ALL read and open registration | bounded | Anonymous page view on sample page |
| TS-ENT-048 | BookStack | SSRF via image upload (historic) | passive | Version check |
| TS-ENT-049 | Flowise / MLflow | See devops-containers.md TS-DO-050 and TS-DO-051 | passive | See that file |
| TS-ENT-050 | Gitbook / Notion | Public pages leak internal docs | bounded | Anonymous view of public URL |
| TS-ENT-051 | Phabricator | See devops-containers.md TS-DO-044 | bounded | See that file |
| TS-ENT-052 | Discourse | See cms-ecommerce.md TS-CMS-116 | passive | See that file |
| TS-ENT-053 | Zulip | API key in page source | passive | Grep for api key patterns |
| TS-ENT-054 | Coremedia / Sitecore / Umbraco | Admin and preview exposure; Sitecore deserialization CVE-2021-42237 | passive | GET admin and preview paths; version check |
| TS-ENT-055 | AEM (Adobe Experience Manager) | CRX exposed; default admin:admin; DAM traversal; SLING API exposure | bounded | GET /crx/de status; default credential test only if approved |
| TS-ENT-056 | AEM | Reflected XSS CVE-2021-27905 (<=6.5 SP5) | passive | Version check |
| TS-ENT-057 | Adobe ColdFusion | WDDX deserialization CVE-2023-26360; LFI CVE-2010-2861; passwordless RDS | passive | Version check; /CFIDE/administrator/ status |
| TS-ENT-058 | Adobe ColdFusion | Administrator exposed | passive | GET /CFIDE/administrator/ status |
| TS-ENT-059 | Lucee | Admin with empty or default credentials | authorized-only | Credential test only if approved |
| TS-ENT-060 | Oracle WebLogic | Admin console on 7001/7002; RCE CVE-2020-14882, CVE-2019-2725, CVE-2023-21839 | passive | Console status; version check |
| TS-ENT-061 | Oracle WebLogic | Default credentials on admin console | authorized-only | Credential test only if approved |
| TS-ENT-062 | Atlassian FishEye / Crucible | RCE CVE-2021-39108 | passive | Version check |
| TS-ENT-063 | Atlassian Bitbucket | See devops-containers.md TS-DO-023 | passive | See that file |
| TS-ENT-064 | Splunk / Graylog | See monitoring-databases-queues.md | passive | See that file |
| TS-ENT-065 | Roundcube / RainLoop / Zimbra | Webmail admin exposure; Zimbra mboximport RCE CVE-2022-37042 | passive | Version and admin path status |
| TS-ENT-066 | Apache Solr / Lucene | See monitoring-databases-queues.md | passive | See that file |
| TS-ENT-067 | Liferay / Vaadin | See frameworks-languages.md | passive | See that file |
| TS-ENT-068 | Vaadin / Wicket | See frameworks-languages.md | passive | See that file |
| TS-ENT-069 | XWiki | See cms-ecommerce.md TS-CMS-089 | bounded | See that file |
| TS-ENT-070 | GoAnywhere MFT | Pre-auth deserialization CVE-2023-0669 | passive | Version check |
| TS-ENT-071 | Wing FTP | Weak admin and Lua execution | authorized-only | Credential test only if approved |
| TS-ENT-072 | CrushFTP | Virtual filesystem escape and auth bypass CVE-2024-4040 | passive | Version check |
| TS-ENT-073 | IceWarp | Unauthenticated file upload CVE-2021-40488 | passive | Version check |
| TS-ENT-074 | Revive Adserver / Tiki / Emlog | See cms-ecommerce.md | passive | See that file |
| TS-ENT-075 | HotelDruid / OpenCATS / BigAnt / openSIS / GestSup / ResourceSpace / EyesOfNetwork | Application-specific SQLi and exposed data (historic) | passive | Version check per advisory |
| TS-ENT-076 | Jeecg-Boot | SQLi CVE-2024-52564; default admin | passive | Version check; credential test only if approved |
| TS-ENT-077 | YONYOU NC | Pre-auth deserialization CVE-2024-0583 | passive | Version check |
| TS-ENT-078 | Dell / Unisphere / Dotcms | Path traversal and XSS | passive | Version check |
| TS-ENT-079 | DotCMS | Path traversal and file disclosure | passive | Version check |
| TS-ENT-080 | Ruckus / Ubiquiti / F5 | See identity-network-iot.md | passive | See that file |
