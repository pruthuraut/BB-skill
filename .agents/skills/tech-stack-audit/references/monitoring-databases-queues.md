# Monitoring, Logging, Databases, Data Stores, Message Queues, Search

Class key: see cms-ecommerce.md.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-MON-001 | Grafana | Anonymous dashboard search and access | bounded | GET /api/search?type=dash-db anonymous (count only) |
| TS-MON-002 | Grafana | API keys or org data reachable anonymously | bounded | GET /api/org anonymous status |
| TS-MON-003 | Grafana | Directory traversal in plugin assets (CVE-2021-43798, <8.3.1) | passive | Version check |
| TS-MON-004 | Grafana | SQL Expressions RCE CVE-2024-9264 (11.0.x to 11.2.x, feature enabled) | passive | Version and feature-flag check only |
| TS-MON-005 | Grafana | Azure AD OAuth group bypass CVE-2023-3128 (6.7.0 to 10.0.1) | passive | Version check |
| TS-MON-006 | Grafana | Auth race CVE-2022-39328 (9.2.x <9.2.4) and OAuth takeover CVE-2022-31107 (5.3.0 to 9.0.2) | passive | Version check |
| TS-MON-007 | Grafana | Image Renderer command injection CVE-2025-11539 (<3.11.7) | passive | Version check of renderer plugin |
| TS-MON-008 | Kibana | Unauthenticated status and app access | passive | GET /api/status and /app/kibana status |
| TS-MON-009 | Kibana | Prototype pollution CVE-2019-7609 (<6.6.1) | passive | Version check |
| TS-MON-010 | Kibana | Timelion RCE CVE-2021-22150 (7.0.0 to 7.12.0) | passive | Version check |
| TS-MON-011 | Kibana | Saved objects and index patterns readable anonymously | bounded | GET /api/saved_objects/_find?type=index-pattern anonymous |
| TS-MON-012 | Prometheus | /metrics publicly exposed | passive | GET /metrics status; check for credentials in labels (redact) |
| TS-MON-013 | Prometheus | Admin API enabled (--web.enable-admin-api) | passive | GET /api/v1/status/flags shows admin flag; do not call delete APIs |
| TS-MON-014 | Zabbix | Default Admin/zabbix credentials | authorized-only | Credential test only if approved |
| TS-MON-015 | Zabbix | SAML session auth bypass CVE-2022-23131 | passive | Version check |
| TS-MON-016 | Zabbix | Time-based SQLi CVE-2024-22120 (6.0.x to 7.0 beta) | passive | Version check |
| TS-MON-017 | Zabbix | Agent script execution by authenticated users | authorized-only | Requires approved review |
| TS-MON-018 | Splunk | Default admin/changeme | authorized-only | Credential test only if approved |
| TS-MON-019 | Splunk | Scripted inputs and custom commands RCE for authenticated users | authorized-only | Requires approved review of app config |
| TS-MON-020 | Graylog | Web interface and log data reachable without auth | bounded | GET /api/system anonymous status |
| TS-MON-021 | Nagios XI | Pre-auth command injection CVE-2020-35578 | passive | Version check |
| TS-MON-022 | Nagios | Default credentials and topology exposure | authorized-only | Credential test only if approved |
| TS-MON-023 | Cacti | Unauthenticated command injection CVE-2022-46169 | passive | Version check |
| TS-MON-024 | Pandora FMS | SQLi and RCE CVE-2020-5840 | passive | Version check |
| TS-MON-025 | Uptime Kuma | Unauthenticated monitor creation (SSRF pivot) | bounded | GET dashboard anonymous status only |
| TS-MON-026 | Maltrail | Login username command injection CVE-2023-27163 | passive | Version check |
| TS-MON-027 | EyesOfNetwork | Command injection CVE-2023-36007; default admin | passive | Version check; credential test only if approved |
| TS-MON-028 | Netdisco | Topology and SNMP community exposure | bounded | GET unauthenticated pages status |
| TS-MON-029 | NetAlertX | Unauthenticated device inventory | bounded | GET main page anonymous status |
| TS-MON-030 | Instana / Dynatrace / New Relic | Agent or collector endpoints exposed | passive | Check endpoints on public hosts; key exposure per saas file |
| TS-MON-031 | Apache Flink | Dashboard and REST exposed on 8081; unauthenticated JAR upload | bounded | GET /overview, /jobs, /taskmanagers status (no upload) |
| TS-MON-032 | Apache SkyWalking | GraphQL SQLi CVE-2020-9483 | passive | Version check |
| TS-MON-033 | Envoy | Admin endpoint exposed (9901) | passive | GET /stats and /config_dump status (internal hosts only if in scope) |
| TS-MON-034 | Countly | Dashboard and default credentials | authorized-only | Credential test only if approved |
| TS-MON-035 | Matomo | Tracking endpoint and admin reachable | passive | GET /piwik.php, /matomo/ status |
| TS-MON-036 | Elasticsearch | Unauthenticated indices and _cat endpoints | bounded | GET /_cat/indices anonymous (names only) |
| TS-MON-037 | Elasticsearch | Memory disclosure CVE-2021-22145; stack overflow CVE-2023-31419 | passive | Version check |
| TS-MON-038 | MySQL / MariaDB | Port 3306 exposed | passive | Port reachability and banner only |
| TS-MON-039 | PostgreSQL | Port 5432 exposed | passive | Port reachability and banner only |
| TS-MON-040 | MongoDB | Unauthenticated access on 27017 | passive | Port banner; unauthenticated `listDatabases` only if approved |
| TS-MON-041 | MongoDB | NoSQL operator injection in login | bounded | Own test account with `$ne` probe, compare responses |
| TS-MON-042 | Mongo Express | Admin UI exposed; eval RCE CVE-2019-10758 | passive | GET UI status; version check |
| TS-MON-043 | Redis | Unauthenticated access on 6379 | passive | Port banner; `PING` only if approved |
| TS-MON-044 | Redis | Config-rewrite file write | authorized-only | Requires approved lab test |
| TS-MON-045 | Redis (Debian) | Lua sandbox escape CVE-2022-0543 | passive | Package version check |
| TS-MON-046 | Solr | Admin API unauthenticated; Log4Shell CVE-2021-44228 | passive | GET /solr/admin/cores status; Log4j version check |
| TS-MON-047 | Solr | DataImportHandler RCE CVE-2019-0193 (<8.2.0) | passive | Version check; DIH endpoint status only |
| TS-MON-048 | Meilisearch | Keys endpoint and indexes exposed | bounded | GET /indexes anonymous status |
| TS-MON-049 | Typesense / Algolia | API key exposed in client JS | passive | Grep client JS for key patterns (see saas file) |
| TS-MON-050 | CouchDB | Admin Party mode (no auth) | bounded | GET /_all_dbs anonymous |
| TS-MON-051 | InfluxDB 1.x | Unauthenticated query API | bounded | GET /ping and /query?q=SHOW DATABASES (no writes) |
| TS-MON-052 | Hasura | Anonymous GraphQL and metadata API | bounded | Introspection query and export_metadata with no admin secret |
| TS-MON-053 | Appwrite | Console exposed; JWT secret leak CVE-2024-31219 | passive | GET /v1/console status; version check |
| TS-MON-054 | Parse Platform | App ID and JS key exposed | passive | Grep client JS |
| TS-MON-055 | RabbitMQ | Management UI with guest/guest on 15672 | authorized-only | Credential test only if approved |
| TS-MON-056 | ActiveMQ | Deserialization RCE CVE-2023-46604 and Jolokia abuse CVE-2022-41678 | passive | Version check; web console status on 8161 |
| TS-MON-057 | RocketMQ | Command injection CVE-2023-33246 | passive | Version check |
| TS-MON-058 | Apache Unomi | OGNL/MVEL injection CVE-2020-13942 | passive | Version check |
| TS-MON-059 | Apache HugeGraph | Gremlin RCE CVE-2024-27348 | passive | Version check |
| TS-MON-060 | Apache OFBiz | Request handler bypass CVE-2024-45195 | passive | Version check |
| TS-MON-061 | Apache Lucene | Exposed search endpoints | bounded | Anonymous search request on own query |
| TS-MON-062 | Sphinx | Search endpoint exposed | bounded | Connect to 9312 banner only |
| TS-MON-063 | Supabase | Anon key with RLS misconfiguration | bounded | Own anon key: read a table with no auth header scope check |
| TS-MON-064 | Firebase RTDB | `.read: true` rules | bounded | GET https://<project>.firebaseio.com/.json (shallow=true first) |
| TS-MON-065 | Firestore | Public documents via REST | bounded | GET documents list with API key and no auth token |
