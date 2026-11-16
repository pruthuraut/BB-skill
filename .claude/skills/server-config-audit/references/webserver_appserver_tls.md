# Web/App Server Products, Version Checks, and TLS (extension)

Class key: `passive` = banner, header, or known-path status only. `bounded` = a few protocol-correct requests (for example, a handshake). Version checks compare with the fixed release in the advisory; exploitation is not part of this skill.

## Web servers

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| WS-SRV-001 | Nginx | Version disclosure (Server header, error pages) | passive | `curl -sI`; `server_tokens` config review |
| WS-SRV-002 | Nginx | Alias misconfiguration path traversal (`/assets../`) | bounded | Own-path request, status and body length vs baseline |
| WS-SRV-003 | Nginx | Client body buffer and header size limits | bounded | One oversized request, check 413/400 response |
| WS-SRV-004 | Nginx | CVE-2024-7347 mp4 module overread (1.5.13 to 1.27.0) | passive | Version check |
| WS-SRV-005 | Nginx | HTTP/3 CVEs CVE-2024-32760, 31079, 35200, 34161 and CVE-2024-24989/24990 | passive | Version check |
| WS-SRV-006 | Nginx | Resolver overwrite CVE-2021-23017; resolver CVE-2016-0742/0746/0747 | passive | Version check |
| WS-SRV-007 | Nginx | HTTP/2 DoS CVE-2019-9511/9513/9516 | passive | Version check |
| WS-SRV-008 | Nginx | Range filter overflow CVE-2017-7529 | passive | Version check |
| WS-SRV-009 | Nginx | Request-line extension bypass CVE-2013-4547 | passive | Version check |
| WS-SRV-010 | Nginx | Chunked overflow CVE-2013-2028 | passive | Version check |
| WS-SRV-011 | Nginx | SSL session reuse across server blocks CVE-2025-23419 | passive | Version check and config review |
| WS-SRV-012 | Nginx | mp4 memory corruption CVE-2022-41741/41742 | passive | Version check |
| WS-SRV-013 | Apache httpd | Server-status and server-info exposed | passive | GET /server-status and /server-info status |
| WS-SRV-014 | Apache httpd | Directory listing (Options Indexes) | bounded | GET directories found in crawl |
| WS-SRV-015 | Apache httpd | mod_cgi Shellshock exposure CVE-2014-6271 | passive | Version check and cgi-bin presence |
| WS-SRV-016 | Apache httpd | Path traversal CVE-2021-41773 / 42013 (2.4.49 and 2.4.50) | passive | Version check |
| WS-SRV-017 | IIS | Short filename (8.3) enumeration | bounded | Tilde probe on a known path; compare responses |
| WS-SRV-018 | IIS | Directory browsing enabled | bounded | GET directory paths |
| WS-SRV-019 | IIS | web.config and backups exposed | passive | GET /web.config and /web.config.bak status |
| WS-SRV-020 | IIS | Dangerous verbs (PUT, DELETE, TRACE) | passive | OPTIONS Allow header |
| WS-SRV-021 | IIS | WebDAV write enabled | passive | OPTIONS and PROPFIND config review |
| WS-SRV-022 | Caddy | Admin API on port 2019 reachable | passive | GET /config/ status (no POST) |
| WS-SRV-023 | Caddy | Admin API config change without auth | authorized-only | Review config; no POST |
| WS-SRV-024 | Cherokee / LiteSpeed / OpenResty / Hiawatha / Kestrel / IBM HTTP Server / EmbedThis Appweb | Server header version disclosure | passive | Response headers |
| WS-SRV-025 | Appweb | Directory traversal in older versions | bounded | Own-path traversal probe with `..%2f` markers; compare to baseline |
| WS-SRV-026 | OpenResty / Nginx Lua | Header version disclosure | passive | Response headers |
| WS-SRV-027 | Apache Traffic Server | Smuggling CVE-2022-31779; overflow CVE-2023-39456 | passive | Version check |
| WS-SRV-028 | Varnish | Cache poisoning via unkeyed headers | bounded | See http-protocol-cache CACHE-001 |
| WS-SRV-029 | HAProxy | Stats page exposed | bounded | GET /haproxy?stats status |
| WS-SRV-030 | Envoy | Admin endpoint on 9901 | passive | GET /server_info status |

## App servers

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| AS-TOM-001 | Tomcat | Manager interface exposed (/manager/html) | passive | GET status; default credential test only if approved |
| AS-TOM-002 | Tomcat | Ghostcat AJP CVE-2020-1938 (<9.0.31) | passive | Port 8009 open check and version |
| AS-TOM-003 | Tomcat | Examples and host-manager exposed | passive | GET /examples/, /host-manager/ status |
| AS-TOM-004 | Tomcat | Partial PUT file read/write CVE-2025-24813 (9.0.0.M1 to 9.0.98) | passive | Version and readonly config check |
| AS-TOM-005 | Tomcat | Case-insensitive FS race CVE-2024-50379 / 56337 (<9.0.98) | passive | Version and OS check |
| AS-TOM-006 | Tomcat | FileStore deserialization CVE-2020-9484 (<9.0.35) | passive | Version and config check |
| AS-TOM-007 | Tomcat | PUT JSP upload CVE-2017-12617 | passive | Version check |
| AS-TOM-008 | Tomcat | Windows CGI command injection CVE-2019-0232 | passive | Version and CGI config |
| AS-TOM-009 | Tomcat | Rapid Reset CVE-2023-44487 and trailer smuggling CVE-2023-46589 | passive | Version check |
| AS-TOM-010 | Tomcat | FileStore TOCTOU CVE-2022-23181 | passive | Version check |
| AS-JET-001 | Jetty | Exposed /test, /examples, JMX console | passive | GET status |
| AS-JBS-001 | JBoss / WildFly | Admin console on 8080/9990 without auth; WAR deploy | passive | GET console status |
| AS-JBS-002 | JBoss | Deserialization through /invoker/readonly CVE-2017-12149; JMX CVE-2015-7501 | passive | Endpoint status and version |
| AS-WLS-001 | WebLogic | Admin console on 7001/7002 reachable | passive | GET /console/login status |
| AS-WLS-002 | WebLogic | Async deserialization CVE-2019-2725; T3/IIOP CVE-2023-21839; console CVE-2020-14882 | passive | Version check |
| AS-GLF-001 | GlassFish | Admin console on 4848 with default credentials | authorized-only | GET status; credential test only if approved |
| AS-GLF-002 | GlassFish | JMX and RMI ports (8686, 3700, 4444, 4848) | passive | Port check only |
| AS-GLF-003 | GlassFish | Directory listing enabled | bounded | GET directories |
| AS-WSP-001 | WebSphere | Console and default ports exposed | passive | GET /ibm/console status |
| AS-CF-001 | Adobe ColdFusion | Administrator and RDS exposure; WDDX and LFI CVEs | passive | GET /CFIDE/administrator/ status; version check |

## TLS and protocol

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TLS-001 | Any | SSLv3, TLS 1.0 and 1.1 accepted | passive | `testssl.sh --protocols <host>` or `sslyze --regular <host>` |
| TLS-002 | Any | Weak ciphers (RC4, DES, NULL, EXPORT) | passive | `nmap --script ssl-enum-ciphers -p 443 <host>` |
| TLS-003 | Any | Heartbleed on OpenSSL | bounded | `nmap --script ssl-heartbleed -p 443 <host>` (read-only check) |
| TLS-004 | Any | Certificate expiry, hostname mismatch, weak key size | passive | `sslyze --certinfo <host>` |
| TLS-005 | Any | HSTS missing (see csrf-and-headers-audit) | passive | Response headers |
| TLS-006 | Any | Downgrade and renegotiation issues | bounded | `testssl.sh -U <host>` |
| TLS-007 | HTTP/2 | ALPN offers h2 on origin and edge | passive | `curl -sI --http2 <url>` |
| TLS-008 | Any | Session resumption cross-server (CVE-2025-23419 family) | passive | Config review on Nginx |
