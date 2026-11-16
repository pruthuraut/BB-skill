# Claude Code Assistant Guidelines: Bug Bounty & Vulnerability Skills Framework

This repository contains multi-agent skills implementing Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)* and specialized vulnerability auditing workflows derived from local repository notes.

## Available Skills & Agents

### Reconnaissance & Surface Discovery
1. **`recon-hunter` (Master 16-Phase Pipeline):** `.agents/skills/recon-hunter/SKILL.md` (Automated Recon-to-Bug Engine)
2. **`subdomainenum` (50 Checks):** `.agents/skills/subdomainenum/SKILL.md`
3. **`techfingerprint` (40 Checks):** `.agents/skills/techfingerprint/SKILL.md`
4. **`contentdiscovery` (50 Checks):** `.agents/skills/contentdiscovery/SKILL.md`
5. **`linkparamdiscovery` (40 Checks):** `.agents/skills/linkparamdiscovery/SKILL.md`
6. **`jsrecon` (JS Mining & Secrets):** `.agents/skills/jsrecon/SKILL.md`
7. **`cloud-supplychain` (Cloud & Dependency Confusion):** `.agents/skills/cloud-supplychain/SKILL.md`
8. **`network-portscan` (Full TCP Port & Service Discovery):** `.agents/skills/network-portscan/SKILL.md` (Naabu/Nmap/Masscan on explicitly authorized hosts)
9. **`subdomain-takeover` (50 Checks):** `.agents/skills/subdomain-takeover/SKILL.md` (Dangling CNAME/NS/MX/A records, decommissioned SaaS/cloud; non-destructive verification only)
10. **`server-config-audit` (102 + 20 SMC Checks):** `.agents/skills/server-config-audit/SKILL.md` (Apache, Nginx, IIS, Tomcat, Jetty, WildFly, WebLogic, WebSphere, JBoss, GlassFish, HTTP/2 misconfiguration)

### Authentication & Credential Security
11. **`credentialattacks` (40 Checks):** `.agents/skills/credentialattacks/SKILL.md`
12. **`authbypass` (40 Checks):** `.agents/skills/authbypass/SKILL.md` (Login/Registration Bypass, Verification & OTP Bypass, Identity Collisions, Email-Change ATO)
13. **`session-management` (40 Checks):** `.agents/skills/session-management/SKILL.md` (Token Entropy, Fixation, Cookie Attributes, Logout/Timeout, JWT Attacks)
14. **`oauth-sso` (50 Checks):** `.agents/skills/oauth-sso/SKILL.md` (OAuth 2.0, OIDC, SAML, SSO: redirect_uri, state, PKCE, id_token, XSW)

### Vulnerability & Logic Auditing
15. **`ssrf-audit` (55 Checks):** `.agents/skills/ssrf-audit/SKILL.md` (SSRF: URL fetchers, imports, webhooks, renderers (PDF/SVG/XXE/media), IP-format/IPv6/Unicode/DNS/rebinding/redirect/parser bypasses, cloud & container metadata, file:// and protocol schemes, bounded port fingerprinting, blind SSRF; O/R/S/W/N execution classes)
16. **`idor` (35 Checks):** `.agents/skills/idor/SKILL.md` (IDOR/BOLA: ID locations, UUID/ObjectId predictability, methods, versions, files, bulk, GraphQL, WebSockets, cross-account replay)
17. **`access-control` (37 Checks):** `.agents/skills/access-control/SKILL.md` (Privilege Escalation & Function-Level Authorization: roles, JWT/cookie claims, mass assignment, tenants, memberships, feature flags, gateway/UI vs API, races)
18. **`path-traversal` (39 Checks):** `.agents/skills/path-traversal/SKILL.md` (Path Traversal, LFI/RFI, encodings & filter bypasses, zip slip, PHP wrappers, server-level traversal; R/S/W/X execution classes)
19. **`sqli` (50 Checks):** `.agents/skills/sqli/SKILL.md` (SQL Injection: all input locations, UNION/error/boolean/time/OOB, ORDER BY/LIMIT/LIKE/IN/identifier contexts, write-sink safety, second-order, JSON/GraphQL, WAF bypass, MySQL/PostgreSQL/MSSQL/Oracle/SQLite; D/P/S/W/X execution classes)
20. **`xss` (60 Checks):** `.agents/skills/xss/SKILL.md` (Reflected/Stored/Blind/DOM XSS, context breakouts, SVG/Markdown/PDF/email sinks, AngularJS/Vue/React, mXSS, postMessage, DOM clobbering, prototype pollution, WAF/CSP bypass, dangling markup, XSSI/JSONP; R/E/S/B/I execution classes)
21. **`business-logic` (25 Checks):** `.agents/skills/business-logic/SKILL.md` (Price Manipulation, Race Conditions, State Machine Bypasses)
22. **`api-security` (25 + 25 AA + 15 AI Checks):** `.agents/skills/api-security/SKILL.md` (Swagger/OpenAPI Exposure, GraphQL Security, CORS)
23. **`resource-exhaustion` (25 Checks):** `.agents/skills/resource-exhaustion/SKILL.md` (Rate Limiting, Form Flooding, Destructive Action Re-Auth)

### Smart Start and Routing
- `target-router` (planning only): run `python3 scripts/route_target.py --target <t> --fingerprint <file> --params <file> --urls <file>`. It prints the skills and checklist rows that apply, with each row's class (`passive`, `bounded`, `authorized-only`). It never sends traffic.

### Technology and Platform Exposure
24. **`tech-stack-audit` (about 470 checks):** `.agents/skills/tech-stack-audit/SKILL.md` (CMS, frameworks, DevOps, monitoring, databases, appliances, IoT, enterprise; version and exposure checks, no exploits)
25. **`saas-third-party-exposure` (about 90 vendors):** `.agents/skills/saas-third-party-exposure/SKILL.md` (client-side keys and tags, public vs secret)

### Additional Vulnerability Classes
26. **`open-redirect-and-header-injection`:** `.agents/skills/open-redirect-and-header-injection/SKILL.md` (open redirect, CRLF, Host header)
27. **`server-side-injection` (33 checks):** `.agents/skills/server-side-injection/SKILL.md` (SSTI, command injection, XXE, NoSQL, LDAP, deserialization)
28. **`csrf-and-headers-audit` (about 30 checks):** `.agents/skills/csrf-and-headers-audit/SKILL.md` (CSRF, clickjacking, security headers, CSP)
29. **`http-protocol-cache` (about 30 checks):** `.agents/skills/http-protocol-cache/SKILL.md` (smuggling, HTTP/2, cache poisoning, WAF bypass)
30. **`client-side-js-security` (about 30 checks):** `.agents/skills/client-side-js-security/SKILL.md` (prototype pollution, postMessage, storage, service workers, WebSockets)
31. **`file-upload-audit` (40 checks: UP + FU):** `.agents/skills/file-upload-audit/SKILL.md`
32. **`email-security-audit` (14 checks):** `.agents/skills/email-security-audit/SKILL.md`
33. **`ssti-audit` (about 70 checks):** `.agents/skills/ssti-audit/SKILL.md` (template injection detection across engines, injection points, blind SSTI; `scripts/ssti_probe.py` for scope-gated arithmetic probes)
34. **`command-injection-audit` (about 65 checks):** `.agents/skills/command-injection-audit/SKILL.md` (unix and Windows command injection; `scripts/cmdi_probe.py` for scope-gated split-marker and arithmetic probes; `scripts/sink_scan.py` for passive source review)
35. **`nosql-injection-audit` (about 40 checks):** `.agents/skills/nosql-injection-audit/SKILL.md` (operator and syntax differential probes; `scripts/nosql_probe.py`)
36. **`ldap-injection-audit` (about 30 checks):** `.agents/skills/ldap-injection-audit/SKILL.md` (wildcard, boolean, escape differential probes; `scripts/ldap_probe.py`)
37. **`xml-xxe-audit` (about 45 checks):** `.agents/skills/xml-xxe-audit/SKILL.md` (entity expansion, out-of-band XXE, XInclude, XSLT, XPath; `scripts/xxe_probe.py`, `scripts/xml_parser_scan.py`)
38. **`business-logic-vulns` (20 checks):** `.agents/skills/business-logic-vulns/SKILL.md` (price, quantity, currency, discount stacking, referrals, coupon races, double spend, payment-step bypass, interest/transfer tampering, negative balances, resource and storage quotas, workflow and state machine, refunds, trial dates, feature flags, subscription tier, verification bypass)
39. **`race-conditions` (15 checks + limit sweep):** `.agents/skills/race-conditions/SKILL.md` (balance, coupons, votes, uploads, signup, reset tokens, gift cards, inventory, 2FA, sessions, rate limits, read-modify-write, distributed consistency; "only N times" limit sweep; `scripts/race_probe.py` for scope-gated synchronized bursts)
40. **`csrf-audit` (20 core + about 45 bypass checks):** `.agents/skills/csrf-audit/SKILL.md` (token removal/reuse/entropy/session binding, JSON/XML/multipart/AJAX/WebSocket/GraphQL, SameSite, login/password/email CSRF, method override, Origin/Referer bypasses, chains; PoC templates; `scripts/csrf_probe.py`, `scripts/csrf_token_analyze.py`)
41. **`cors-audit` (15 core + about 40 bypass origins):** `.agents/skills/cors-audit/SKILL.md` (origin reflection, null, subdomain/suffix/prefix/regex, parser and encoding tricks, third-party trust, preflight, WebSocket; impact chains incl. CSRF-token theft, internal pivot, TLS break, Vary cache; concepts and PoC templates; `scripts/cors_probe.py`)
42. **`clickjacking-audit` (10 core + about 25 variants):** `.agents/skills/clickjacking-audit/SKILL.md` (XFO and frame-ancestors parsing, coverage gaps, same-origin gadgets, frame-buster sandbox bypass, double-clickjacking, cursorjacking, drag-and-drop, multi-step, prefilled forms, auth and OAuth consent pages; PoC templates; `scripts/clickjack_check.py`)
43. **`postmessage-audit` (10 core + variants):** `.agents/skills/postmessage-audit/SKILL.md` (origin and source checks, weak origin patterns, wildcard targetOrigin, sinks, iframe/popup channels, extensions; PoC templates; `scripts/pm_scan.py` passive JS scanner)
44. **`file-download-audit` (10 core + variants):** `.agents/skills/file-download-audit/SKILL.md` (traversal download, listing, MIME, Content-Disposition, auth, file IDOR, cloud/signed URLs, sensitive files, symlinks, PDF generation; `scripts/download_check.py`)
45. **`tls-audit` (20 checks + extras):** `.agents/skills/tls-audit/SKILL.md` (protocols, ciphers, POODLE/BEAST/CRIME/BREACH/Heartbleed/Sweet32, HSTS, certificates, mixed content, cookies, OCSP, pinning, FS, CT, downgrade, renegotiation; `scripts/tls_quick.py`, `scripts/tls_map_testssl.py`)
46. **`crypto-audit` (15 checks + variants):** `.agents/skills/crypto-audit/SKILL.md` (password hashing, weak ciphers/ECB, hardcoded keys, key management, IV reuse, padding oracle, KDF, RNG, timing, pinning bypass, JWT confusion, repo key exposure; `scripts/crypto_scan.py`, `scripts/cipher_analyze.py`)
47. **`request-smuggling-audit` (10 core + variants):** `.agents/skills/request-smuggling-audit/SKILL.md` (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, header techniques, proxy/LB chains, WAF bypass, cache via smuggling, CL.0, client-side and pause-based desync, h2c; timing-first detection; `scripts/smuggle_timing.py`)
48. **`cache-poisoning-audit` (10 core + variants):** `.agents/skills/cache-poisoning-audit/SKILL.md` (unkeyed headers/cookies/params, deception path and extension tricks, normalization, method override, Vary, fat GET, header injection, CPDoS, CDN notes; buster-only probes; `scripts/cache_probe.py`)
49. **`cloud-container-audit` (15 checks + variants):** `.agents/skills/cloud-container-audit/SKILL.md` (S3/Blob/GCS public access, AWS/Azure/GCP metadata via SSRF, Docker API, Kubernetes API, kubelet, etcd, dashboard, container escape exposure, IAM, functions, databases, queues, CDN; `scripts/cloud_exposure_check.py`)
50. **`data-exposure-audit` (20 checks):** `.agents/skills/data-exposure-audit/SKILL.md` (page source/comments, JS and source maps, client keys, meta/hidden fields, errors, debug endpoints, robots/sitemap, .env/config, backups, VCS, logs, headers, cookies, web storage, IndexedDB, API PII and excess data, URL params, autocomplete, Referer; `scripts/exposure_scan.py`, `scripts/api_pii_scan.py`)
51. **`error-handling-audit` (10 checks):** `.agents/skills/error-handling-audit/SKILL.md` (stack traces, DB errors, versions, internal IPs/paths, crafted input, valid/invalid differentials, custom error pages, debug pages, API status codes, GraphQL errors; `scripts/error_probe.py`)
52. **`websocket-audit` (15 checks):** `.agents/skills/websocket-audit/SKILL.md` (unauth sockets, CSWSH, tampering, replay, flooding (approval), plaintext data, Origin bypass, ws/wss, room IDOR, rate limits, SQLi/XSS/command injection, token hijacking, downgrade; `scripts/ws_probe.py`)
53. **`graphql-audit` (15 checks):** `.agents/skills/graphql-audit/SKILL.md` (introspection, depth, batching, aliases, directives, mutation authz, subscriptions, injection, suggestions, errors, nested DoS (approval), IDOR, field authz, complexity, persisted queries; `scripts/gql_probe.py`)
54. **`rest-api-audit` (15 checks):** `.agents/skills/rest-api-audit/SKILL.md` (own-object CRUD authz lifecycle, method handling, HEAD/OPTIONS, URL/body/header manipulation, status codes, error consistency, HATEOAS, pagination, sort/filter injection, version deprecation and compatibility; `scripts/rest_probe.py`)
55. **`soap-api-audit` (10 checks):** `.agents/skills/soap-api-audit/SKILL.md` (SOAPAction spoofing, XML injection, XXE, WSDL enumeration, WS-Security, replay, faults, attachments, encoding/type confusion, namespaces; `scripts/soap_probe.py`)
56. **`grpc-audit` (10 checks):** `.agents/skills/grpc-audit/SKILL.md` (reflection, unauth access, protobuf serialization, plaintext/h2c hijacking, metadata, stream DoS (approval), TLS/ALPN/gRPC-Web, enumeration, deadlines, credentials; `scripts/grpc_probe.py` + grpcurl)

Existing skills gained an "Extended checklist (added)" section that points to a `references/` file. Each row carries an ID, product, check, class, and safe verification.

## Environment Setup & Tooling
- Run `./setup.sh` to install all required Go, Python, and system dependencies automatically.
- Consult [SETUP.md](SETUP.md) for full tool installation commands, provider configs, and health-check verification.

## Standard Execution Rules
- Never assume a target is authorized. Active testing requires `scripts/scope_check.sh TARGET` to pass against that target's `scope.txt`.
- To check a subdomain, IP, or cloud host against a program's scope file, use `scripts/scope_check.sh HOST [ROOT] PROGRAM` (reads `<ROOT>/<PROGRAM>/scope.txt`). Skill scripts that take `--target` do this automatically.
- Always divide auditing across specialized subagents to preserve context fidelity.
- Update tracking checklists from 0 to N complete during assessments.
- Reference specialized wordlists under `wordlists/` (indexed in `wordlists/README.md`).
- Save all structured findings to `artifacts/`.
- Classes: run `passive` and `bounded` rows inside scope with the stated limits. Run `authorized-only` rows only after explicit approval for that specific check.
- Version-gated CVE rows are version checks. Never run exploit code from a checklist row.
