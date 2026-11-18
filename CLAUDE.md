# Claude Code Assistant Guidelines: Bug Bounty & Vulnerability Skills Framework

This repository contains multi-agent skills implementing Jason Haddix's *The Bug Hunter's Methodology (TBHM v4)* and specialized vulnerability auditing workflows derived from local repository notes.

## Available Skills & Agents

### Reconnaissance & Surface Discovery
1. **`recon-hunter` (Master 16-Phase Pipeline):** `.agents/skills/recon-hunter/SKILL.md` (Automated Recon-to-Bug Engine)
2. **`subdomainenum` (50 Checks):** `.agents/skills/subdomainenum/SKILL.md`
3. **`techfingerprint` (40 Checks):** `.agents/skills/techfingerprint/SKILL.md`
4. **`contentdiscovery` (50 Checks):** `.agents/skills/contentdiscovery/SKILL.md`
5. **`linkparamdiscovery` (40 Checks):** `.agents/skills/linkparamdiscovery/SKILL.md`
6. **`jsrecon` (JS Mining & Secrets + 50 JSA checks):** `.agents/skills/jsrecon/SKILL.md` (`scripts/js_analyzer.py` secrets/routes/source maps; `scripts/js_sink_audit.py` sinks, browser APIs, storage, workers, CSP/Trusted Types gadgets, third-party scripts)
7. **`cloud-supplychain` (Cloud & Dependency Confusion):** `.agents/skills/cloud-supplychain/SKILL.md`
8. **`network-portscan` (Full TCP Port & Service Discovery):** `.agents/skills/network-portscan/SKILL.md` (Naabu/Nmap/Masscan on explicitly authorized hosts)
9. **`subdomain-takeover` (50 Checks):** `.agents/skills/subdomain-takeover/SKILL.md` (Dangling CNAME/NS/MX/A records, decommissioned SaaS/cloud; non-destructive verification only)
10. **`server-config-audit` (102 + 20 SMC Checks):** + merged: `tls-audit` `.agents/skills/server-config-audit/SKILL.md` (Apache, Nginx, IIS, Tomcat, Jetty, WildFly, WebLogic, WebSphere, JBoss, GlassFish, HTTP/2 misconfiguration)

### Authentication & Credential Security
11. **`credentialattacks` (40 Checks):** `.agents/skills/credentialattacks/SKILL.md`
12. **`authbypass` (40 Checks):** `.agents/skills/authbypass/SKILL.md` (Login/Registration Bypass, Verification & OTP Bypass, Identity Collisions, Email-Change ATO)
13. **`session-management` (40 Checks):** `.agents/skills/session-management/SKILL.md` (Token Entropy, Fixation, Cookie Attributes, Logout/Timeout, JWT Attacks) + extended: deep JWT (20 checks, `scripts/jwt_variant_probe.py`)
14. **`oauth-sso` (50 Checks):** `.agents/skills/oauth-sso/SKILL.md` (OAuth 2.0, OIDC, SAML, SSO: redirect_uri, state, PKCE, id_token, XSW)

### Vulnerability & Logic Auditing
15. **`ssrf-audit` (55 Checks):** `.agents/skills/ssrf-audit/SKILL.md` (SSRF: URL fetchers, imports, webhooks, renderers (PDF/SVG/XXE/media), IP-format/IPv6/Unicode/DNS/rebinding/redirect/parser bypasses, cloud & container metadata, file:// and protocol schemes, bounded port fingerprinting, blind SSRF; O/R/S/W/N execution classes)
16. **`idor` (35 Checks):** `.agents/skills/idor/SKILL.md` (IDOR/BOLA: ID locations, UUID/ObjectId predictability, methods, versions, files, bulk, GraphQL, WebSockets, cross-account replay)
17. **`access-control` (37 Checks):** `.agents/skills/access-control/SKILL.md` (Privilege Escalation & Function-Level Authorization: roles, JWT/cookie claims, mass assignment, tenants, memberships, feature flags, gateway/UI vs API, races)
18. **`path-traversal` (39 Checks):** `.agents/skills/path-traversal/SKILL.md` (Path Traversal, LFI/RFI, encodings & filter bypasses, zip slip, PHP wrappers, server-level traversal; R/S/W/X execution classes)
19. **`sqli` (50 Checks):** `.agents/skills/sqli/SKILL.md` (SQL Injection: all input locations, UNION/error/boolean/time/OOB, ORDER BY/LIMIT/LIKE/IN/identifier contexts, write-sink safety, second-order, JSON/GraphQL, WAF bypass, MySQL/PostgreSQL/MSSQL/Oracle/SQLite; D/P/S/W/X execution classes)
20. **`xss` (60 Checks):** `.agents/skills/xss/SKILL.md` (Reflected/Stored/Blind/DOM XSS, context breakouts, SVG/Markdown/PDF/email sinks, AngularJS/Vue/React, mXSS, postMessage, DOM clobbering, prototype pollution, WAF/CSP bypass, dangling markup, XSSI/JSONP; R/E/S/B/I execution classes)
21. **`api-security` (25 + 25 AA + 15 AI Checks):** `.agents/skills/api-security/SKILL.md` (Swagger/OpenAPI Exposure, GraphQL Security, CORS)
22. **`resource-exhaustion` (25 Checks):** `.agents/skills/resource-exhaustion/SKILL.md` (Rate Limiting, Form Flooding, Destructive Action Re-Auth)

### Smart Start and Routing
- `target-router` (planning only): run `python3 scripts/route_target.py --target <t> --fingerprint <file> --params <file> --urls <file>`. It prints the skills and checklist rows that apply, with each row's class (`passive`, `bounded`, `authorized-only`). It never sends traffic.

### Technology and Platform Exposure
23. **`tech-stack-audit` (about 470 checks):** `.agents/skills/tech-stack-audit/SKILL.md` (CMS, frameworks, DevOps, monitoring, databases, appliances, IoT, enterprise; version and exposure checks, no exploits)
24. **`saas-third-party-exposure` (about 90 vendors):** `.agents/skills/saas-third-party-exposure/SKILL.md` (client-side keys and tags, public vs secret)

### Additional Vulnerability Classes
25. **`open-redirect-and-header-injection`:** `.agents/skills/open-redirect-and-header-injection/SKILL.md` (open redirect, CRLF, Host header) + extended: open redirect (15 checks), CRLF (10 checks; `scripts/redirect_crlf_probe.py`)
26. **`server-side-injection` (33 checks):** `.agents/skills/server-side-injection/SKILL.md` (SSTI, command injection, XXE, NoSQL, LDAP, deserialization) + extended: deserialization (21 checks, `scripts/deser_detect.py`), SSI (10 checks, `scripts/ssi_probe.py`)
27. **`client-side-js-security` (about 30 checks):** + merged: `postmessage-audit`, `websocket-audit` `.agents/skills/client-side-js-security/SKILL.md` (prototype pollution, postMessage, storage, service workers, WebSockets) + extended: prototype pollution (20 checks, `scripts/pp_scan.py`), WebSocket deep (15 checks)
28. **`file-upload-audit` (40 checks: UP + FU):** `.agents/skills/file-upload-audit/SKILL.md`
29. **`email-security-audit` (14 MAIL + 25 EM checks):** `.agents/skills/email-security-audit/SKILL.md` (`scripts/email_dns_audit.py`: SPF/DKIM/DMARC/CAA/BIMI/MTA-STS/MX, subdomain spoofability, scope-gated SMTP VRFY/EXPN)
30. **`ssti-audit` (about 70 checks):** `.agents/skills/ssti-audit/SKILL.md` (template injection detection across engines, injection points, blind SSTI; `scripts/ssti_probe.py` for scope-gated arithmetic probes)
31. **`command-injection-audit` (about 65 checks):** `.agents/skills/command-injection-audit/SKILL.md` (unix and Windows command injection; `scripts/cmdi_probe.py` for scope-gated split-marker and arithmetic probes; `scripts/sink_scan.py` for passive source review)
32. **`nosql-injection-audit` (about 40 checks):** `.agents/skills/nosql-injection-audit/SKILL.md` (operator and syntax differential probes; `scripts/nosql_probe.py`)
33. **`ldap-injection-audit` (about 30 checks):** `.agents/skills/ldap-injection-audit/SKILL.md` (wildcard, boolean, escape differential probes; `scripts/ldap_probe.py`)
34. **`xml-xxe-audit` (about 45 checks):** + merged: `soap-api-audit` `.agents/skills/xml-xxe-audit/SKILL.md` (entity expansion, out-of-band XXE, XInclude, XSLT, XPath; `scripts/xxe_probe.py`, `scripts/xml_parser_scan.py`)
35. **`business-logic-vulns` (20 checks):** + merged: `business-logic`, `race-conditions` `.agents/skills/business-logic-vulns/SKILL.md` (price, quantity, currency, discount stacking, referrals, coupon races, double spend, payment-step bypass, interest/transfer tampering, negative balances, resource and storage quotas, workflow and state machine, refunds, trial dates, feature flags, subscription tier, verification bypass)
36. **`csrf-audit` (20 core + about 45 bypass checks):** + merged: `csrf-and-headers-audit`, `clickjacking-audit` `.agents/skills/csrf-audit/SKILL.md` (token removal/reuse/entropy/session binding, JSON/XML/multipart/AJAX/WebSocket/GraphQL, SameSite, login/password/email CSRF, method override, Origin/Referer bypasses, chains; PoC templates; `scripts/csrf_probe.py`, `scripts/csrf_token_analyze.py`)
37. **`cors-audit` (15 core + about 40 bypass origins):** `.agents/skills/cors-audit/SKILL.md` (origin reflection, null, subdomain/suffix/prefix/regex, parser and encoding tricks, third-party trust, preflight, WebSocket; impact chains incl. CSRF-token theft, internal pivot, TLS break, Vary cache; concepts and PoC templates; `scripts/cors_probe.py`)
38. **`file-download-audit` (10 core + variants):** `.agents/skills/file-download-audit/SKILL.md` (traversal download, listing, MIME, Content-Disposition, auth, file IDOR, cloud/signed URLs, sensitive files, symlinks, PDF generation; `scripts/download_check.py`)
39. **`crypto-audit` (15 checks + variants):** `.agents/skills/crypto-audit/SKILL.md` (password hashing, weak ciphers/ECB, hardcoded keys, key management, IV reuse, padding oracle, KDF, RNG, timing, pinning bypass, JWT confusion, repo key exposure; `scripts/crypto_scan.py`, `scripts/cipher_analyze.py`)
40. **`request-smuggling-audit` (10 core + variants):** + merged: `http-protocol-cache` `.agents/skills/request-smuggling-audit/SKILL.md` (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, header techniques, proxy/LB chains, WAF bypass, cache via smuggling, CL.0, client-side and pause-based desync, h2c; timing-first detection; `scripts/smuggle_timing.py`) + extended: WAF bypass (25 checks, `scripts/waf_probe.py`)
41. **`cache-poisoning-audit` (10 core + variants):** `.agents/skills/cache-poisoning-audit/SKILL.md` (unkeyed headers/cookies/params, deception path and extension tricks, normalization, method override, Vary, fat GET, header injection, CPDoS, CDN notes; buster-only probes; `scripts/cache_probe.py`)
42. **`cloud-container-audit` (15 checks + variants):** `.agents/skills/cloud-container-audit/SKILL.md` (S3/Blob/GCS public access, AWS/Azure/GCP metadata via SSRF, Docker API, Kubernetes API, kubelet, etcd, dashboard, container escape exposure, IAM, functions, databases, queues, CDN; `scripts/cloud_exposure_check.py`)
43. **`data-exposure-audit` (20 checks):** `.agents/skills/data-exposure-audit/SKILL.md` (page source/comments, JS and source maps, client keys, meta/hidden fields, errors, debug endpoints, robots/sitemap, .env/config, backups, VCS, logs, headers, cookies, web storage, IndexedDB, API PII and excess data, URL params, autocomplete, Referer; `scripts/exposure_scan.py`, `scripts/api_pii_scan.py`)
44. **`error-handling-audit` (10 checks):** `.agents/skills/error-handling-audit/SKILL.md` (stack traces, DB errors, versions, internal IPs/paths, crafted input, valid/invalid differentials, custom error pages, debug pages, API status codes, GraphQL errors; `scripts/error_probe.py`)
45. **`graphql-audit` (15 checks):** `.agents/skills/graphql-audit/SKILL.md` (introspection, depth, batching, aliases, directives, mutation authz, subscriptions, injection, suggestions, errors, nested DoS (approval), IDOR, field authz, complexity, persisted queries; `scripts/gql_probe.py`)
46. **`rest-api-audit` (15 checks):** `.agents/skills/rest-api-audit/SKILL.md` (own-object CRUD authz lifecycle, method handling, HEAD/OPTIONS, URL/body/header manipulation, status codes, error consistency, HATEOAS, pagination, sort/filter injection, version deprecation and compatibility; `scripts/rest_probe.py`)
47. **`grpc-audit` (10 checks):** `.agents/skills/grpc-audit/SKILL.md` (reflection, unauth access, protobuf serialization, plaintext/h2c hijacking, metadata, stream DoS (approval), TLS/ALPN/gRPC-Web, enumeration, deadlines, credentials; `scripts/grpc_probe.py` + grpcurl)
48. **`google-dorking-osint` (49 checks):** `.agents/skills/google-dorking-osint/SKILL.md` (search-engine dorks for exposed files, listings, panels, sensitive paths, secrets, SQL errors, and leaks on pastebin/GitHub/Gist/Stack Overflow/Trello/Slack/Notion; `scripts/dork_gen.py` writes clickable dorks, `scripts/dork_triage.py` ranks and scope-verifies hits)
49. **`dns-security-audit` (22 checks):** `.agents/skills/dns-security-audit/SKILL.md` (AXFR, DNSSEC, DoH/DoT, recursion, record disclosure, RRL, cookies; Kali dig, dnsrecon, nmap, openssl; `scripts/dns_probe.py`)
50. **`microservices-gateway-audit` (22 checks):** `.agents/skills/microservices-gateway-audit/SKILL.md` (Eureka, Consul, Nacos discovery, gateway bypass, tracing and CORS, mesh and mTLS; Kali nmap; `scripts/gateway_probe.py`)

51. **`phpmyadmin-audit` (143 checks):** `.agents/skills/phpmyadmin-audit/SKILL.md` (phpMyAdmin discovery, fingerprinting, config and backup exposure, login token and cookies, version-only CVE checks, bounded XSS and SQL-error probes, approval-gated file reads, authorized-only database steps; Kali ffuf, gobuster, dirsearch, nuclei, nikto, nmap NSE, searchsploit, sqlmap, hydra; `scripts/pma_probe.py`)

52. **`android-app-audit`:** `.agents/skills/android-app-audit/SKILL.md` (orchestrator for Android app testing: 19 category skills, 1,011 checklist rows, `android_static.py`, `android_device.py`, `firebase_probe.py`, `deeplink_probe.py`, Frida hooks; setup.sh installs jadx, apktool, adb, frida, objection, drozer, apkleaks, mobsfscan)
53. **`android-static-audit`:** `.agents/skills/android-static-audit/SKILL.md` (41 checks: jadx and apktool decompilation, manifest exposure, secrets, SDK versions, obfuscation)
54. **`android-dynamic-audit`:** `.agents/skills/android-dynamic-audit/SKILL.md` (30 checks: Frida, Objection, Burp, Drozer, adb intents, file permissions (test device, approval for active checks))
55. **`android-data-storage-audit`:** `.agents/skills/android-data-storage-audit/SKILL.md` (15 checks: SharedPreferences and SQLite plaintext, file permissions, cache, backups, logcat, Keystore use)
56. **`android-network-audit`:** `.agents/skills/android-network-audit/SKILL.md` (30 checks: cleartext, network security config, pinning, TrustManager, hostname verifier, TLS)
57. **`android-reverse-protection-audit`:** `.agents/skills/android-reverse-protection-audit/SKILL.md` (15 checks: root, emulator, Frida and debugger detection, obfuscation, repackaging, dynamic code loading)
58. **`android-ipc-intent-audit`:** `.agents/skills/android-ipc-intent-audit/SKILL.md` (30 checks: exported components, intent injection and redirection, PendingIntent, providers, task hijacking)
59. **`android-webview-audit`:** `.agents/skills/android-webview-audit/SKILL.md` (20 checks: JavaScript interface, file and content access, SSL error handler, saved passwords, URL override)
60. **`android-crypto-keystore-audit`:** `.agents/skills/android-crypto-keystore-audit/SKILL.md` (80 checks: ECB, hardcoded keys, KDFs, IV reuse, Keystore KeyGenParameterSpec, biometric crypto objects)
61. **`android-firebase-audit`:** `.agents/skills/android-firebase-audit/SKILL.md` (15 checks: Realtime Database, Firestore, Storage, Remote Config, google-services.json (read-only, scope-gated))
62. **`android-deeplink-audit`:** `.agents/skills/android-deeplink-audit/SKILL.md` (50 checks: deep link validation, App Links and assetlinks.json, scheme hijacking, parameter injection)
63. **`android-notification-audit`:** `.agents/skills/android-notification-audit/SKILL.md` (50 checks: lock-screen content, pending intents, channels, listeners, remote views)
64. **`android-permission-audit`:** `.agents/skills/android-permission-audit/SKILL.md` (50 checks: minimum permissions, dangerous and custom permission protection levels, runtime checks)
65. **`android-backup-audit`:** `.agents/skills/android-backup-audit/SKILL.md` (50 checks: allowBackup, fullBackupContent, adb backup (gated), backup agents, secrets in backup)
66. **`android-logging-audit`:** `.agents/skills/android-logging-audit/SKILL.md` (50 checks: sensitive data in logs, release log stripping, logcat exposure, crash reports)
67. **`android-component-audit`:** `.agents/skills/android-component-audit/SKILL.md` (50 checks: exported activities, services, receivers and providers, caller identity, provider paths)
68. **`android-enterprise-audit`:** `.agents/skills/android-enterprise-audit/SKILL.md` (145 checks: work profile isolation and MDM/enterprise behaviour; device-platform bypasses recorded as not tested)
69. **`android-sdk-payment-audit`:** `.agents/skills/android-sdk-payment-audit/SKILL.md` (100 checks: third-party SDK data flows, ad and analytics SDKs, in-app purchase and wallet logic)
70. **`android-accessibility-audit`:** `.agents/skills/android-accessibility-audit/SKILL.md` (98 checks, defensive only: FLAG_SECURE, password and card fields, overlay and tapjacking defences)
71. **`android-forensic-audit`:** `.agents/skills/android-forensic-audit/SKILL.md` (92 checks: residue of the app's own data on the owner's test device after uninstall or clearing)

72. **`ios-app-audit`:** `.agents/skills/ios-app-audit/SKILL.md` (orchestrator for iOS app testing: 16 category skills, 955 checklist rows `IOS-0001`..`IOS-0955`, `ios_static.py` with a built-in Mach-O reader, `ios_container_audit.py`, `ios_device.py` (libimobiledevice + SSH, gated), `ios_deeplink.py` (scope-gated AASA), `ios_checklist.py` (0/N to N/N tracker), 19 Frida hooks, `selftest.py`; setup.sh installs radare2, libimobiledevice, ideviceinstaller, frida, objection, ipsw)
73. **`ios-static-audit`:** `.agents/skills/ios-static-audit/SKILL.md` (30 checks: class dump, Info.plist, ATS, URL schemes, secrets, entitlements, Mach-O hardening, SDKs, WebView, keychain and crypto API use)
74. **`ios-dynamic-audit`:** `.agents/skills/ios-dynamic-audit/SKILL.md` (20 checks: Frida, Objection, pinning and jailbreak bypass, Burp, LLDB, biometrics, pasteboard, UserDefaults, snapshots (jailbroken test device, approval for active checks))
75. **`ios-reverse-protection-audit`:** `.agents/skills/ios-reverse-protection-audit/SKILL.md` (10 checks: jailbreak detection, dylib injection, anti-debugging, code signing and integrity)
76. **`ios-data-storage-audit`:** `.agents/skills/ios-data-storage-audit/SKILL.md` (75 checks: keychain, UserDefaults, plists, SQLite, caches, tmp, backups, iCloud, Data Protection classes, file system)
77. **`ios-coredata-audit`:** `.agents/skills/ios-coredata-audit/SKILL.md` (50 checks: store protection, WAL/SHM, predicate injection, transformables, CloudKit, Spotlight, logout cleanup)
78. **`ios-network-audit`:** `.agents/skills/ios-network-audit/SKILL.md` (25 checks: ATS exceptions, cleartext, pinning, trust evaluation, cookies, credential storage, WebSockets, background sessions)
79. **`ios-crypto-keychain-audit`:** `.agents/skills/ios-crypto-keychain-audit/SKILL.md` (70 checks: weak algorithms, ECB, hardcoded keys, PBKDF2, IV reuse, RNG, Secure Enclave, keychain accessibility, access control, access groups)
80. **`ios-deeplink-audit`:** `.agents/skills/ios-deeplink-audit/SKILL.md` (65 checks: URL schemes, universal links, AASA (scope-gated), parameter injection, open redirect, WebView loading, auth on link handlers)
81. **`ios-privacy-permission-audit`:** `.agents/skills/ios-privacy-permission-audit/SKILL.md` (15 checks: usage descriptions vs imported APIs and entitlements, ATT, local network, HealthKit, HomeKit)
82. **`ios-extension-ipc-audit`:** `.agents/skills/ios-extension-ipc-audit/SKILL.md` (65 checks: share, widget, keyboard, notification, intents, file provider and network extensions; app groups, Handoff, Darwin notifications, XPC)
83. **`ios-sandbox-audit`:** `.agents/skills/ios-sandbox-audit/SKILL.md` (50 checks: container isolation, app group and iCloud containers, bookmarks, symlinks; platform escapes not tested)
84. **`ios-notification-audit`:** `.agents/skills/ios-notification-audit/SKILL.md` (50 checks: lock-screen content, extensions, action authentication, critical alerts, silent pushes)
85. **`ios-memory-audit`:** `.agents/skills/ios-memory-audit/SKILL.md` (143 checks: PIE, canary, ARC, PAC, unsafe C, secret retention in memory via marker scan)
86. **`ios-sdk-payment-audit`:** `.agents/skills/ios-sdk-payment-audit/SKILL.md` (100 checks: SDK inventory and data flows, StoreKit receipts and subscriptions, Apple Pay, card forms, wallet limits)
87. **`ios-accessibility-audit`:** `.agents/skills/ios-accessibility-audit/SKILL.md` (97 checks, defensive only: secure text entry, keyboard cache, third-party keyboards, accessibility values, screen capture; OS features not tested)
88. **`ios-forensic-audit`:** `.agents/skills/ios-forensic-audit/SKILL.md` (90 checks: the app's own residue after logout, clearing, uninstall and reinstall; system data not tested)

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
