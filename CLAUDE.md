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
10. **`server-config-audit` (102 Checks):** `.agents/skills/server-config-audit/SKILL.md` (Apache, Nginx, IIS, Tomcat, Jetty, WildFly, WebLogic, WebSphere, JBoss, GlassFish, HTTP/2 misconfiguration)

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
22. **`api-security` (25 Checks):** `.agents/skills/api-security/SKILL.md` (Swagger/OpenAPI Exposure, GraphQL Security, CORS)
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
31. **`file-upload-audit` (20 checks):** `.agents/skills/file-upload-audit/SKILL.md`
32. **`email-security-audit` (14 checks):** `.agents/skills/email-security-audit/SKILL.md`
33. **`ssti-audit` (about 70 checks):** `.agents/skills/ssti-audit/SKILL.md` (template injection detection across engines, injection points, blind SSTI; `scripts/ssti_probe.py` for scope-gated arithmetic probes)
34. **`command-injection-audit` (about 65 checks):** `.agents/skills/command-injection-audit/SKILL.md` (unix and Windows command injection; `scripts/cmdi_probe.py` for scope-gated split-marker and arithmetic probes; `scripts/sink_scan.py` for passive source review)
35. **`nosql-injection-audit` (about 40 checks):** `.agents/skills/nosql-injection-audit/SKILL.md` (operator and syntax differential probes; `scripts/nosql_probe.py`)
36. **`ldap-injection-audit` (about 30 checks):** `.agents/skills/ldap-injection-audit/SKILL.md` (wildcard, boolean, escape differential probes; `scripts/ldap_probe.py`)
37. **`xml-xxe-audit` (about 45 checks):** `.agents/skills/xml-xxe-audit/SKILL.md` (entity expansion, out-of-band XXE, XInclude, XSLT, XPath; `scripts/xxe_probe.py`, `scripts/xml_parser_scan.py`)

Existing skills gained an "Extended checklist (added)" section that points to a `references/` file. Each row carries an ID, product, check, class, and safe verification.

## Environment Setup & Tooling
- Run `./setup.sh` to install all required Go, Python, and system dependencies automatically.
- Consult [SETUP.md](SETUP.md) for full tool installation commands, provider configs, and health-check verification.

## Standard Execution Rules
- Never assume a target is authorized. Active testing requires `scripts/scope_check.sh TARGET` to pass against that target's `scope.txt`.
- Always divide auditing across specialized subagents to preserve context fidelity.
- Update tracking checklists from 0 to N complete during assessments.
- Reference specialized wordlists under `wordlists/` (indexed in `wordlists/README.md`).
- Save all structured findings to `artifacts/`.
- Classes: run `passive` and `bounded` rows inside scope with the stated limits. Run `authorized-only` rows only after explicit approval for that specific check.
- Version-gated CVE rows are version checks. Never run exploit code from a checklist row.
