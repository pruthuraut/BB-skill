# Server Misconfiguration Checklist (SMC, 20 generic checks)

Extends `checklist_102.md` (product-specific) with generic misconfiguration checks that apply to any stack. Router class key: `passive` = existing headers, one ordinary GET/HEAD/OPTIONS; `bounded` = a few low-impact requests to idempotent endpoints (maps to class B in SKILL.md); `authorized-only` = credential attempts (class C), state changes (class M), or lab-only behavior (class L).

Probe: `scripts/misconfig_probe.py` covers SMC-003 to SMC-009, SMC-012, SMC-013, SMC-015, SMC-017, and SMC-018 to SMC-020 (when given a reflected parameter).

## Core checks (20)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SMC-001 | Admin panels | Default credentials on server services and admin panels (Tomcat manager, Jenkins, Grafana, routers, databases, CMS admin) | authorized-only | Class C only: one attempt with an owner-supplied disposable account; otherwise report the reachable login and product version (see tech-stack-audit) |
| SMC-002 | Services | Unnecessary services exposed (databases, caches, admin ports, debug ports, SMB, RDP, SSH on odd ports, Docker/K8s APIs) | passive | network-portscan results; list service and why it should not be public |
| SMC-003 | Directories | Directory listing enabled (`Index of /`, IIS listing, Jetty, Tomcat `listings=true`) | bounded | misconfig_probe.py common directories; record one listing, do not crawl |
| SMC-004 | Headers | Server version disclosure (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `Via`, `X-Runtime`) | passive | misconfig_probe.py header review |
| SMC-005 | Errors | Stack trace disclosure in error pages (Java, .NET YSOD, Python traceback, Node, PHP, Ruby) | bounded | misconfig_probe.py error triggers (bad method, malformed JSON, `%`, array params, long input) |
| SMC-006 | Debug | Debug mode enabled in production (Django `DEBUG=True`, Flask/Werkzeug debugger, Laravel Ignition/Whoops, Rails dev errors, Symfony profiler `/_profiler`, Spring Boot Actuator, ASP.NET `customErrors Off`, Express dev, Next.js dev overlay, PHP `display_errors`) | bounded | misconfig_probe.py signatures and debug paths; never use the Werkzeug console or Ignition execution endpoints |
| SMC-007 | Methods | HTTP methods beyond GET/POST allowed (PUT, DELETE, PATCH, PROPFIND, MKCOL, COPY, MOVE, CONNECT) | bounded | `OPTIONS` Allow header and per-method status on a non-existent path; never PUT/DELETE real resources (class M) |
| SMC-008 | TRACE | TRACE enabled (Cross-Site Tracing; reflects headers incl. cookies) | bounded | One `TRACE /` with a marker header; check the marker is echoed |
| SMC-009 | OPTIONS | OPTIONS information disclosure (Allow, DAV, MS-Author-Via, CORS preflight details, server internals) | bounded | One OPTIONS on `/` and on an API path |
| SMC-010 | CORS | CORS misconfiguration at server level (global reflection, `null`, credentials) | bounded | See cors-audit (`cors_probe.py --quick`) |
| SMC-011 | Redirects | Open redirect in URL parameters (`next`, `url`, `redirect`, `returnTo`) | bounded | See open-redirect-and-header-injection |
| SMC-012 | Host header | Host header injection in virtual hosting (password reset poisoning, absolute links, routing to internal vhosts, cache keys) | bounded | misconfig_probe.py: `Host: <canary>` and duplicate/absolute-URI forms; check reflection in Location and body |
| SMC-013 | X-Forwarded-Host | X-Forwarded-Host (and X-Host, X-Forwarded-Server, Forwarded) injection reflected, enabling cache poisoning or reset poisoning | bounded | misconfig_probe.py under a cache buster; see cache-poisoning-audit CP-001 |
| SMC-014 | Proxy | Proxy misconfiguration allowing request smuggling, open proxying (`GET http://other/`), or internal routing (`X-Original-URL`, `X-Rewrite-URL`) | bounded | Absolute-URI request to an own OOB host (open proxy), override headers to `/nonexistent`; smuggling via request-smuggling-audit |
| SMC-015 | Error handling | Improper error handling revealing internal info (internal IPs, file paths, SQL fragments, hostnames, framework names, versions) | bounded | misconfig_probe.py leak patterns across error triggers |
| SMC-016 | Node.js | Server-side JavaScript injection (`eval`, `Function`, `vm`, `setTimeout(string)`, `$where`, template sinks) in Node apps | bounded | Arithmetic marker only (`7*7` → 49, `require` never); see server-side-injection and nosql-injection-audit |
| SMC-017 | Verbose errors | Verbose error messages on auth, API, and validation responses (user enumeration, schema hints, ORM errors) | bounded | misconfig_probe.py malformed JSON and type confusion on an API path |
| SMC-018 | CRLF | HTTP header injection via CRLF in request values reflected into headers | bounded | misconfig_probe.py `--crlf-url` with `FUZZ`: `%0d%0aX-Injected:%20<marker>` and variants |
| SMC-019 | CRLF | CRLF injection in response headers (Location, Set-Cookie, Content-Disposition, custom headers) | bounded | Same, check each reflected header |
| SMC-020 | Splitting | HTTP response splitting (injected blank line + body) | bounded | `%0d%0a%0d%0a<marker>` payload; confirm a second body/injected content only for your own request |

## Debug and error signatures (used by misconfig_probe.py)

| Stack | Signature |
|---|---|
| Django | `You're seeing this error because you have DEBUG = True`, `Traceback (most recent call last)`, `django.` |
| Flask / Werkzeug | `Werkzeug Debugger`, `__debugger__`, `The debugger caught an exception` |
| Laravel | `Whoops! There was an error`, `Ignition`, `laravel/framework`, `vendor/laravel` |
| Symfony | `Symfony\Component`, `/_profiler`, `sf-toolbar` |
| Rails | `Action Controller: Exception caught`, `ActiveRecord::`, `app/controllers` |
| Spring | `Whitelabel Error Page`, `org.springframework`, `java.lang.`, `at org.` |
| ASP.NET | `Server Error in '/' Application`, `Stack Trace:`, `System.Web`, `YSOD` |
| Node / Express | `at Object.<anonymous>`, `at Module._compile`, `node_modules/express`, `SyntaxError: Unexpected token` |
| PHP | `Fatal error:`, `Warning:` + `on line`, `Parse error:`, `Stack trace:` + `#0` |
| Go | `goroutine 1 [running]`, `panic:` |
| Generic | `ORA-`, `SQLSTATE[`, `MySQL server version`, `PG::`, internal IPs `10.`, `172.16-31.`, `192.168.`, paths `/var/www/`, `/home/`, `C:\inetpub\` |

## Debug paths (bounded GET/HEAD only)

`/_profiler`, `/_profiler/phpinfo`, `/__debug__/`, `/debug`, `/console` (Werkzeug), `/_ignition/health-check`, `/telescope`, `/horizon`, `/actuator`, `/actuator/env`, `/trace.axd`, `/elmah.axd`, `/phpinfo.php`, `/info.php`, `/server-status`, `/server-info`, `/.env`, `/debug/pprof/`, `/debug/vars`, `/rails/info/properties`, `/__webpack_hmr`.

Never call execution endpoints (Ignition `execute-solution`, Werkzeug console, Actuator `POST` endpoints, Telescope commands).

## Cross-references

| SMC row | Related rows |
|---|---|
| SMC-001 | checklist_102 credential rows (class C), tech-stack-audit |
| SMC-002 | network-portscan, cloud-container-audit |
| SMC-003 | file-download-audit FD-002, contentdiscovery |
| SMC-006 | tech-stack-audit framework rows (Actuator, Ignition, Werkzeug) |
| SMC-010 | cors-audit |
| SMC-011 | open-redirect-and-header-injection |
| SMC-012, SMC-013 | cache-poisoning-audit CP-001, authbypass reset poisoning |
| SMC-014 | request-smuggling-audit |
| SMC-016 | server-side-injection, nosql-injection-audit |
| SMC-018 to 020 | open-redirect-and-header-injection CRLF rows, cache-poisoning-audit CP-010 |
