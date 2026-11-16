# Technology Fingerprinting: 40-Item Master Audit Checklist

This checklist tracks execution progress across all 40 technology fingerprinting checks. It maps directly into the 5 specialized subagents to guarantee thorough tech stack identification, framework-specific vulnerability prioritization, and zero missed components.

**Progress:** `[ 0 / 40 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Command / Method | Status |
|---|-------------------|----------|------------------|--------|
| **01** | Use Wappalyzer browser extension for tech stack detection | Subagent 01 | Wappalyzer CLI / Browser headless DOM analysis | `[ ]` |
| **02** | Use whatweb for CLI technology fingerprinting at scale | Subagent 01 | `whatweb -a 3 --color=never -v <target>` | `[ ]` |
| **03** | Use webanalyze (Go-based Wappalyzer) for fast batch profiling | Subagent 01 | `webanalyze -host <target> -crawl 2 -silent` | `[ ]` |
| **04** | Check HTTP response headers for server version disclosure | Subagent 01 | `httpx -u <target> -title -server -tech-detect -status-code` | `[ ]` |
| **05** | Check X-Powered-By header for backend identification | Subagent 01 | `curl -s -I <target> \| grep -i "X-Powered-By"` | `[ ]` |
| **06** | Analyze cookies for framework indicators | Subagent 01 | Extract cookies: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid` | `[ ]` |
| **07** | Check for framework-specific meta & generator tags in HTML | Subagent 01 | `curl -sL <target> \| grep -iE "<meta name=\"(generator\|application-name)\""` | `[ ]` |
| **08** | Identify CMS using WPScan, Joomscan, Droopescan | Subagent 05 | `wpscan --url <target> --stealth`, `joomscan -u <target>`, `droopescan scan drupal` | `[ ]` |
| **09** | Detect JS frameworks via source code analysis (React, Angular, Vue) | Subagent 03 | Crawl HTML/JS bundles for framework instantiation signatures | `[ ]` |
| **10** | Check for React indicators (`__NEXT_DATA__`, `_reactRootContainer`) | Subagent 03 | Regex query for `_reactRootContainer`, `__REACT_DEVTOOLS_GLOBAL_HOOK__` | `[ ]` |
| **11** | Check for Angular indicators (`ng-version`, `ng-app`, `_nghost`) | Subagent 03 | Regex search for `ng-version=".*"`, `ng-app`, `_ngcontent-`, `_nghost-` | `[ ]` |
| **12** | Check for Vue.js indicators (`__vue__`, `data-v-` attributes) | Subagent 03 | Regex search for `data-v-[a-f0-9]+`, `__VUE__`, `Vue.config` | `[ ]` |
| **13** | Identify backend language from error messages & file extensions | Subagent 04 | Trigger 404/500/syntax errors (`/nonexistent_test'"`), parse stack traces | `[ ]` |
| **14** | Check for Cloudflare CDN via `cf-ray` headers and DNS resolution | Subagent 02 | `curl -sI <target> \| grep -iE "(cf-ray\|cf-cache-status\|__cf_bm)"` | `[ ]` |
| **15** | Identify hosting provider from IP WHOIS data and ASN lookup | Subagent 02 | `whois $(dig +short <target> \| head -n 1) \| grep -iE "(OrgName\|netname\|descr)"` | `[ ]` |
| **16** | Use BuiltWith API for detailed technology profiling & history | Subagent 01 | `curl -s "https://api.builtwith.com/v20/api.json?KEY=$BUILTWITH_KEY&LOOKUP=<target>"` | `[ ]` |
| **17** | Check for WAF using wafw00f or Wappalyzer WAF detection | Subagent 02 | `wafw00f https://<target> -a -o artifacts/waf.txt` | `[ ]` |
| **18** | Identify CDN provider via CNAME records (Cloudfront, Akamai, Fastly) | Subagent 02 | `dig +short CNAME <target> \| grep -Ei "(cloudfront\|fastly\|edgekey\|azureedge)"` | `[ ]` |
| **19** | Check for specific CMS version via `readme.html`, `changelog` files | Subagent 05 | Probe `/readme.html`, `/license.txt`, `/CHANGELOG.md`, `/wp-includes/version.php` | `[ ]` |
| **20** | Use fingerprintx for service fingerprinting on open ports | Subagent 02 | `fingerprintx -t <target>:80,443,8080,8443 --json` | `[ ]` |
| **21** | Detect API gateway from response headers | Subagent 05 | Inspect `X-Request-ID`, `X-Amzn-Trace-Id`, `X-Kong-Proxy-Latency`, `x-envoy-*` | `[ ]` |
| **22** | Identify GraphQL endpoint via introspection query | Subagent 05 | POST `{"query":"{__schema{types{name}}}"}` to `/graphql`, `/api/graphql` | `[ ]` |
| **23** | Check for Swagger/OpenAPI documentation at `/swagger-ui/`, `/api-docs/` | Subagent 05 | Probe `/swagger-ui.html`, `/swagger/v1/swagger.json`, `/v2/api-docs`, `/openapi.json` | `[ ]` |
| **24** | Detect GraphQL Playground or GraphiQL interface at `/graphql` | Subagent 05 | GET `/graphql`, `/graphiql`, `/playground` with `Accept: text/html` | `[ ]` |
| **25** | Check for WordPress REST API at `/wp-json/wp/v2/` | Subagent 05 | GET `/wp-json/`, `/wp-json/wp/v2/users`, `/wp-json/wp/v2/posts` | `[ ]` |
| **26** | Identify Laravel via `/telescope`, `/_debugbar`, `/horizon` endpoints | Subagent 04 | GET `/_debugbar/open-handler`, `/telescope`, `/horizon`, `/nova` | `[ ]` |
| **27** | Check for Django admin at `/admin/` or `/django-admin/` login panel | Subagent 04 | Probe `/admin/login/`, `/django-admin/`, look for `csrfmiddlewaretoken` | `[ ]` |
| **28** | Detect Rails via cookie naming (`_session_id`) and headers | Subagent 04 | Inspect `_session_id`, `_app_session`, `X-CSRF-Token`, `/rails/info/routes` | `[ ]` |
| **29** | Check for Spring Boot actuator endpoints (`/actuator/health`, `/env`) | Subagent 04 | Probe `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/heapdump` | `[ ]` |
| **30** | Identify ASP.NET via viewstate and event validation hidden fields | Subagent 04 | Look for `__VIEWSTATE`, `__EVENTVALIDATION`, `ASP.NET_SessionId` | `[ ]` |
| **31** | Check for PHP via `X-Powered-By: PHP` and `.php` extensions | Subagent 04 | Verify `X-Powered-By: PHP/x.x`, `PHPSESSID`, exposed `.php` routes | `[ ]` |
| **32** | Detect Node.js via `X-Powered-By: Express` header | Subagent 04 | Inspect `X-Powered-By: Express`, `connect.sid`, error `TypeError: Cannot read...` | `[ ]` |
| **33** | Check for Next.js via `__NEXT_DATA__` script tag and build ID | Subagent 03 | Grep `<script id="__NEXT_DATA__"` and extract `buildId`, `page`, `props` | `[ ]` |
| **34** | Check for Nuxt.js via `__NUXT__` script tag and data attributes | Subagent 03 | Grep `window.__NUXT__` or `data-n-head` attributes in HTML | `[ ]` |
| **35** | Identify Gatsby via `gatsby-script` and `___graphql` endpoint | Subagent 03 | Grep `id="___gatsby"`, `gatsby-script`, probe `___graphql` | `[ ]` |
| **36** | Check for Svelte via `class:svelte-xxx` data attributes | Subagent 03 | Grep CSS/DOM for classes matching `svelte-[a-z0-9]{5,8}` | `[ ]` |
| **37** | Detect Ember.js via `meta name=ember-cli` and script tags | Subagent 03 | Grep `<meta name=".*ember-cli"` or `data-ember-action` | `[ ]` |
| **38** | Check for Meteor via `__meteor_runtime_config__` script | Subagent 03 | Grep `__meteor_runtime_config__ = JSON.parse(...)` in page source | `[ ]` |
| **39** | Identify Flask via specific cookie naming and Werkzeug headers | Subagent 04 | Look for `session=.eJ...`, `Server: Werkzeug/x.x`, `/console` pin interface | `[ ]` |
| **40** | Detect FastAPI via `/docs` (Swagger UI) and `/redoc` endpoints | Subagent 04 | GET `/docs`, `/redoc`, `/openapi.json` returning FastAPI OpenAPI schema | `[ ]` |
