# Web Frameworks, Languages, Runtimes

Class key: see cms-ecommerce.md. Version checks never run exploit code.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-FW-001 | Django | DEBUG=True error pages leak settings and source | passive | Request a missing path, look for debug 404 with settings |
| TS-FW-002 | Django | Admin exposed at /admin/ | passive | GET /admin/ and /admin/login/ status |
| TS-FW-003 | Django | Raw SQL via extra() or user input in filters | authorized-only | Requires approved SQLi test (see sqli skill) |
| TS-FW-004 | Ruby on Rails | Mass assignment of role/admin attributes | authorized-only | Test on own account with approved profile update |
| TS-FW-005 | Ruby on Rails | secret_key_base exposed (forged cookies) | passive | Grep for secret_key_base in JS, error pages, config leak |
| TS-FW-006 | Flask | Debug mode with Werkzeug console | passive | Trigger error page; look for /console path (do not use console) |
| TS-FW-007 | Flask | Weak SECRET_KEY allowing session forgery | authorized-only | Requires approved test with own session cookie |
| TS-FW-008 | Laravel | APP_DEBUG=true error pages expose environment | passive | Trigger 500 on own test route, look for env values |
| TS-FW-009 | Laravel | .env exposed | passive | GET /.env, /backend/.env, /api/.env status (do not print values) |
| TS-FW-010 | Symfony | Web profiler at /_profiler exposed | passive | GET /_profiler status |
| TS-FW-011 | Symfony | APP_SECRET leaked | passive | Grep .env and JS for APP_SECRET-like strings (redact in report) |
| TS-FW-012 | Express.js | Permissive CORS reflection | bounded | Origin: https://evil.example on API, check ACAO and credentials |
| TS-FW-013 | Express.js | Missing security headers | passive | Check HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| TS-FW-014 | Express.js | Rate limit absent on login | bounded | Send up to 10 requests to own test account endpoint, check 429 |
| TS-FW-015 | FastAPI | OpenAPI docs in production (/docs, /redoc, /openapi.json) | passive | GET /docs, /redoc, /openapi.json status |
| TS-FW-016 | FastAPI | CORS wildcard | bounded | Origin header probe as TS-FW-012 |
| TS-FW-017 | FastAPI | Debug tracebacks on errors | passive | Malformed request, look for traceback text |
| TS-FW-018 | ASP.NET | ViewState MachineKey known or guessable | authorized-only | Requires approved review of web.config (no decryption attempts) |
| TS-FW-019 | ASP.NET | elmah.axd and trace.axd exposed | passive | GET /elmah.axd, /trace.axd status |
| TS-FW-020 | ASP.NET | Version header disclosure | passive | X-AspNet-Version, X-Powered-By |
| TS-FW-021 | Node.js | Prototype pollution via merge of user JSON | bounded | Send `{"__proto__":{"x":"1"}}` to own test endpoint, check global side effect in response |
| TS-FW-022 | Node.js | Command injection via child_process | authorized-only | Requires approved test; review code path first |
| TS-FW-023 | Spring Boot | Actuator endpoints exposed (/actuator/env, /heapdump, /beans) | passive | GET /actuator and /actuator/health; list exposed IDs |
| TS-FW-024 | Spring Boot | Actuator env/restart abuse with Spring Cloud | authorized-only | Requires approved test; do not modify properties |
| TS-FW-025 | Spring4Shell CVE-2022-22965 | Spring 5.3.x <5.3.18, 5.2.x <5.2.20 on JDK9+ WAR | passive | Version check only |
| TS-FW-026 | Spring Cloud Function CVE-2022-22963 | 3.1.x <3.1.7, 3.2.x <3.2.3 | passive | Version check only |
| TS-FW-027 | Next.js | Source maps in production | passive | GET _next/static chunks and .map files |
| TS-FW-028 | Next.js | API routes and getServerSideProps data exposure | bounded | Enumerate /api/ routes and inspect JSON for secrets |
| TS-FW-029 | Nuxt.js | Server data in window.__NUXT__ | passive | Grep page for __NUXT__ payload; review for secrets |
| TS-FW-030 | Remix | Loader data exposing secrets | passive | Grep __remixContext payload |
| TS-FW-031 | SvelteKit | Server load data exposure (__data.json) | passive | GET __data.json on public routes |
| TS-FW-032 | Astro | Source maps and /_astro/ server data | passive | GET .js.map under /_astro/ |
| TS-FW-033 | Gatsby | GraphQL endpoint /___graphql in production | passive | GET /___graphql status |
| TS-FW-034 | Gridsome | GraphQL endpoint in production | passive | GET /___graphql status |
| TS-FW-035 | Hugo / Jekyll / Hexo | _config.yml or config exposed, _site listing | passive | GET config and _site paths |
| TS-FW-036 | Vue.js / React / Angular / Svelte / Solid | Development build in production | passive | Grep bundle for dev-mode markers |
| TS-FW-037 | AngularJS | Client-side template injection via {{ }} | bounded | Own test input `{{7*7}}` reflected as 49 |
| TS-FW-038 | Angular | DomSanitizer bypassSecurityTrust* with user input | authorized-only | Code review first; test only on own content |
| TS-FW-039 | Ember.js | Debug mode and EmberENV in production | passive | Grep bundle for EmberENV, development strings |
| TS-FW-040 | Backbone.js / Marionette.js | Template injection via _.template | bounded | Own input probe as TS-FW-037 |
| TS-FW-041 | Backbone.js | Mass assignment via model PUT | authorized-only | Test on own record only |
| TS-FW-042 | Meteor | DDP / sockjs endpoints exposing collections | bounded | Connect as anonymous, list subscriptions |
| TS-FW-043 | Phoenix | LiveView socket leaks state | bounded | Connect to /live websocket as anonymous |
| TS-FW-044 | Koa | Stack traces on unknown routes | passive | Request missing route, look for stack |
| TS-FW-045 | Go | pprof and expvar exposed (/debug/pprof/, /debug/vars) | passive | GET /debug/pprof/ and /debug/vars status |
| TS-FW-046 | Go | Hardcoded secrets in binary | authorized-only | Requires approved binary analysis of artifacts you own or are given |
| TS-FW-047 | Haskell (Yesod/WAI) | Development error pages | passive | Trigger error on own test route |
| TS-FW-048 | PHP | Version in X-Powered-By | passive | Response headers |
| TS-FW-049 | Python / WSGI | Server header (Python/, WSGIServer/) | passive | Response headers |
| TS-FW-050 | Perl CGI | Exposed .cgi/.pl scripts and cgi-bin listing | passive | GET /cgi-bin/ listing |
| TS-FW-051 | Ktor / Kotlin | Server header and cleartext endpoints in app | passive | Headers; strings in artifacts you own |
| TS-FW-052 | Dart / Flutter web | main.dart.js.map exposed | passive | GET main.dart.js.map |
| TS-FW-053 | Flutter mobile | Hardcoded keys in app bundle | authorized-only | Requires approved analysis of app you are authorized to test |
| TS-FW-054 | Lua | Source files (.lua) served | passive | GET known script paths; grep for .lua references |
| TS-FW-055 | Erlang | EPMD port 4369 exposed | passive | Port check (no commands) |
| TS-FW-056 | TypeScript | Source maps in production | passive | GET .js.map and sourceMappingURL |
| TS-FW-057 | Rust (WASM) | Cargo or WASM dependency version disclosure | passive | Grep wasm/js for crate versions |
| TS-FW-058 | Vaadin | Version disclosure with known deserialization history | passive | Grep vaadin version |
| TS-FW-059 | Apache Struts 2 | OGNL RCE CVE-2017-5638, CVE-2018-11776, CVE-2023-50164 | passive | Version check only |
| TS-FW-060 | Apache Wicket | Path traversal CVE-2022-22978 (<9.10.0, <8.14.0) | passive | Version check only |
| TS-FW-061 | Liferay | JSON deserialization CVE-2020-7961 | passive | Version check only |
| TS-FW-062 | Blazor | _framework DLLs served, decompilable secrets | passive | GET _framework/ listing; grep DLL strings for secret patterns in your scope |
| TS-FW-063 | Livewire | Component payload leaks model state | bounded | Inspect wire:snapshot JSON for private attributes |
| TS-FW-064 | Inertia.js | Server props overexposure | bounded | Request with X-Inertia header, inspect props JSON |
| TS-FW-065 | HTMX | hx-vals XSS and CSRF on AJAX endpoints | bounded | Own-input reflection probe; check CSRF token requirement |
| TS-FW-066 | Handlebars | SSTI and triple-stash XSS | bounded | Own-input probe with `{{7*7}}` and `{{{x}}}` markup |
| TS-FW-067 | Mustache | Server-side template injection | bounded | Own-input probe |
| TS-FW-068 | Socket.io | Endpoint exposed, cross-origin emit | bounded | GET /socket.io/?EIO=4&transport=polling and Origin probe |
| TS-FW-069 | SignalR | negotiate endpoint leaks capabilities | passive | GET /signalr/negotiate status |
| TS-FW-070 | NextAuth.js | /api/auth/session and providers exposed | passive | GET /api/auth/providers (session only if you own it) |
| TS-FW-071 | Passport.js | SSO callback URLs and provider config in client | passive | Grep for auth/callback and provider IDs |
| TS-FW-072 | Redux | DevTools enabled in production | passive | Grep for __REDUX_DEVTOOLS_EXTENSION__ hooks |
| TS-FW-073 | Pinia / Vuex | Store hydration state exposed | passive | Grep __pinia or __INITIAL_STATE__ |
| TS-FW-074 | Lodash / Moment / jQuery / Bootstrap | Outdated versions with known XSS or prototype pollution | passive | Library version triage (see jsrecon js_library_versions.md) |
| TS-FW-075 | Yii / Zend / CakePHP / CodeIgniter / ThinkPHP | Version disclosure, debug mode, historic RCE | passive | Version check; ThinkPHP CVEs are version-gated |
| TS-FW-076 | ThinkPHP | Version exposure with known RCE history | passive | Version check only |
| TS-FW-077 | Sinatra | Session secret weak or default | authorized-only | Requires approved review of config you control |
| TS-FW-078 | Shiro (Apache) | RememberMe deserialization CVE-2016-4437; auth bypass CVE-2020-17523 | passive | Look for rememberMe cookie set in response; version check |
| TS-FW-079 | Vite / Webpack / Rspack / Parcel / UnoCSS / Rspress | Source maps and config in build output | passive | GET .map files and build manifest |
| TS-FW-080 | Hasura / Sanity / Directus | Anonymous schema/metadata access | bounded | Introspection query and metadata GET with no auth |
