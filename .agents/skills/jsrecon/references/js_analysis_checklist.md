# JavaScript Analysis Checklist (JSA, 50 checks)

All rows are offline analysis of JavaScript you downloaded from in-scope hosts (bundles, chunks, recovered source maps), so they are `passive`. Verifying a lead (calling an endpoint, testing a key, triggering a sink) follows the class of the skill named in the last column.

Tools: `scripts/js_analyzer.py` (beautify, source maps, 60+ secret patterns, routes) and `scripts/js_sink_audit.py` (sinks, browser APIs, storage, workers, CSP/Trusted Types gadgets, extra secrets). Run js_analyzer first, then js_sink_audit on the beautified/recovered output.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| JSA-001 | Endpoints | Hardcoded API endpoints (absolute URLs, `/api/...` paths, template-literal routes) | passive | js_analyzer.py routes; feed api-security / rest-api-audit |
| JSA-002 | Keys | Hardcoded API keys | passive | js_analyzer.py secret patterns; classify public vs secret (saas-third-party-exposure) |
| JSA-003 | Secrets | Hardcoded secrets and tokens (bearer, JWT, generic `secret`/`token` assignments) | passive | js_analyzer.py; never use found tokens |
| JSA-004 | Feature flags | Hidden feature flags (`featureFlags`, `isBeta`, `enableX`, LaunchDarkly/Optimizely/Split keys, flag maps) | passive | js_sink_audit.py `feature-flag`; test server-side enforcement (business-logic-vulns BLV-018) |
| JSA-005 | Admin routes | Admin panel routes (router configs, `/admin`, `/internal`, `/staff`, `/superuser`, role-gated components) | passive | js_sink_audit.py `admin-route`; verify server-side authz (access-control) |
| JSA-006 | Debug | Debug mode toggles (`debug: true`, `__DEV__`, `localStorage.debug`, `?debug=1` handlers, verbose loggers) | passive | js_analyzer.py `Debug / Dev Flag` + js_sink_audit.py `debug-toggle` |
| JSA-007 | Internal | Internal IP addresses and hostnames | passive | js_analyzer.py `Internal IP Address`, `Internal Hostname` |
| JSA-008 | Database | Database connection strings (`mongodb://user:pass@`, `postgres://`, `mysql://`, `Server=...;Password=`) | passive | js_sink_audit.py `conn-string` |
| JSA-009 | Crypto | Encryption keys (AES keys, IVs, HMAC secrets, `CryptoJS.AES.encrypt(x, "key")`, JWK private keys) | passive | js_sink_audit.py `crypto-key`; crypto-audit CRY-003 / CRY-V-011 |
| JSA-010 | OAuth | OAuth client secrets (`client_secret`, `clientSecret`) shipped to the browser | passive | js_sink_audit.py `oauth-client-secret`; oauth-sso |
| JSA-011 | AWS | AWS credentials (access key ID + secret, Cognito identity pool IDs, `aws_secret_access_key`) | passive | js_analyzer.py AWS patterns; cloud-container-audit CC-009 rules |
| JSA-012 | Firebase | Firebase configuration (`apiKey`, `databaseURL`, `projectId`, `storageBucket`) | passive | js_analyzer.py; test rules per cloud-supplychain CLD-FB-* |
| JSA-013 | Payments | Stripe / payment keys (`sk_live_` is critical; `pk_live_` is public; Braintree, Adyen, PayPal secrets) | passive | js_analyzer.py Stripe patterns + js_sink_audit.py `payment-secret` |
| JSA-014 | Maps | Google Maps API keys (check referrer/API restrictions and billing abuse) | passive | js_analyzer.py `Google API Key`; saas-third-party-exposure |
| JSA-015 | Email | SendGrid / Mailgun API keys | passive | js_analyzer.py SendGrid + js_sink_audit.py `mailgun-key` |
| JSA-016 | SMS | Twilio credentials (Account SID + auth token / API key) | passive | js_analyzer.py Twilio patterns |
| JSA-017 | Slack | Slack webhook URLs and tokens | passive | js_analyzer.py Slack patterns; never post to webhooks |
| JSA-018 | WebSocket | Hidden WebSocket endpoints (`new WebSocket(`, `io(`, SockJS, SignalR hubs, graphql-ws) | passive | js_sink_audit.py `websocket-endpoint`; client-side-js-security (ws_probe.py) |
| JSA-019 | Routes | Unused / debug API routes (`/v0/`, `/test/`, `/debug/`, `/internal/`, commented-out calls, dead feature routes) | passive | js_sink_audit.py `debug-route`; api-security AA-008 |
| JSA-020 | Source maps | Source map references (`sourceMappingURL`, `.map` files with `sourcesContent`) | passive | js_analyzer.py `--unpack-maps`; data-exposure-audit DE-002 |
| JSA-021 | Env config | Environment-specific config objects (`window.__ENV__`, `process.env.*` inlined, `__NEXT_DATA__`, `config.staging`, `REACT_APP_*`, `VITE_*`, `NEXT_PUBLIC_*`) | passive | js_sink_audit.py `env-config` |
| JSA-022 | JWT | JWT handling logic (decode-only checks, `alg` choice client-side, token in URL/storage, expiry checked only client-side) | passive | js_sink_audit.py `jwt-handling`; session-management JWT rows |
| JSA-023 | localStorage | `localStorage` with sensitive data (tokens, PII) | passive | js_sink_audit.py `storage-sensitive`; data-exposure-audit DE-014 |
| JSA-024 | sessionStorage | `sessionStorage` with sensitive data | passive | Same |
| JSA-025 | IndexedDB | IndexedDB with sensitive data (offline caches, message stores) | passive | js_sink_audit.py `indexeddb`; DE-015 |
| JSA-026 | postMessage | Insecure postMessage handlers (no/weak origin checks, dangerous sinks) | passive | client-side-js-security `pm_scan.py` (PMX rows) |
| JSA-027 | Sanitizers | DOMPurify / sanitizer bypass potential (old versions, `ALLOW_UNKNOWN_PROTOCOLS`, `ADD_TAGS`/`ADD_ATTR`, `SAFE_FOR_TEMPLATES` off, sanitize-then-modify, custom regex sanitizers) | passive | js_sink_audit.py `sanitizer`; xss mXSS/sanitizer rows; library versions in `js_library_versions.md` |
| JSA-028 | eval | `eval()` / `Function()` / string `setTimeout` with user input | passive | js_sink_audit.py `eval-sink` with source proximity; xss DOM rows |
| JSA-029 | innerHTML | `innerHTML` / `outerHTML` / `insertAdjacentHTML` with unsanitized input | passive | js_sink_audit.py `html-sink` |
| JSA-030 | document.write | `document.write()` / `writeln()` with user input | passive | js_sink_audit.py `document-write` |
| JSA-031 | React | `dangerouslySetInnerHTML` | passive | js_sink_audit.py `react-dangerous`; xss framework rows |
| JSA-032 | Vue | `v-html` (and `domProps: { innerHTML }` in render functions) | passive | js_sink_audit.py `vue-vhtml` |
| JSA-033 | AngularJS | AngularJS expression injection (`ng-app` + user data in templates, `$sce.trustAsHtml`, `$compile`, versions < 1.6 sandbox) | passive | js_sink_audit.py `angularjs`; xss AngularJS rows |
| JSA-034 | Prototype pollution | Prototype pollution vectors (`__proto__`/`constructor.prototype` handling, unsafe deep merge/extend/set by path, query-string parsers) | passive | js_sink_audit.py `proto-pollution`; client-side-js-security PROTO rows |
| JSA-035 | DOM clobbering | DOM clobbering possibilities (globals read via `window.x \|\| default`, `document.getElementById` results used as config, named form elements) | passive | js_sink_audit.py `dom-clobbering` |
| JSA-036 | Open redirect | Open redirect via `window.location` / `location.href` / `location.assign` / `window.open` fed by URL params, hash, or `document.referrer` | passive | js_sink_audit.py `location-redirect`; open-redirect-and-header-injection |
| JSA-037 | CORS in fetch | CORS-relevant fetch calls (`mode: 'cors'` to third parties carrying tokens, `mode: 'no-cors'` assumptions, dynamic base URLs) | passive | js_sink_audit.py `fetch-cors`; cors-audit |
| JSA-038 | Credentials | `credentials: 'include'` / `withCredentials = true` on cross-origin requests | passive | js_sink_audit.py `credentials-include` |
| JSA-039 | Service worker | Service worker registration and scope (`navigator.serviceWorker.register`, broad scope, script URL built from input, caching authenticated responses) | passive | js_sink_audit.py `service-worker`; client-side-js-security SW rows |
| JSA-040 | Web workers | Web worker message handling (`new Worker(` with dynamic URL, `onmessage` → `importScripts`/`eval`) | passive | js_sink_audit.py `web-worker` |
| JSA-041 | Notifications | Notification API abuse potential (`Notification.requestPermission`, push subscription keys, notification text from untrusted data) | passive | js_sink_audit.py `notification` |
| JSA-042 | Geolocation | Geolocation API data leakage (`getCurrentPosition`/`watchPosition` sent to third parties or stored) | passive | js_sink_audit.py `geolocation` |
| JSA-043 | Media | Camera / microphone permission abuse (`getUserMedia`, `getDisplayMedia`, permissions requested on load) | passive | js_sink_audit.py `media-capture`; Permissions-Policy header |
| JSA-044 | Clipboard | Clipboard API data exfiltration (`navigator.clipboard.readText`, `paste` listeners sending data, `execCommand('copy')` hijacking) | passive | js_sink_audit.py `clipboard` |
| JSA-045 | Spectre | `SharedArrayBuffer` / high-resolution timers (requires COOP/COEP cross-origin isolation) | passive | js_sink_audit.py `sharedarraybuffer`; check COOP/COEP headers |
| JSA-046 | WASM | WebAssembly module loading (`WebAssembly.instantiateStreaming`/`compile` from dynamic or third-party URLs, `wasm-unsafe-eval` in CSP) | passive | js_sink_audit.py `wasm` |
| JSA-047 | CSP bypass | CSP bypass vectors in loaded code (JSONP endpoints, script gadgets in allowed libraries, `unsafe-eval`-dependent code, AngularJS/Vue on allowed CDNs) | passive | js_sink_audit.py `csp-gadget`; xss CSP rows |
| JSA-048 | Nonce gadgets | Nonce-based CSP bypass via script gadgets (code that copies `nonce` to new scripts, `document.createElement('script')` with attacker-controlled `src`, `strict-dynamic` trust propagation) | passive | js_sink_audit.py `nonce-gadget` |
| JSA-049 | Trusted Types | Trusted Types bypass (`createPolicy` with pass-through `createHTML`/`createScriptURL`, `default` policy, policies applied to user input) | passive | js_sink_audit.py `trusted-types` |
| JSA-050 | Third-party | Third-party script inclusion risks (scripts from many origins, no SRI `integrity`, dynamic script injection, abandoned/expired domains, tag managers) | passive | js_sink_audit.py `third-party-script` on HTML/JS; saas-third-party-exposure; subdomain-takeover for dead script hosts |

## Cross-references

| JSA rows | Related |
|---|---|
| JSA-001, JSA-019 | api-security, rest-api-audit, linkparamdiscovery |
| JSA-002 to JSA-017 | saas-third-party-exposure, data-exposure-audit DE-003, crypto-audit |
| JSA-018, JSA-026, JSA-034, JSA-039, JSA-040 | client-side-js-security |
| JSA-027 to JSA-033, JSA-035, JSA-047 to JSA-049 | xss |
| JSA-036 | open-redirect-and-header-injection |
| JSA-037, JSA-038 | cors-audit |
| JSA-041 to JSA-046 | csrf-audit (Permissions-Policy / COOP / COEP header rows) |
