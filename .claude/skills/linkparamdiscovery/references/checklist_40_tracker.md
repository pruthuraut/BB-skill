# Link & Parameter Discovery: 40-Item Master Audit Checklist

This checklist tracks execution progress across all 40 link, URL, parameter, and client-side endpoint discovery checks. It maps directly into the 5 specialized subagents and incorporates `wordlists/params.txt` and `API-FUZZ.txt`.

**Progress:** `[ 0 / 40 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Method / Command | Status |
|---|-------------------|----------|------------------|--------|
| **01** | Use katana for comprehensive web crawling & URL discovery | Subagent 01 | `katana -u <target> -d 3 -jc -kf -fx -o katana_urls.txt` | `[ ]` |
| **02** | Use hakrawler for fast web crawling with depth control | Subagent 01 | `echo <target> \| hakrawler -depth 3 -plain > hakrawler_urls.txt` | `[ ]` |
| **03** | Use Burp Suite spider / GoSpider for site mapping | Subagent 01 | `gospider -s <target> -d 3 -c 10 --other-source --include-subs` | `[ ]` |
| **04** | Extract all links from JavaScript files using LinkFinder | Subagent 02 | `python3 linkfinder.py -i <js_url> -o cli` | `[ ]` |
| **05** | Extract API endpoints from JS files using JSParser | Subagent 02 | `python3 -m jsparser -u <js_url>` / regex AST extraction | `[ ]` |
| **06** | Use paramspider for parameter discovery from historical data | Subagent 03 | `paramspider -d <target> --level high -o paramspider.txt` | `[ ]` |
| **07** | Find hidden parameters with arjun for HTTP parameter discovery | Subagent 03 | `arjun -u <target> -w wordlists/params.txt -m GET,POST,JSON` | `[ ]` |
| **08** | Check for path-based parameters in URL paths | Subagent 03 | Regex query for dynamic path segments (`/users/{id}/`, `/v1/items/:uuid`) | `[ ]` |
| **09** | Analyze JavaScript for API routes and hidden parameters | Subagent 02 | Regex scan JS bundles for `axios.`, `fetch(`, `$.ajax(`, route definitions | `[ ]` |
| **10** | Check for URL fragments and hash-based routing (`#/path`) | Subagent 01 | Parse client-side HashRouter and route manifests (`#/admin`, `#/dashboard`) | `[ ]` |
| **11** | Discover WebSocket endpoints and real-time connections | Subagent 04 | Probe `ws://`, `wss://`, `/socket.io/`, `/ws`, `/cable`, `/hub` | `[ ]` |
| **12** | Look for Server-Sent Events (SSE) streaming endpoints | Subagent 04 | Inspect responses with `Content-Type: text/event-stream`, `/stream`, `/sse` | `[ ]` |
| **13** | Find polling & long-polling connections for real-time | Subagent 04 | Inspect repeated AJAX requests (`/poll`, `/longpoll`, `/heartbeat`) | `[ ]` |
| **14** | Check for microservices architecture with multiple API gateways | Subagent 04 | Correlate `X-Forwarded-Host`, `Via`, and gateway route prefixes (`/api/v1/`, `/service-auth/`) | `[ ]` |
| **15** | Discover internal API documentation in JS source map files | Subagent 02 | Parse unpacked `.map` source trees for inline Swagger / JSDoc comments | `[ ]` |
| **16** | Extract variables and constants from minified JavaScript | Subagent 02 | AST parsing of `const [A-Z0-9_]+ = ...` in client bundles | `[ ]` |
| **17** | Check for sourcemap files (`.map`) for original code access | Subagent 02 | Probe `<script>.map`, unpack via `sourcemapper` | `[ ]` |
| **18** | Analyze Angular/React/Vue compiled templates for routes | Subagent 02 | Grep `path:`, `component:`, `Route`, `children:` in vendor chunks | `[ ]` |
| **19** | Check for REST API versioning (`/v1/`, `/v2/`, `/v3/`) | Subagent 05 | Fuzz paths replacing `/v1/` with `/v0/`, `/v2/`, `/v3/`, `/beta/` | `[ ]` |
| **20** | Look for GraphQL schema via introspection queries | Subagent 05 | POST `{"query":"{__schema{queryType{name}}}"}` to `/graphql` | `[ ]` |
| **21** | Discover SOAP WSDL endpoints (`?wsdl`, `?WSDL`, `?xsd`) | Subagent 05 | Fuzz endpoints with `?wsdl`, `?xsd` using `wad.txt` and `svc.txt` | `[ ]` |
| **22** | Check for XML-RPC endpoints (`/xmlrpc.php`) | Subagent 05 | POST `<methodCall><methodName>system.listMethods</methodName></methodCall>` | `[ ]` |
| **23** | Find form action URLs and hidden form field parameters | Subagent 03 | Parse `<form action="...">` and `<input type="hidden" name="..." value="...">` | `[ ]` |
| **24** | Analyze AJAX calls in browser devtools network traffic | Subagent 03 | Headless Chrome HAR capture of dynamic XHR/Fetch requests | `[ ]` |
| **25** | Check for iframe and embed source URLs for cross-origin content | Subagent 01 | Grep `<iframe src="...">` and `<embed src="...">` | `[ ]` |
| **26** | Discover image/asset CDN URLs for additional attack surface | Subagent 05 | Grep `src="https://..."` pointing to S3 buckets, CloudFront, Imgix | `[ ]` |
| **27** | Look for OAuth/OpenID configuration at `/.well-known/` | Subagent 05 | Probe `/.well-known/openid-configuration` & `oauth-authorization-server` | `[ ]` |
| **28** | Check for SAML metadata endpoints for federation config | Subagent 05 | Probe `/saml/metadata`, `/FederationMetadata/2007-06/FederationMetadata.xml` | `[ ]` |
| **29** | Find callback/redirect URLs in authentication flows | Subagent 05 | Inspect `redirect_uri=`, `callback=`, `return_to=`, `goto=` parameters | `[ ]` |
| **30** | Analyze `postMessage` handlers for cross-origin flaws | Subagent 04 | Grep `window.addEventListener("message", ...)` missing origin checks | `[ ]` |
| **31** | Check for URL parameters in Referer headers of outgoing links | Subagent 03 | Audit outbound external links for leaked tokens in query strings | `[ ]` |
| **32** | Look for email templates with parameterized URLs | Subagent 05 | Fuzz `/email/template/`, `/preview/email`, `/newsletter` with `token=` | `[ ]` |
| **33** | Check for webhooks with configurable callback URLs | Subagent 05 | Audit settings/API routes accepting `webhook_url=`, `callback_url=` | `[ ]` |
| **34** | Discover file upload endpoints and accepted parameters | Subagent 05 | Fuzz `/upload`, `/file-upload` for `multipart/form-data` parameters | `[ ]` |
| **35** | Check for export/download endpoints with configurable output | Subagent 05 | Audit `/export`, `/download` with `format=csv`, `type=pdf`, `filter=` | `[ ]` |
| **36** | Look for search endpoints with filter/sort parameters | Subagent 03 | Fuzz search queries: `q=`, `query=`, `keyword=`, `sort=`, `order=`, `by=` | `[ ]` |
| **37** | Check for pagination parameters (`page`, `offset`, `limit`) | Subagent 03 | Fuzz pagination: `page=`, `limit=`, `offset=`, `size=`, `cursor=` | `[ ]` |
| **38** | Discover batch/bulk operation endpoints | Subagent 05 | Fuzz `/batch`, `/bulk`, `/api/v1/users/batch` | `[ ]` |
| **39** | Check for admin/debug endpoints from JS route definitions | Subagent 02 | Grep JS router for `admin`, `debug`, `management`, `test`, `internal` | `[ ]` |
| **40** | Look for WebSocket message format from JS analysis | Subagent 04 | Parse `socket.send()`, `ws.emit()`, Stomp/SockJS protocol payloads | `[ ]` |
