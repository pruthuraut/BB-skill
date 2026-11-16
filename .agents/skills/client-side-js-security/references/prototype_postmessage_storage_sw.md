# Client-Side JavaScript: Prototype Pollution, postMessage, Web Storage, Service Workers, DOM

Class key: `passive` (read source/DevTools/storage listing), `bounded` (own-page probes with marker values, OOB host only).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| PROTO-001 | Client-side | Prototype pollution via URL parameters (`?__proto__[x]=y`, `?constructor[prototype][x]=y`) | bounded | Load with marker, check `Object.prototype.x` in console |
| PROTO-002 | Client-side | Gadget reached through polluted property (DOM sink or config) | bounded | Review gadget code; test marker only |
| PROTO-003 | Client-side | DOM Invader-style detection of merge functions | bounded | Use Burp DOM Invader on own page |
| PROTO-004 | Server-side Node.js | JSON `__proto__` key accepted by merge (lodash.merge/deepmerge) | bounded | Send `{"__proto__":{"pp_probe":"1"}}` to own endpoint; check reflected property on a later request |
| PROTO-005 | Server-side Node.js | Pollution leading to environment or NODE_OPTIONS influence | authorized-only | Approved lab only; never write env values in production |
| PROTO-006 | Lodash | Prototype pollution risk in old versions | passive | Version triage (jsrecon js_library_versions.md) |
| PM-001 | postMessage | Listener without origin check | passive | Grep `addEventListener('message'` and check for event.origin validation |
| PM-002 | postMessage | Message data flows into innerHTML, eval, or location | bounded | Own page iframe test sending marker payload from your origin |
| PM-003 | postMessage | Wildcard targetOrigin ('*') leaking sensitive data | passive | Grep `postMessage(` with '*' target |
| PM-004 | postMessage | Opener/iframe relations allow cross-origin reads | bounded | Own origin page opening target and reading message |
| DOM-001 | DOM XSS | Source (location.hash, document.URL, referrer) to sink (innerHTML, document.write, eval) | bounded | Marker in hash and reflection in DOM |
| DOM-002 | DOM clobbering | id or name attributes overwrite globals | bounded | Own HTML injection marker, check global value |
| STOR-001 | localStorage / sessionStorage | Tokens or PII stored in web storage | passive | List keys in DevTools on own session; grep bundle for storage writes |
| STOR-002 | IndexedDB | Sensitive records retained after logout | bounded | Own account: logout, then list IndexedDB keys |
| STOR-003 | Cookies vs storage | Auth token readable by any XSS (no HttpOnly equivalent) | passive | Classify token storage location for report severity |
| SW-001 | Service Worker | Scope too broad (root scope from attacker-controlled script path) | passive | Enumerate navigator.serviceWorker registrations and scope |
| SW-002 | Service Worker | Script URL injectable (persistent XSS) | bounded | Review registration code path for user-controlled script URL |
| SW-003 | Service Worker | Cached authenticated responses served after logout | bounded | Own account: cache inspection after logout |
| WS-001 | WebSocket | Authentication only on HTTP, not on socket messages (BOLA over WS) | bounded | Own two accounts: replay other account's message IDs over own socket |
| WS-002 | WebSocket | Cross-site WebSocket hijacking (no Origin validation) | bounded | Origin: foreign host on handshake |
| WS-003 | WebSocket | Message injection into XSS-sensitive rendering | bounded | Own-message marker |
| AJAX-001 | JSON responses | JSONP endpoint accepts arbitrary callback | bounded | `?callback=test` and check response type and content-type |
| AJAX-002 | Scripts | Dangling markup in attributes | bounded | Review HTML encoding; own marker only |
