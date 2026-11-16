# postMessage Checklist

Class key: `passive` = JS reading and scanner. `bounded` = PoC on your own origin in your own browser against your own session. `authorized-only` = real users, other people's extensions, or chains needing another vulnerability.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| PMX-001 | Listener | Insecure handler with no origin check (`addEventListener("message", e => ...)` uses `e.data` directly) | bounded | pm_scan.py flags `no-origin-check`; send a marker from a PoC frame or popup and observe the effect |
| PMX-002 | Listener | Origin validated weakly: `indexOf`/`includes`/`search`/`match` substring, `startsWith`, `endsWith` without dot, unanchored or unescaped regex, `"null"` allowed, comparison after `toLowerCase` on attacker string, check only in one branch | bounded | Send from an origin that satisfies the weak check (for example `https://target.com.attacker.example`, `https://attackertarget.com`) |
| PMX-003 | Sender | Sensitive data posted to `window.parent` or `window.opener` (tokens, auth codes, PII, session IDs) | bounded | Frame or open the page from your origin, catch messages (template 3), check for your own token |
| PMX-004 | Sender | Wildcard targetOrigin `postMessage(data, "*")` or dynamic targetOrigin from URL (`?origin=`, `document.referrer`) | bounded | pm_scan.py flags `wildcard-target` and `dynamic-target`; catch with template 3 after navigating the frame |
| PMX-005 | Listener | Data injection from an external source: message changes state (settings, cart, redirect URL, feature config, auth state) | bounded | Send a crafted message, confirm state change on your own account |
| PMX-006 | Listener | XSS via message content: `e.data` reaches `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, `setTimeout(string)`, `location`/`href`/`src`, jQuery `html()`/`append()`/`$()` | bounded | Marker payload (for example `<img src=x onerror=alert(document.domain)>`) from template 1 or 2 |
| PMX-007 | Listener | `event.source` not validated (any window can post even if origin is checked via a shared or user-content origin) | bounded | Review handler; send from a different window on an allowed origin you control (own sandbox page) |
| PMX-008 | Subdomains | Cross-subdomain trust: any `*.target.com` accepted, so XSS or takeover on one subdomain reaches the listener | authorized-only | Report the trust; exploit only with an approved chain |
| PMX-009 | Iframes | Iframe communication channel: OAuth/SSO popups, payment, chat, analytics, embedded SDK bridges, help widgets, `/proxy.html` relays | bounded | Map parent and child messages for each embedded widget; test both directions |
| PMX-010 | Extension | Browser extension messaging: content script relays `window.postMessage` from the page to background or native messaging without origin checks; `externally_connectable` too broad | bounded | Own extension install, own test page sending the relay message |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| PMX-V-001 | Origin | `"null"` origin accepted (sandboxed iframe, `data:` URL sender) | bounded | Template 4 |
| PMX-V-002 | Origin | Origin check present but message processed before the check returns (async, or check result unused) | passive | Code review |
| PMX-V-003 | Data | `JSON.parse(e.data)` then deep merge, leading to prototype pollution | bounded | Send `{"__proto__":{"pmx":1}}`; check `Object.prototype.pmx` (see client-side-js-security PROTO rows) |
| PMX-V-004 | Data | Message type switch (`e.data.type`) exposes privileged actions (logout, navigate, setToken, resize to clickjack) | bounded | Enumerate types from JS; send each with harmless arguments |
| PMX-V-005 | Navigation | Message sets `location` or a redirect URL; `javascript:` URL gives XSS, external URL gives open redirect | bounded | Send `javascript:alert(document.domain)` and an external URL |
| PMX-V-006 | Timing | Race on load: sender posts before the legitimate frame loads, or attacker navigates the frame to their origin and catches the reply | bounded | Navigate `frames[0].location` to own page, catch messages |
| PMX-V-007 | Window refs | `window.open` returns a handle; target page posts back to `opener` with `*` (OAuth popup leaks code) | bounded | Template 3 with `window.open` |
| PMX-V-008 | Channels | `MessageChannel` port handed to an unverified frame | passive | Review port transfer code |
| PMX-V-009 | Channels | `BroadcastChannel` or `localStorage` events used for auth sync between tabs (same origin only, but abusable with same-origin XSS) | passive | Review usage |
| PMX-V-010 | Libraries | Known-vulnerable widgets and SDK bridges (older chat, analytics, payment, and A/B-testing snippets with open listeners) | passive | Version and vendor list (see saas-third-party-exposure) |
| PMX-V-011 | Framing | Listener page can be framed or opened by any origin (needed for delivery) | passive | XFO/frame-ancestors (clickjacking-audit) and COOP; COOP `same-origin` severs `opener` |
| PMX-V-012 | Mobile | WebView `postMessage` bridges (`window.ReactNativeWebView.postMessage`, `webkit.messageHandlers`) trust page content | bounded | Own app build or device |

## Weak origin-check patterns (what pm_scan.py looks for)

| Pattern | Bypass origin |
|---|---|
| `e.origin.indexOf("target.com") > -1` / `includes("target.com")` | `https://target.com.attacker.example`, `https://attacker.example/?target.com` is not an origin, so use a hostname containing it |
| `e.origin.startsWith("https://target.com")` | `https://target.com.attacker.example` |
| `e.origin.endsWith("target.com")` | `https://attackertarget.com` |
| `/https:\/\/.*target.com/.test(e.origin)` | `https://attacker.example.targetXcom.attacker.example` style (unescaped dot, unanchored) |
| `e.origin.match("https://www.target.com")` | String is turned into a regex; dots match any char: `https://wwwXtarget.com` |
| `if (e.origin !== x) console.log(...)` without `return` | Any origin |
| `e.origin == "null"` or allowlist containing `"null"` | Sandboxed iframe |
| Checking `e.data.origin` (attacker-supplied) instead of `e.origin` | Any origin |

## Sinks to trace from `event.data`

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`, `eval`, `Function`, `setTimeout`/`setInterval` with string, `location`, `location.href`, `location.assign/replace`, `window.open`, `src`/`href`/`action` attributes, `srcdoc`, jQuery `html`/`append`/`prepend`/`after`/`before`/`$()`, `$.globalEval`, `Range.createContextualFragment`, framework escape hatches (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`), `localStorage.setItem` (stored), `fetch`/XHR URLs (SSRF-like client requests with credentials).

## Cross-references

| PMX row | Related rows |
|---|---|
| PMX-001, 002 | client-side-js-security PM-001 |
| PMX-006 | PM-002, xss DOM rows |
| PMX-003, 004 | PM-003 |
| PMX-V-006, 007 | PM-004, oauth-sso |
| PMX-V-003 | PROTO-001, PROTO-002 |
