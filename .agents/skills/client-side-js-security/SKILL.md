---
name: client-side-js-security
description: Audit authorized web front ends for client-side JavaScript security issues: prototype pollution (client and Node.js server), postMessage origin and sink bugs, DOM XSS and DOM clobbering, web storage and IndexedDB token exposure, service worker scope and caching, WebSocket authentication and cross-site hijacking, and JSONP callbacks. Triggers on "prototype pollution", "__proto__", "postMessage", "message listener", "localStorage token", "sessionStorage", "IndexedDB", "service worker", "WebSocket", "CSWSH", "JSONP", "DOM Invader", or when jsrecon finds message handlers, storage writes, or socket endpoints.
---

# Client-Side JavaScript Security

Find where front-end code trusts input from URLs, messages, storage, or sockets. Probes use marker values on your own page and your own account. Never deliver a payload to another user's browser.

Checklist: `references/prototype_postmessage_storage_sw.md` (about 30 rows).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Use jsrecon output to list message listeners, `postMessage` calls, storage writes, service worker registrations, and socket URLs.
3. Prototype pollution: load a page with `?__proto__[probe]=1` and `?constructor[prototype][probe]=1` (PROTO-001) and check `Object.prototype.probe` in a console. For Node endpoints, send one JSON probe to your own test endpoint (PROTO-004).
4. postMessage: check each listener for `event.origin` validation (PM-001). For sinks, send a marker message from your own origin page (PM-002). Flag `'*'` target origins that carry sensitive data (PM-003).
5. Storage: list keys for your own session after login and after logout (STOR-001, STOR-002). Report tokens in storage as a severity factor for XSS, not as a standalone finding.
6. Service workers: list registrations and scopes (SW-001). Check for logout cache clearing (SW-003).
7. WebSocket: replay your own messages on a second socket if your account has two sessions (WS-001). Test Origin on the handshake (WS-002).
8. Save results to `artifacts/<target>/client_side.json`.

## Classes

- `passive`: reading source, storage, and registrations.
- `bounded`: marker probes on your own page or account.
- `authorized-only`: anything that affects other users.

## Rules

- Any finding that needs a victim to visit an attacker page must be shown with your own two accounts or a local test page.
- Never capture real session data from storage or sockets. Record key names only.

## Deep postMessage testing

- Use `postmessage-audit` (`../postmessage-audit/SKILL.md`) for the 10-check postMessage assessment, weak origin patterns, PoC templates, and `scripts/pm_scan.py`. PM-001 to PM-004 here map to PMX-001, PMX-006, PMX-004, and PMX-V-007.

## Deep WebSocket testing

- Use `websocket-audit` (`../websocket-audit/SKILL.md`) for the 15-check WebSocket assessment and `scripts/ws_probe.py`. WS-001 to WS-003 map to WSK-001/WSK-009, WSK-002/WSK-007, and WSK-012.
