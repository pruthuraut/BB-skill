---
name: websocket-audit
description: Audit authorized WebSocket endpoints across 15 checks — unauthenticated connections to sensitive data, cross-site WebSocket hijacking (CSWSH), client-side message tampering, replay of captured messages, flooding DoS (approval only), plaintext sensitive data, Origin validation bypass, encryption requirement (ws:// vs wss://), IDOR in channel/room identifiers, rate limiting, SQL injection, XSS via rendered message content, command injection in handlers, connection hijacking via session tokens (tokens in URLs, sockets surviving logout), and protocol downgrade — with a dependency-free scope-gated RFC 6455 probe (handshake matrix with/without cookies and with hostile Origins, ws/wss downgrade, message send/replay, field fuzzing with markers, IDOR comparison between two own accounts, bounded rate test, and sensitive-data scanning of frames), CSWSH PoC template, and Socket.IO/STOMP/GraphQL-WS notes. Triggers on "WebSocket", "ws://", "wss://", "CSWSH", "cross-site WebSocket hijacking", "Socket.IO", "SignalR", "STOMP", "graphql-ws", "Sec-WebSocket", "real-time", "chat socket", or when recon finds Upgrade: websocket endpoints.
---

# WebSocket Security Audit (15 checks)

A WebSocket starts as an HTTP request (`Upgrade: websocket`) and then becomes a long-lived message channel. The handshake carries cookies automatically, so missing Origin checks allow cross-site hijacking; after the handshake, many apps stop checking authorization per message, so every message is a request to test like an API call.

- Checklist: `references/websocket_checklist.md` (WSK-001 to WSK-015, frameworks and sub-protocols, impact notes).
- PoC templates: `references/websocket_poc_templates.md` (CSWSH page, message tampering in Burp, Socket.IO and STOMP framing).
- Tracker: `references/websocket_tracker.md`.
- `scripts/ws_probe.py`: dependency-free RFC 6455 client. Handshake matrix (with/without cookie, legit/evil/null/suffix/prefix Origins, Sec-WebSocket-Version variants, ws:// on the same host), send and replay your own messages, fuzz a JSON field with markers (XSS, SQL, command, NoSQL, template), IDOR comparison with your second account's IDs, bounded burst for rate limiting, and secret/PII scanning of received frames.
- Related: `client-side-js-security` (WS-001 to WS-003), `csrf-audit` (XSRF-011), `cors-audit` (CORS-015), `idor`, `sqli`, `xss`, `command-injection-audit`, `resource-exhaustion`, `session-management`, `graphql-audit` (subscriptions over WebSocket).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Find sockets: Burp Proxy → WebSockets history, DevTools Network → WS, JS (`new WebSocket(`, `io(`, `SockJS`, `signalR`, `graphql-ws`, `subscriptions-transport-ws`). Note the URL, sub-protocol (`Sec-WebSocket-Protocol`), auth method (cookie, token in URL, token in first message), and message formats.
3. Capture a few of your own messages (subscribe, send chat, fetch profile) into a file, one per line.
4. Run the probe:

   ```bash
   python3 .agents/skills/websocket-audit/scripts/ws_probe.py --target example.com \
     --url wss://ws.example.com/socket --cookie 'session=OWN_A' --origin https://www.example.com \
     --messages msgs.txt --fuzz-field text --idor-message '{"action":"join","room":"ROOM_OF_ACCOUNT_B"}' \
     --out artifacts/example.com/websocket.json
   ```

5. CSWSH (WSK-002/007): if any hostile Origin gets `101` with your cookie and the socket returns your data or accepts actions, build the PoC from the templates and confirm with your own victim profile.
6. Authorization per message (WSK-003/009): edit message fields (user IDs, room IDs, roles, amounts) in Burp Repeater (WebSocket) using your two accounts.
7. Injection (WSK-011/012/013): follow up any marker reflection or error with the sqli, xss, and command-injection-audit skills.
8. Rate limiting (WSK-010) uses `--burst` (default 0, at most 50 without approval). Flooding for DoS (WSK-005) is authorized-only.
9. Session (WSK-014): token in the WebSocket URL (logged, leaks via Referer); open socket survives logout or password change; token not bound to the user.
10. Save findings to `artifacts/<target>/websocket.json` and the tracker to `artifacts/<target>/websocket_tracker.md`.

## Classes

- `passive`: reading JS, captured handshakes and frames.
- `bounded`: handshake matrix, a few own messages, field fuzzing with markers, IDOR with own two accounts, bursts up to 50 messages.
- `authorized-only`: flooding or connection exhaustion (WSK-005), payloads beyond markers, actions on other users' channels or data, and PoCs shown to real users.

## Rules

- Use your own accounts and your own channels/rooms. For IDOR, use your second account's room or object IDs.
- Never post content into channels other users read (public chat, shared rooms) except with harmless markers in your own test channel.
- Close sockets after testing; do not keep long-lived connections open.

## Mitigation guidance for reports

- Validate `Origin` against an exact allowlist on the handshake; require a CSRF-style token or ticket for socket auth instead of ambient cookies.
- Authenticate the handshake and authorize every message server-side (ownership of rooms/objects, roles).
- `wss://` only; reject `ws://`. Do not put tokens in URLs; use short-lived tickets sent in the first message.
- Validate and encode message data (parameterized queries, output encoding, no shell calls).
- Per-connection and per-user rate limits, maximum frame/message size, connection limits, idle timeouts.
- Close sockets on logout, password change, and session expiry; replay protection (nonces/sequence numbers) for state-changing messages.

## Sources

RFC 6455, OWASP WebSocket Security Cheat Sheet and WSTG-CLNT-10, PortSwigger Web Security Academy WebSockets labs and CSWSH research, CWE-1385 (missing Origin validation in WebSockets), Burp Suite WebSockets documentation.
