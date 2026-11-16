# WebSocket Security Checklist

Class key: `passive` = JS and captured traffic. `bounded` = handshake matrix, few own messages, marker fuzzing, own-account IDOR, bursts ≤ 50. `authorized-only` = flooding, real users' channels, payloads beyond markers.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| WSK-001 | Auth | Unauthenticated connections reach sensitive data or actions (no cookie/token → 101 and data flows) | bounded | ws_probe.py `no-cookie` handshake + replay of own read messages; compare with authenticated responses |
| WSK-002 | CSWSH | Cross-site WebSocket hijacking: cookie-authenticated handshake accepted from a foreign Origin | bounded | ws_probe.py `origin-evil` 101 with cookie; PoC template 1 in own victim profile |
| WSK-003 | Client tampering | Client-side message injection/tampering: server trusts fields the client sets (userId, role, price, recipient, isAdmin) | bounded | Edit own messages in Burp Repeater (WebSocket); ws_probe.py `--messages` with modified fields |
| WSK-004 | Replay | Captured messages can be replayed (no nonce/sequence; state-changing actions repeat) | bounded | ws_probe.py replays each own message twice on a new connection; check duplicates server-side |
| WSK-005 | DoS | Message flooding or oversized frames degrade service (no size or rate limits) | authorized-only | Approved window only; never on production without consent |
| WSK-006 | Plaintext data | Sensitive data in messages (tokens, PII, other users' data, internal IDs) in clear or more than needed | passive | ws_probe.py frame scan for secrets/PII; review captured frames |
| WSK-007 | Origin bypass | Origin validation bypass: `null`, suffix (`eviltarget.com`), prefix (`target.com.evil`), missing Origin, case, port | bounded | ws_probe.py Origin matrix (see cors-audit bypass origins) |
| WSK-008 | Encryption | `ws://` accepted (no TLS), or app uses `ws://` from HTTPS pages | bounded | ws_probe.py `ws-downgrade` (same host, port 80/ws) |
| WSK-009 | IDOR | IDOR in channel/room/topic/object identifiers (join or read other users' rooms) | bounded | ws_probe.py `--idor-message` with account B's room ID while connected as A |
| WSK-010 | Rate limiting | No per-connection/user throttling of messages (brute force via socket, spam) | bounded | ws_probe.py `--burst 30` (≤ 50 without approval); count accepted |
| WSK-011 | SQLi | SQL injection in message parameters | bounded | ws_probe.py `--fuzz-field` quote/boolean markers; follow up with sqli rules |
| WSK-012 | XSS | XSS via message content rendered in other clients (chat, notifications, dashboards) | bounded | Marker payload in own test channel; view in own second browser; xss skill |
| WSK-013 | Command injection | Command injection in message handlers (ping/host/file utilities exposed over socket) | bounded | Arithmetic/sleep-free markers per command-injection-audit; never destructive |
| WSK-014 | Session | Connection hijacking via session tokens: token in URL query, token reusable across users/devices, socket survives logout/password change, no re-auth on resume | bounded | Inspect handshake URL; logout on another tab and keep sending on the open socket |
| WSK-015 | Downgrade | Protocol downgrade: wss→ws, older `Sec-WebSocket-Version`, fallback transports (Socket.IO/SockJS long-polling) bypassing socket-level controls | bounded | ws_probe.py version variants and ws://; test fallback HTTP transport endpoints with same auth checks |

## Frameworks and sub-protocols

| Stack | Notes |
|---|---|
| Socket.IO | Engine.IO handshake `GET /socket.io/?EIO=4&transport=polling` then upgrade; messages `42["event",{...}]`; polling fallback often lacks Origin checks (`cors` option) |
| SignalR | `/hub/negotiate` then `wss://.../hub?id=...`; messages end with `\x1e`; check `negotiate` auth and CORS |
| STOMP (Spring) | `CONNECT`, `SUBSCRIBE destination:/topic/x`, `SEND`; test subscribing to other users' `/user/{id}/queue` |
| GraphQL WS | `graphql-ws` (`connection_init`, `subscribe`) or legacy `subscriptions-transport-ws` (`connection_init`, `start`); auth in `connection_init` payload; see graphql-audit GQL-012 |
| ActionCable (Rails) | `{"command":"subscribe","identifier":"{\"channel\":\"X\"}"}`; check `identifier` params for IDOR |
| Phoenix Channels | `["1","1","room:123","phx_join",{}]`; topic IDOR |
| SockJS | `/info`, `/xhr`, `/websocket`; fallback transports |

## Impact notes

| Finding | Typical rating |
|---|---|
| CSWSH returning private data or performing actions | High |
| Unauthenticated socket returning other users' data | High |
| IDOR on rooms/objects | Medium–High |
| Stored XSS via chat delivered to other users | High |
| SQLi / command injection via socket | Critical |
| `ws://` accepted but app uses `wss://` | Low |
| Token in socket URL | Low–Medium (logs, Referer) |
| Missing rate limit with brute-force impact (OTP, login via socket) | Medium |

## Cross-references

| WSK row | Related rows |
|---|---|
| WSK-002, WSK-007 | client-side-js-security WS-002, csrf-audit XSRF-011, cors-audit CORS-015 |
| WSK-001, WSK-009 | client-side-js-security WS-001, idor |
| WSK-012 | client-side-js-security WS-003, xss |
| WSK-011 | sqli |
| WSK-013 | command-injection-audit |
| WSK-005, WSK-010 | resource-exhaustion |
| WSK-014 | session-management |
| WSK-015 | tls-audit |
