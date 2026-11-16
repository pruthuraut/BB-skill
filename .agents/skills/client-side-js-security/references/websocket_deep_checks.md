# WebSocket Deep Testing Checklist

Class key: `passive` = handshake and code review. `bounded` = a few frames on your own accounts. `authorized-only` = floods, resource exhaustion, and data exfiltration tests (approval only). Frame-level tests use `scripts/ws_probe.py` in this skill (from websocket-audit).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| WSX-001 | Handshake | Handshake accepted without authentication | bounded | `ws_probe.py` handshake with and without cookies |
| WSX-002 | Handshake | Cross-site WebSocket hijacking (no Origin check) | bounded | Hostile Origin on handshake |
| WSX-003 | Messages | JSON message format accepts unexpected fields or types | bounded | Own message with extra field and marker |
| WSX-004 | Messages | Message boundary issues (concatenated or split frames) | bounded | Own split frames; compare parsing |
| WSX-005 | Compression | permessage-deflate enabled (CRIME-style leakage risk) | passive | Check Sec-WebSocket-Extensions in handshake |
| WSX-006 | Extensions | Unsafe extension negotiation accepted | passive | Review negotiated extensions |
| WSX-007 | Limits | Connection limit not enforced per user | authorized-only | Approval; few connections only |
| WSX-008 | Keepalive | Ping or pong used to keep sessions alive past expiry | bounded | Own session, observe whether expired tokens still work |
| WSX-009 | Fragmentation | Fragmented frames bypass message validation | bounded | Own fragmented message with marker |
| WSX-010 | Binary | Binary frame handling differs from text validation | bounded | Own binary frame with marker |
| WSX-011 | Size | Max message size not enforced | authorized-only | Approval; single oversized frame in lab only |
| WSX-012 | Channels | Subscription to another user's channel allowed | bounded | Own two accounts: subscribe to the other channel ID |
| WSX-013 | Race | Race in message handling (duplicate state changes) | authorized-only | Approved sandbox only |
| WSX-014 | Tokens | Token refresh not applied to long-lived connections | bounded | Revoke own token, check the open socket |
| WSX-015 | Exfiltration | Data leaves through binary frames undetected by DLP | passive | Review logging and monitoring of frames |
