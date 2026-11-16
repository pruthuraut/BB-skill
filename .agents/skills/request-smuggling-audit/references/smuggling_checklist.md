# HTTP Request Smuggling Checklist

Class key: `passive` = chain mapping, versions, configs. `bounded` = timing or error-differential detection, one request per variant, on idempotent endpoints. `authorized-only` = smuggled-prefix confirmation on production, and every impact demonstration.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RS-001 | CL.TE | Front end uses Content-Length, back end uses Transfer-Encoding | bounded | smuggle_timing.py CL.TE probe: `Content-Length: 4`, body `1\r\nA\r\nX`; back end waits for the next chunk (delay) |
| RS-002 | TE.CL | Front end uses Transfer-Encoding, back end uses Content-Length | bounded | Only after RS-001 is negative: `Content-Length: 6`, body `0\r\n\r\nX`; back end waits for one more byte (delay) |
| RS-003 | TE.TE | Both support TE, but one can be induced to ignore it with obfuscation | bounded | Repeat RS-001/RS-002 with each TE obfuscation (list below) |
| RS-004 | H2.CL | HTTP/2 front end downgrades to HTTP/1.1 and passes a `content-length` the back end trusts | bounded | Burp HTTP Request Smuggler H2 probes; timing/error differential only |
| RS-005 | H2.TE | HTTP/2 request with `transfer-encoding: chunked` forwarded on downgrade | bounded | Burp H2 probes; timing/error differential only |
| RS-006 | Header techniques | Header manipulation: duplicate CL, CL with spaces or `+`, CL and TE both present, line folding, `\n` only line endings, header name with trailing space or tab, H2 header CRLF injection, pseudo-header injection | bounded | Single request per variant; record status, error, timing |
| RS-007 | Proxy chain | Desync between a reverse proxy (Nginx, Apache, HAProxy, Envoy, Traefik, ATS, Varnish) and the back end (Gunicorn, Node, Tomcat, IIS, Puma) | bounded | Fingerprint each hop; run RS-001 to RS-006 against paths routed to different back ends |
| RS-008 | Load balancer | Desync at cloud load balancers or CDNs (ALB, ELB, GCLB, Azure Front Door, Akamai, Cloudflare, Fastly) and per-pool behavior | bounded | Same probes on hosts behind each LB; note that some LBs pin connections per client (lower impact) |
| RS-009 | WAF bypass | Smuggled request reaches the back end without WAF inspection (blocked path or payload accepted when smuggled) | authorized-only | Approved test: smuggle a request to a WAF-blocked own path with a benign marker |
| RS-010 | Cache | Smuggling used to poison a cache (smuggled request's response stored for a normal URL) | authorized-only | Lab only, or own unique cache key with written approval; see cache-poisoning-audit |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| RS-V-001 | CL.0 | Back end ignores Content-Length on certain endpoints (static files, redirects, `Expect`), treating the body as the next request | bounded | Burp "CL.0" probe on own connection to a unique path; differential only |
| RS-V-002 | 0.CL | Front end ignores CL, back end honors it (needs early-response gadget) | authorized-only | Lab |
| RS-V-003 | Client-side desync | Browser-powered desync: server ignores CL on some endpoints, so a victim's browser can be made to desync its own connection | bounded | Burp "connection-state" and CSD probes; confirm with your own browser only |
| RS-V-004 | Pause-based | Server times out reading the body but keeps the connection (pause-based desync, for example Apache with certain redirects) | authorized-only | Lab or approved window |
| RS-V-005 | h2c | `Upgrade: h2c` passed through a proxy, giving direct HTTP/2 to the back end and bypassing proxy rules | bounded | `h2csmuggler.py --test`; only check that upgrade succeeds |
| RS-V-006 | H2 CRLF | CRLF in an HTTP/2 header value or name becomes a new header or request on downgrade | bounded | Burp H2 probe with `foo: bar\r\nTransfer-Encoding: chunked` |
| RS-V-007 | Tunnelling | Request tunnelling (H2 front end with per-request back-end connections): smuggled request's response leaks into the attacker's response | authorized-only | Lab or approved; HEAD-based tunnelling probes |
| RS-V-008 | Queue poisoning | Response queue poisoning: back end returns two responses, front end hands the extra to the next user | authorized-only | Never on production without written approval |
| RS-V-009 | Chunk parsing | Chunk extensions, chunk size with leading zeros or `0x`, oversized chunk sizes, bare LF in chunk lines | bounded | One probe per variant |
| RS-V-010 | Expect | `Expect: 100-continue` differences between hops | bounded | Single request differential |
| RS-V-011 | Versions | Known smuggling CVEs: HAProxy (CVE-2021-40346, CVE-2023-25725), Apache Traffic Server (CVE-2022-31779), Tomcat (CVE-2023-46589), Node llhttp (CVE-2022-32213/32215, CVE-2023-30589), Gunicorn, Puma, Netty | passive | Version check |
| RS-V-012 | HTTP/1.0 | Keep-alive and HTTP/1.0 connection handling mismatch | bounded | Single request differential |

## Transfer-Encoding obfuscations (RS-003)

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:	chunked                (tab)
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding:
 chunked                                    (line folding)
X: X[\n]Transfer-Encoding: chunked          (bare LF before header)
Transfer-Encoding: x
Transfer-Encoding: chunked                  (sent twice, second with "x")
Transfer-encoding: cHuNkEd
Transfer-Encoding: "chunked"
Transfer-Encoding: chunked\x0b             (vertical tab)
Transfer-Encoding: \x00chunked
```

## Impact table (what to say in the report)

| Confirmed primitive | Possible impact (demonstrate only in a lab or with approval) |
|---|---|
| Desync on a reused back-end connection | Bypass front-end access controls (reach `/admin` only allowed internally) |
| + reflected input on back end | Reflected XSS delivered to the next user without interaction |
| + storage feature (comment, profile) | Capture other users' requests, including cookies |
| + cache in front | Persistent cache poisoning or deception |
| Response queue poisoning | Other users receive responses meant for someone else |
| WAF in front | Payloads reach the back end uninspected |

## Cross-references

| RS row | Related rows |
|---|---|
| RS-001, 002 | http-protocol-cache SMG-001, SMG-002 |
| RS-003 | SMG-003 |
| RS-004, 005 | SMG-004 |
| RS-007, 008 | SMG-008, server-config-audit SMC-014 |
| RS-V-008 | SMG-009 |
| RS-V-011 | SMG-005 to SMG-007 |
| RS-010 | cache-poisoning-audit |
