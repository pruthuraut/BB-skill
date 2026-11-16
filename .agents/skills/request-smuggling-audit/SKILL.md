---
name: request-smuggling-audit
description: Detect HTTP request smuggling / desync on authorized infrastructure across 10 core checks — CL.TE, TE.CL, TE.TE with Transfer-Encoding obfuscation, H2.CL and H2.TE (HTTP/2 downgrade), header manipulation techniques, proxy-to-backend desync, load balancer chains, WAF inspection bypass, and cache poisoning via smuggling — plus variants (CL.0, 0.CL, client-side desync, pause-based desync, h2c upgrade smuggling, HTTP/2 header CRLF injection, request tunnelling, response queue poisoning, chunk extensions, Expect 100-continue). Uses timing-based and differential detection that does not leave poisoned data on shared connections, a scope-gated raw-socket timing probe, PoC request templates, and tool guidance (Burp HTTP Request Smuggler, smuggler.py, h2csmuggler). Triggers on "request smuggling", "desync", "CL.TE", "TE.CL", "TE.TE", "H2.CL", "H2.TE", "HTTP/2 downgrade", "Transfer-Encoding", "chunked", "CL.0", "client-side desync", "h2c", "response queue poisoning", or when a CDN, load balancer, or reverse proxy fronts an origin.
---

# HTTP Request Smuggling (10 core checks + variants)

Smuggling happens when two servers in a chain (CDN, load balancer, reverse proxy, WAF, origin) disagree on where one request ends. The attacker's leftover bytes become the start of the next request on the same back-end connection, which may belong to another user. That is why confirmation is dangerous and detection must be done carefully.

- Checklist: `references/smuggling_checklist.md` (RS-001 to RS-010 core, RS-V-* variants, TE obfuscation list, impact table).
- PoC templates: `references/smuggling_poc_templates.md` (timing probes, differential confirmation on own path, H2 variants, CL.0, client-side desync, impact demonstrations for approved labs).
- Tracker: `references/smuggling_tracker.md`.
- Probe: `scripts/smuggle_timing.py` (raw-socket timing detection for CL.TE, TE.CL, and TE obfuscations in the safe order; scope-gated; one request per variant; never sends a confirmation prefix).
- Related: `request-smuggling-audit` (SMG-001 to SMG-009), `cache-poisoning-audit`, `server-config-audit` (proxy config, SMC-014), `techfingerprint` (`waf_cdn_origin.md`), `server-config-audit` (ALPN/HTTP/2).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. Read the program policy: many programs require prior approval for desync confirmation; some forbid it.
2. Map the chain: CDN/WAF/LB/proxy/origin and their versions (`Server`, `Via`, `X-Cache`, `CF-Ray`, `X-Served-By`), HTTP/2 support (`curl -sI --http2`), and whether connection reuse to the back end is likely.
3. Pick a low-traffic, idempotent endpoint you own or that has no side effects (for example a static asset or `/robots.txt` that accepts POST, or your own account page). Never test on login, payment, or shared state-changing endpoints.
4. **Detection (bounded):** run `scripts/smuggle_timing.py --url <endpoint>`. It sends the CL.TE timing probe first, then TE.CL only if CL.TE is not detected (the TE.CL probe can poison a CL.TE back end), then TE obfuscations. A delay close to the timeout on a variant, with fast baseline requests, is a candidate.
5. **HTTP/2 (bounded):** with Burp Suite HTTP Request Smuggler ("Smuggle probe", H2 options) or `smuggler.py` for HTTP/1, check H2.CL, H2.TE, and H2 CRLF header injection using timing and error differentials only.
6. **Differential confirmation (authorized-only on production):** send the attack request followed immediately by a normal request **from your own connection**, targeting a path only you request (for example `/<random>-smuggle-test`). A 404 for that unique path on your follow-up request confirms desync without affecting other users' paths. Repeat at most a few times. Prefer a staging or lab replica.
7. **Impact (authorized-only):** WAF bypass, cache poisoning, request capture, response queue poisoning only in an approved lab or with explicit written approval and a test window.
8. Save findings to `artifacts/<target>/request_smuggling.json` and the tracker to `artifacts/<target>/smuggling_tracker.md`.

## Classes

- `passive`: chain mapping, version/CVE checks, config review.
- `bounded`: timing and error-differential detection, one request per variant, on idempotent endpoints.
- `authorized-only`: differential confirmation with a smuggled prefix on production, any impact demonstration (capturing requests, poisoning caches or response queues, bypassing access controls), and high-volume scanning.

## Rules

- Never smuggle a prefix that targets a real path other users request, and never try to capture other users' requests.
- Stop after detection on production; hand confirmation to an approved window or lab.
- Keep the timeout short (10 s) and do not loop probes. If a site slows down or errors appear, stop.

## Mitigation guidance for reports

- Use HTTP/2 end to end (no downgrade), or normalize ambiguous requests at the front end.
- Reject requests with both `Content-Length` and `Transfer-Encoding`, multiple or malformed `Transfer-Encoding`/`Content-Length`, and obfuscated header names or values.
- Front end: close the back-end connection after an ambiguous or rejected request; do not reuse connections across clients where possible.
- Validate HTTP/2 pseudo-headers and reject CR/LF/colon in header names and values during downgrade.
- Patch proxies and servers (HAProxy, Apache Traffic Server, Varnish, Tomcat, Node, Nginx, IIS) to versions with smuggling fixes; disable h2c upgrades through proxies.

## Sources

PortSwigger Research "HTTP Desync Attacks" (2019), "HTTP/2: The Sequel is Always Worse" (2021), "Browser-Powered Desync Attacks" (2022), "Smashing the State Machine" pause-based techniques, PortSwigger Web Security Academy request smuggling labs, RFC 9112 section 6, CWE-444, Bishop Fox h2csmuggler, defparam smuggler.py.

## Merged skills (content preserved)

These skills covered the same topic and were merged here. Nothing was removed: each original SKILL.md, reference file, and Cursor rule is kept under `references/merged/<name>/`, and each script is in `scripts/` (a prefix marks name collisions).

- `http-protocol-cache`: full content in `references/merged/http-protocol-cache/` (SKILL.md, references, rule); scripts in `scripts/`
