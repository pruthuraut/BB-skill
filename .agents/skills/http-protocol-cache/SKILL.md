---
name: http-protocol-cache
description: Audit authorized web infrastructure for HTTP request smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 downgrade desync), HTTP/2 DoS and CVE exposure, web cache poisoning through unkeyed headers, web cache deception through static-extension paths, and WAF or CDN bypass with chunked encoding and parameter pollution. Triggers on "request smuggling", "desync", "HTTP/2", "h2", "Transfer-Encoding", "cache poisoning", "unkeyed header", "web cache deception", "WAF bypass", "chunked", "CDN origin bypass", or when a fingerprint shows Varnish, Akamai, Fastly, Cloudflare, HAProxy, or Traffic Server in front of an origin.
---

# HTTP Protocol, Cache, and WAF Bypass

Find front-end and back-end disagreements on request framing, caches that store per-user responses, and WAF rules that inspect less than the origin processes. Every probe uses your own test path or a path no real user requests. Confirmed desync or cache poisoning on shared paths is authorized-only.

Checklist: `references/smuggling_cache_h2.md` (about 30 rows).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. Desync testing needs an explicit window and approval, because a bad probe can affect other users.
2. Fingerprint the chain: CDN, WAF, load balancer, origin server, HTTP version (`curl -sI --http2`). Use techfingerprint `waf_cdn_origin.md`.
3. Passive: version and CVE checks for Tomcat, Traffic Server, HAProxy, Nginx (SMG-005 to SMG-007).
4. Cache (bounded): add a unique cache-buster query to your own test path, send with and without the unkeyed header (CACHE-001), and compare cache headers (`Age`, `X-Cache`, `CF-Cache-Status`).
5. Cache deception (bounded): on your own logged-in account, request your account path with a static extension. Check cache headers and whether a fresh anonymous request sees your data. Stop on first confirmation.
6. Smuggling (bounded): use timing differentials on your test path only (SMG-001 to SMG-004). Do not send requests that could be prepended to other users' traffic.
7. WAF (bounded): benign marker strings for every encoding variant (WAF-001 to WAF-008). Never submit real attack payloads to a WAF in production.
8. Save results to `artifacts/<target>/http_protocol.json`.

## Classes

- `passive`: version, header, config review.
- `bounded`: own-path differentials with cache-busters.
- `authorized-only`: confirmed desync, poisoning of shared entries, or purge.

## Rules

- Never purge production caches. Use a unique path for every cache test.
- Never test HTTP/2 Rapid Reset style floods. Version check only (SMG-005).
