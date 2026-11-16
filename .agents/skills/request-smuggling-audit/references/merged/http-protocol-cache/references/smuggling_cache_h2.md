# HTTP Request Smuggling, HTTP/2 Desync, Cache Poisoning and Deception, WAF Chunked Bypass

Class key: `passive` (version and header review), `bounded` (timing or differential probes on in-scope hosts with your own test paths; never poison a shared cache entry for real users), `authorized-only` (confirmed desync or cache poisoning needs written approval and a test path that no user requests).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SMG-001 | Front-end/back-end pair | CL.TE desync (Content-Length vs Transfer-Encoding) | bounded | Timing differential with a harmless 0-length chunk; approved test path only |
| SMG-002 | Front-end/back-end pair | TE.CL desync | bounded | Timing differential as SMG-001 |
| SMG-003 | Front-end/back-end pair | TE.TE obfuscation (`Transfer-Encoding: xchunked`, tab, space) | bounded | Differential response on own path |
| SMG-004 | HTTP/2 downgrade | H2.CL and H2.TE desync | bounded | Differential probe with own test path |
| SMG-005 | HTTP/2 | Rapid Reset DoS (CVE-2023-44487, Tomcat <9.0.81) | passive | Version check only; never send reset floods |
| SMG-006 | Tomcat | Trailer header smuggling CVE-2023-46589 (<9.0.83) | passive | Version check |
| SMG-007 | Apache Traffic Server | Request smuggling CVE-2022-31779 (<9.1.4 / 8.1.5) | passive | Version check |
| SMG-008 | Varnish / HAProxy / Akamai / Cloudflare | Front-end parser differential | bounded | Header differential on own path |
| SMG-009 | Pipeline | Connection reuse across users (response queue poisoning) | authorized-only | Approved lab test only |
| CACHE-001 | Unkeyed headers | X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL reflected and cached | bounded | Unique cache-buster query on own path, compare with and without header |
| CACHE-002 | Unkeyed headers | Cache key ignores parameters used for reflection | bounded | Cache-buster query differential |
| CACHE-003 | Varnish | Unkeyed headers in VCL hash_data | passive | Review config if available; else differential probe |
| CACHE-004 | Web cache deception | Static extension appended to authenticated dynamic path (`/account/x.css`) cached with private data | bounded | Own test account: request path with .css and check Cache-Control and whether second anonymous request gets your data |
| CACHE-005 | Web cache deception | Path normalization mismatch (`/account/..%2fstatic`) | bounded | Own account differential |
| CACHE-006 | CDN | Origin reachable directly, bypassing WAF and cache | bounded | Host header check against origin IP (see techfingerprint waf_cdn_origin.md) |
| WAF-001 | WAF | Chunked encoding bypass of body inspection | bounded | Own payload split across chunks, compare block vs allow |
| WAF-002 | WAF | Case and comment obfuscation of blocked keywords | bounded | Benign marker strings only |
| WAF-003 | WAF | Parameter pollution bypass (duplicate params, first-only inspection) | bounded | Duplicate param marker on own input |
| WAF-004 | WAF | Encoding variants (URL, double, Unicode, HTML entity, wide-byte) | bounded | Benign marker strings |
| WAF-005 | WAF | Oversized body skipping inspection | bounded | One 1 MB own-body request, check block change |
| WAF-006 | AWS WAF | Case-sensitive rules and body size limits | bounded | Benign marker tests as above |
| WAF-007 | Akamai | Method override and XFF to trusted address (`X-Forwarded-For: 127.0.0.1`) | bounded | Header differential on own path |
| WAF-008 | Akamai / Fastly | Purge or method abuse exposure | bounded | OPTIONS and header check only; never purge production cache |
