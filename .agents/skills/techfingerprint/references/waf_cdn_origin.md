# CDN, WAF, Edge, and Origin Discovery (extension)

Class key: `passive` = headers, DNS, certificate transparency. `bounded` = one or two requests to the origin IP with the correct Host header. Origin discovery is only for confirming in-scope assets; do not test a discovered origin unless it is also in scope.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CDN-001 | Generic | Identify CDN/WAF from headers and cookies (cf-ray, x-akamai, x-iinfo, x-fastly, server: cloudflare) | passive | `curl -sI <url>`; `wafw00f <url>` |
| CDN-002 | Cloudflare | Origin IP leak via historical DNS or subdomain not proxied | passive | Certificate transparency and DNS history for the apex |
| CDN-003 | Cloudflare | Origin reachable with Host header | bounded | `curl -sk --resolve <t>:443:<candidate-ip> https://<t>/` (in-scope IPs only) |
| CDN-004 | Akamai | Origin IP exposure through DNS or cert history | passive | Certificate transparency for apex and wildcard names |
| CDN-005 | Akamai | Origin accepts requests bypassing edge | bounded | Host-header test as CDN-003 |
| CDN-006 | Akamai | Method and XFF bypass of edge rules | bounded | Header differential on own path (see http-protocol-cache WAF-007) |
| CDN-007 | Fastly | Origin exposure and unauthenticated purge | passive | Origin via history; purge only in a test service, never production |
| CDN-008 | Imperva / Incapsula | Origin via historical DNS or CloudFlair-style lookups | passive | Historical DNS review |
| CDN-009 | Imperva | WAF rule bypass with encoding tricks | bounded | Benign marker tests (see http-protocol-cache WAF-*) |
| CDN-010 | CloudFront | Origin bypass to S3 or ALB directly | bounded | Host header check against bucket or ALB name |
| CDN-011 | CloudFront | Signed URL or cookie bypass | authorized-only | Review signing policy; no key attempts |
| CDN-012 | Edgio / Limelight / EdgeCast | Origin exposure and cache poisoning | passive | Historical DNS and headers |
| CDN-013 | Gcore / GoCache | Origin exposure via certificate logs | passive | Certificate transparency |
| CDN-014 | DDoS-Guard | Origin IP via DNS history | passive | Historical DNS |
| CDN-015 | ArvanCloud | Origin IP and WAF bypass | bounded | Host-header test on in-scope IP |
| CDN-016 | Bunny CDN | Origin and storage zone exposure | bounded | See saas file SAAS-006, SAAS-007 |
| CDN-017 | Sucuri | WAF headers and bypassable rules | passive | Header review |
| CDN-018 | ImageEngine / Imgix | Origin URL in image URLs | passive | Grep image URLs for origin host |
| CDN-019 | KeyCDN | Origin exposure via misconfiguration | passive | Header review |
| CDN-020 | Varnish | Cache poisoning via unkeyed headers | bounded | See http-protocol-cache CACHE-001 |
| CDN-021 | AWS WAF | Case, encoding, HPP, body size bypass | bounded | Benign marker tests |
| CDN-022 | Cloudways / Pantheon / WP Engine / Kinsta / SiteGround / Heroku / Platform.sh | Hosting identifiers in headers | passive | Header review |
| CDN-023 | DataDome / Kasada / Akamai Bot Manager | Bot protection present and token validation | bounded | See client-side and saas files |
| CDN-024 | Generic WAF | Parameter pollution and chunked bypass | bounded | See http-protocol-cache WAF-001 to WAF-005 |
