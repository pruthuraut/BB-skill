# Web Cache Poisoning and Deception Checklist

Class key: `passive` = cache headers, Vary, configs. `bounded` = unique cache buster or unique path; deception with own test-account data. `authorized-only` = real cache keys, CPDoS on real pages, purges.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CP-001 | Unkeyed headers | Unkeyed header reflected and cached (X-Forwarded-Host, X-Host, X-Forwarded-Scheme/Proto, X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix, Forwarded) | bounded | cache_probe.py: canary in header with unique buster, then clean request with same buster returns canary |
| CP-002 | Unkeyed cookies | Cookie value reflected but not keyed (language, currency, theme, A/B bucket, fehost) | bounded | cache_probe.py `--cookie-names`; same two-step check |
| CP-003 | Unkeyed params | Query parameters excluded from the key but reflected (utm_*, fbclid, gclid, callback, `_`) | bounded | cache_probe.py unkeyed params under buster |
| CP-004 | Deception paths | Path-parameter tricks make a private page cacheable: `/account/x.css`, `/account;x.css`, `/account%2fx.css`, `/account%3bx.css`, `/account.css`, `/account%00.css`, `/account?x.css` | bounded | cache_probe.py deception with own marker |
| CP-005 | Normalization | Cache key normalization differs from origin: case, trailing slash, encoded characters (`%2e`, `%2f`), dot segments, duplicate slashes, `?` vs `%3f`, fragment, port in Host | bounded | Poison variant A under buster, fetch variant B with the same buster; see templates |
| CP-006 | Method override | `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `_method` change the response (for example to 405 or HEAD) while the key stays GET | bounded | cache_probe.py method-override under buster |
| CP-007 | Vary | Vary missing for inputs that change the response (User-Agent, Origin, Accept-Language, Cookie), or Vary on a header the attacker controls with a common value | bounded | cache_probe.py reports Vary; compare responses per header value under buster |
| CP-008 | Fat GET | GET with a body: origin reads body parameters, cache keys only the URL | bounded | cache_probe.py fat GET under buster |
| CP-009 | Extension | File-extension and static-directory tricks for deception: `.css .js .png .jpg .gif .ico .svg .woff .woff2 .avif .webp`, static prefixes `/static/ /assets/ /public/ /resources/ /wp-content/`, `/static/..%2faccount` | bounded | cache_probe.py deception variants; static-directory traversal templates |
| CP-010 | Header injection | Response header injection or splitting through a cached response (CRLF in reflected param, Location header, Set-Cookie injection cached for others) | bounded | Under buster: `%0d%0aX-Injected:%20cp` in a reflected param; see server-config-audit SMC-018 to SMC-020 |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CP-V-001 | Param cloaking | Cache and origin split parameters differently (`;` as separator in Rails/Rack, duplicate params, `?a=1&a=2` first vs last) | bounded | `?cb=X&utm_content=x;callback=canary` under buster |
| CP-V-002 | Unkeyed port | Port in Host header not keyed but reflected (`Host: target.com:1337`) | bounded | Under buster; check redirects/links |
| CP-V-003 | Key injection | Cache-key components joined with delimiters that can be injected (for example `__` in Akamai/Cloudflare custom keys) | bounded | Review key format from `X-Cache-Key` debug headers (Akamai Pragma headers) |
| CP-V-004 | CPDoS HHO | Oversized header causes origin 400 that gets cached (HTTP Header Oversize) | authorized-only | Under buster only with approval; never on real keys |
| CP-V-005 | CPDoS HMC | Meta character in header (`\n`, `\x07`) causes cached error (HTTP Meta Character) | authorized-only | Same |
| CP-V-006 | CPDoS HMO | Method override causes cached 404/405 (HTTP Method Override) | bounded | Under buster only (CP-006) |
| CP-V-007 | Debug headers | Cache debug headers expose the key (`Pragma: akamai-x-get-cache-key`, `Fastly-Debug: 1`, `X-Cache-Key`) | bounded | Single request with debug header |
| CP-V-008 | JS imports | Poisoned host used in script/import URLs (`<script src="//X-Forwarded-Host/...">`) | bounded | Canary host reflection in script src under buster |
| CP-V-009 | Redirects | Unkeyed input changes a cached redirect target (X-Forwarded-Scheme causing http redirect loop, X-Forwarded-Host in Location) | bounded | Under buster |
| CP-V-010 | Internal cache | Application-level caches (framework fragment cache, Next.js ISR, GraphQL persisted queries) keyed differently | bounded | Review and own-key probes |
| CP-V-011 | API caching | Authenticated API responses cached at the CDN (`Cache-Control` missing) | bounded | Own token request, then anonymous same URL with buster |
| CP-V-012 | Delimiters | Origin path delimiters vs cache: Spring `;`, Rails `.` format, OpenLiteSpeed `%00`, Nginx `%0a`, IIS `\`, encoded `#` `%23`, `?` `%3f` | bounded | Deception variants with own marker |
| CP-V-013 | Normalization | Cache normalizes `..%2f` / `%2e%2e/` but origin does not (or reverse): `/static/..%2faccount` cached under static rule | bounded | Own marker deception |
| CP-V-014 | Cookie-less | Cache serves authenticated content to users without cookies when `Vary: Cookie` missing | bounded | Own session request then anonymous with buster |

## Unkeyed input list (start here, then Param Miner)

Headers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `X-Original-URL`, `X-Rewrite-URL`, `X-Original-Host`, `X-Forwarded-For`, `X-Client-IP`, `True-Client-IP`, `X-Wap-Profile`, `X-Device`, `X-Mobile`, `User-Agent`, `Accept-Language`, `Origin`, `X-HTTP-Method-Override`.

Cookies: `lang`, `language`, `locale`, `currency`, `country`, `region`, `theme`, `fehost`, `ab`, `experiment`, `variant`.

Params: `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`, `utm_term`, `fbclid`, `gclid`, `msclkid`, `_`, `cb`, `callback`, `ref`.

## CDN notes

| CDN | Hit indicator | Notes |
|---|---|---|
| Cloudflare | `CF-Cache-Status: HIT/MISS/DYNAMIC` | Caches by extension by default; Cache Deception Armor checks Content-Type vs extension |
| Akamai | `X-Cache: TCP_HIT`, `X-Check-Cacheable` | `Pragma: akamai-x-cache-on, akamai-x-get-cache-key` debug headers |
| Fastly | `X-Cache: HIT`, `X-Served-By`, `X-Cache-Hits` | `Fastly-Debug: 1`; VCL-defined keys |
| CloudFront | `X-Cache: Hit from cloudfront`, `Age` | Cache policy defines keyed headers, cookies, params |
| Varnish | `X-Varnish: id1 id2` (two IDs = hit), `Age` | `hash_data` in VCL defines key |
| Nginx | `X-Cache-Status` (if configured) | `proxy_cache_key` defines key |

## Cross-references

| CP row | Related rows |
|---|---|
| CP-001 | http-protocol-cache CACHE-001, server-config-audit SMC-013 |
| CP-003 | CACHE-002 |
| CP-004, CP-009 | CACHE-004 |
| CP-005, CP-V-013 | CACHE-005 |
| CP-010 | server-config-audit SMC-018 to SMC-020, open-redirect-and-header-injection |
| CP-V-008 | xss |
