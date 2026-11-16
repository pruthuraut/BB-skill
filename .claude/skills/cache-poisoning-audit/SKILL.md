---
name: cache-poisoning-audit
description: Audit authorized sites for web cache poisoning and web cache deception across 10 core checks — unkeyed headers, unkeyed cookies, unkeyed query parameters, path-parameter deception tricks, cache-key normalization differences, HTTP method override, Vary header handling, fat GET requests, file-extension deception, and response header injection — plus variants (parameter cloaking, unkeyed port, cache-key injection, CPDoS via oversized/meta-character headers and method override, static-directory and delimiter rules per framework, CDN-specific behaviors for Cloudflare, Akamai, Fastly, CloudFront, Varnish, Nginx). All probes use a unique cache buster or unique path so only test-owned cache entries are touched. Includes a scope-gated probe for cache detection, unkeyed inputs, fat GET, method override, and deception with an own-data marker. Triggers on "cache poisoning", "web cache deception", "unkeyed header", "X-Forwarded-Host", "cache key", "Vary", "fat GET", "Param Miner", "CPDoS", "X-Cache", "CF-Cache-Status", "Age header", or when a CDN or caching proxy fronts the site.
---

# Web Cache Poisoning and Deception (10 core checks + variants)

- **Poisoning:** an input that changes the response is **not** part of the cache key, so an attacker's response is stored and served to everyone who requests the same key.
- **Deception:** the cache stores a **private** response because the URL looks static (`/account/x.css`), so anyone can later fetch the victim's data from the cache.

- Checklist: `references/cache_checklist.md` (CP-001 to CP-010, CP-V-*, unkeyed input list, deception delimiters and static rules, CDN notes).
- Templates: `references/cache_poc_templates.md`.
- Tracker: `references/cache_tracker.md`.
- Probe: `scripts/cache_probe.py` (detects caching and hit indicators, tests unkeyed headers, cookies, and query parameters with a canary under a unique cache buster, fat GET, method override, Vary, and cache deception variants with your own data marker).
- Related: `http-protocol-cache` (CACHE-001 to CACHE-006), `request-smuggling-audit` (RS-010), `server-config-audit` (SMC-012, SMC-013 Host/X-Forwarded-Host), `xss` (payload delivery), `open-redirect-and-header-injection`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Detect the cache: request a page twice and read `Age`, `X-Cache`, `CF-Cache-Status`, `X-Cache-Hits`, `X-Served-By`, `X-Varnish`, `Cache-Control`, `Vary`. Learn what is cached (static types, HTML, API) and for how long.
3. Always add a unique **cache buster** (`?cb=<random>`) or unique path, so every probe creates its own cache entry that no real user requests.
4. Run `scripts/cache_probe.py --url https://TARGET/page`. For each unkeyed input it reports reflected (response changed) and **cached** (a clean request with the same buster returned the canary).
5. For deeper discovery, use Burp Param Miner ("Guess headers", "Guess params", "Guess cookies") with cache busters enabled.
6. Deception: log in to a dedicated test account with a unique marker in your profile (for example display name `cpd-<random>`), then run the probe with `--auth-url https://TARGET/account --cookie 'session=OWN' --marker cpd-<random>`. It requests static-looking variants of your account URL with your session, then fetches the same URLs anonymously; your marker in the anonymous response confirms deception.
7. Exploitability: decide if the poisoned input can carry a payload (XSS via reflected host, JS import from attacker host, redirect, DoS) and if the poisoned key is one real users request. Demonstrating against real keys (no buster) is authorized-only.
8. Save findings to `artifacts/<target>/cache_poisoning.json` and the tracker to `artifacts/<target>/cache_tracker.md`.

## Classes

- `passive`: cache headers, Vary, CDN fingerprinting, config review.
- `bounded`: probes under a unique cache buster or unique path, deception with your own test-account data.
- `authorized-only`: poisoning keys real users request (no buster), CPDoS against real pages, cache purges, and anything that serves attacker content to others.

## Rules

- Never poison a real page's cache key. Every request carries a unique buster or a unique path.
- Use a dedicated test account with no sensitive data for deception; your marker may stay cached until it expires.
- Never send purge requests (`PURGE`, `BAN`, Fastly or Akamai purge APIs).

## Mitigation guidance for reports

- Do not reflect unkeyed inputs; strip or ignore `X-Forwarded-*` and similar headers at the edge, or add them to the cache key.
- Keep cache keys and origin parsing consistent (same normalization, delimiters, and decoding); disable fat GET bodies and method override headers.
- Cache only by explicit allowlist (static paths and content types); respect `Cache-Control: private, no-store` on authenticated responses; key on the `Content-Type` of the response, not the URL extension.
- Send correct `Vary`; avoid caching error responses (CPDoS).
- Use Cloudflare Cache Deception Armor or equivalent extension/content-type checks.

## Sources

PortSwigger Research "Practical Web Cache Poisoning" (2018), "Web Cache Entanglement" (2020), "Gotta Cache 'em All" (2024), Omer Gil "Web Cache Deception Attack" (2017), CPDoS research (cpdos.org, 2019), PortSwigger Web Security Academy web cache poisoning and deception labs, CWE-524 and CWE-444.
