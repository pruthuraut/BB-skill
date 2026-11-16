# CORS Concepts Reference

## Same-origin policy (SOP)

An origin is the triple **(scheme, host, port)**. SOP stops a page from reading responses from a different origin. It does not stop sending requests (that is why CSRF exists) and it has exceptions:

- Some objects are writable but not readable cross-origin, such as `location` and `location.href` of iframes or new windows.
- Some objects are readable but not writable cross-origin, such as `window.length` (number of frames) and `window.closed`.
- `location.replace` can usually be called cross-origin.
- Some functions can be called cross-origin: `close`, `blur`, `focus` on a new window, and `postMessage` on iframes and windows.

CORS extends SOP: the server adds headers that tell the browser which other origins may read the response. CORS is not a defense against CSRF.

## Simple requests (no preflight)

A request is simple when **all** of these hold:

- Method is `GET`, `HEAD`, or `POST`.
- Only these headers are set manually: `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, `DPR`, `Downlink`, `Save-Data`, `Viewport-Width`, `Width` (and `Range` with a simple value in current browsers).
- `Content-Type` is `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`.
- No event listeners on `XMLHttpRequest.upload`, and no `ReadableStream` body.

Simple requests are sent immediately; the browser only checks ACAO afterwards to decide whether JavaScript may read the response. The side effect happens either way.

## Preflighted requests

Anything else (PUT, DELETE, PATCH, `application/json`, `Authorization`, custom headers) makes the browser send an `OPTIONS` preflight first:

```http
OPTIONS /api/data HTTP/1.1
Origin: https://attacker.example
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom, Content-Type
```

The actual request is sent only if the preflight response approves the origin, method, and headers.

## Credentialed requests

Browsers do not send cookies, HTTP auth, or TLS client certificates cross-origin unless the request asks for it (`credentials: "include"` or `xhr.withCredentials = true`). The response is then exposed to JavaScript only if:

- `Access-Control-Allow-Credentials: true`, and
- `Access-Control-Allow-Origin` is the exact requesting origin (not `*`).

Cookies are still subject to SameSite and third-party cookie policies. A `SameSite=Lax` or `Strict` session cookie is not sent on cross-site fetches, which often blocks exploitation; `SameSite=None; Secure` cookies are sent. Note browser and version in reports.

## Request headers

| Header | Meaning |
|---|---|
| `Origin: <origin>` | Origin of the cross-site or preflight request. No path. Can be `null`. |
| `Access-Control-Request-Method: <method>` | Preflight: method of the actual request. |
| `Access-Control-Request-Headers: <names>` | Preflight: headers of the actual request. |

## Response headers

| Header | Meaning |
|---|---|
| `Access-Control-Allow-Origin: <origin> \| null \| *` | Single origin allowed to read. `*` only works without credentials. No list, no `*.domain` wildcard. |
| `Access-Control-Allow-Credentials: true` | Response readable on credentialed requests. |
| `Access-Control-Allow-Methods: <methods>` | Preflight: allowed methods. |
| `Access-Control-Allow-Headers: <names>` | Preflight: allowed request headers. |
| `Access-Control-Expose-Headers: <names>` | Response headers JS may read beyond the safelisted ones (`Cache-Control`, `Content-Language`, `Content-Length`, `Content-Type`, `Expires`, `Last-Modified`, `Pragma`). |
| `Access-Control-Max-Age: <seconds>` | How long a preflight result is cached. |
| `Vary: Origin` | Required when ACAO is generated dynamically, so caches key on Origin. |

## How ACAO gets generated (why reflection happens)

- Browsers do not support a space-separated list of origins, and `*.bar.net` is not a valid wildcard. The only wildcard is `*`, and it cannot be used with credentials.
- So apps that need several origins with credentials generate ACAO from the request's `Origin`. If a response has `Access-Control-*` headers but no fixed origin, the value is likely generated from input.
- Some apps only add CORS headers when the request carries `Origin`, so the issue is invisible in normal browsing. Always resend sensitive requests with an Origin header.

## The null origin

Browsers send `Origin: null` for:

- Cross-site redirects
- Requests from serialized data
- Requests from `file:` pages
- Sandboxed cross-origin requests (`<iframe sandbox>` with `srcdoc` or `data:`)

Apps sometimes allow `null` for local development. An attacker gets `null` with a sandboxed iframe (PoC template 3).

## Broken parsers

Most servers check Origin with string operations; some parse it as a URL. Browser tolerance for odd characters in hostnames creates gaps:

- In Safari, `https://website.com%60.attacker.com/` is a valid URL, and the Origin header becomes ``https://website.com`.attacker.com``. A URL parser may read the host as `website.com` and ignore the rest.
- Chrome and Firefox accept `_` in subdomains, so `https://website.com_.attacker.com` works there.
- Other validation breakers: `expected-host.com.attacker.com`, `expected-host.computer`, `foo@evil-host:80@expected-host`, `foo@evil-host%20@expected-host`, `evil-host%09expected-host`, `127.1.1.1:80\@127.2.2.2:80`, `127.1.1.1:80:\@@127.2.2.2:80`, `127.1.1.1:80#\@127.2.2.2:80`, `ß.evil-host`.

## Abusing CORS without credentials

When network location acts as authentication (intranet apps, IP allowlists), `ACAO: *` lets an external page use the victim's browser as a proxy to read internal responses. Impact is similar to DNS rebinding. Modern Chrome Private Network Access preflights limit this; check the browser version.

## Breaking TLS with a trusted http origin

If an HTTPS app trusts `http://trusted-subdomain.target.com` with credentials:

1. The victim makes any plain HTTP request.
2. A network attacker injects a redirect to `http://trusted-subdomain.target.com`.
3. The victim's browser follows it.
4. The attacker answers that plain HTTP request with a page that makes a CORS request to `https://target.com`.
5. The browser sends Origin `http://trusted-subdomain.target.com`.
6. The app allows it; sensitive data comes back.
7. The attacker's page reads it and sends it out.

This works even if the main app uses only HTTPS with Secure cookies.

## XSS via CORS trust

Even a correct allowlist creates trust. If `https://subdomain.target.com` is trusted with credentials and has XSS, script injected there can read the main app's API (PoC template 8).

## Vary: Origin and client-side cache poisoning

If ACAO is dynamic but `Vary: Origin` is missing, a browser cache may store a response fetched cross-origin and serve it on normal navigation. Combined with a header-reflected XSS (for example `X-User-id: <svg/onload=alert(1)>` reflected in an HTML error, with `Access-Control-Allow-Headers: X-User-id`), the attacker makes the victim's browser send the custom header via CORS, the poisoned response is cached, and navigating to the URL renders it.

## Server-side cache poisoning via Origin

If Origin is reflected without rejecting CR (`\r`), older IE and Edge treated `\r` as a header terminator: `Origin: z[0x0d]Content-Type: text/html; charset=UTF-7` yields an injected Content-Type. Browsers cannot send this, but a manual request can, and a shared cache may store and serve it. Treat as authorized-only; see http-protocol-cache.
