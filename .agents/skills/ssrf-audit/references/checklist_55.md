# Server-Side Request Forgery (SSRF): 55-Check Ledger

**Progress:** `[ 0 / 55 assessed ]` (+ white-box appendix WB-1…WB-8)

Layout per check: **severity if vulnerable**, execution class(es), tags, subagent, objective, commands, pass/fail, references. SR-01…SR-30 are the core list. SR-31…SR-55 extend it with:
- PortSwigger labs and research (Orange Tsai, James Kettle)
- OWASP WSTG and the SSRF Prevention cheat sheet
- PayloadsAllTheThings, HackTricks, cujanovic/SSRF-Testing, jdonsec/AllThingsSSRF, 0xn3va cheat sheet
- the community tips and HackerOne reports supplied with this skill

Variables: `$T` target origin · `$S` = `.agents/skills/ssrf-audit/scripts` · `$E` = `artifacts/ssrf/evidence` · `$COLLAB` your own OOB host (Burp Collaborator / interactsh / your `ssrf_listener.py`) · `$R` your redirector (`https://YOU/r`) · `FUZZ` = URL-accepting input.

Classes: **O** out-of-band to your host (default) · **R** internal reach with benign proof (default after O) · **S** sensitive read: credentials, user-data, tokens, secret files (explicit permission) · **W** talks to internal non-HTTP services or changes state (gopher/dict/Redis/Docker/admin actions; explicit permission, usually report-only) · **N** wider internal network scanning (explicit permission). See SKILL.md.

Status: `PASS` · `FINDING` · `INFO` · `GATED` · `NOT_APPLICABLE` · `BLOCKED` · `CONFIG_REVIEW` (white-box only).

Ground rules for every check:
- Prove reach with the least sensitive response:
  - your collaborator hit
  - an internal page title
  - `instance-id` / `ami-id` / `project-id` / the IAM **role name**
  - `/etc/hostname`, or the first line of `/etc/passwd`
- Never request IAM/managed-identity credentials, `user-data`, service-account tokens, k8s secrets or private keys without class S permission. `ssrf_probe.py` refuses those paths.
- If secrets come back anyway: stop. Do not use, test or store them. Redact the evidence to key names and report immediately.
- Only GET or HEAD against internal services. No gopher/dict payloads that write to Redis, memcached, SMTP, FastCGI or Docker.
- No Responder/NTLM capture, cracking or relay. A UNC-triggered DNS or SMB connection to your own host is enough evidence.
- No heavy-file or fan-out fetches (SSRF→DoS), and no subnet sweeps without class N.

Reference shorthands:
- `PS-SSRF` = `https://portswigger.net/web-security/ssrf`
- `PS-BLIND` = `https://portswigger.net/web-security/ssrf/blind`
- `PS-URL` = `https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet`
- `PS-ROUTE` = `https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf`
- `PS-XXE` = `https://portswigger.net/web-security/xxe`
- `WSTG-SSRF` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery`
- `OWASP-CS` = `https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`
- `PATT` = `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery`
- `HT` = HackTricks *SSRF* and *URL Format Bypass*
- `ORANGE` = Orange Tsai, *A New Era of SSRF – Exploiting URL Parsers in Trending Programming Languages* (Black Hat USA 2017)
- `CWE-918` = `https://cwe.mitre.org/data/definitions/918.html`

---

## SR-A — Entry Points & Discovery

### SR-01 · URL parameters that fetch remote resources — `HIGH` · O/R
Tags: `url-param` `fetch` · Subagent: SR-A

Candidate names include `url`, `uri`, `dest`, `redirect`, `src`, `source`, `feed`, `host`, `path`, `load`, `fetch`, `proxy`, `image`, `img`, `avatar`, `callback`, `webhook`, `next`, `return`, `site`, `domain`, `endpoint`, `server`, `link`, `preview`, `file`, `document`, `template`, `reference`, `base`. The full list is in `references/ssrf_param_names.txt`. Check GET, form, JSON and multipart. Start with OOB. Then send internal candidates.

```bash
python3 -I $S/ssrf_probe.py --target example.com --url "$T/fetch?url=FUZZ" --mode oob --collab "$COLLAB"
python3 -I $S/ssrf_probe.py --target example.com --url "$T/fetch?url=FUZZ" --mode internal --cloud aws
```
- **Fail:** HTTP hit from the target's infrastructure, or internal content or differential. **Pass:** only allowed destinations are fetched; internal destinations get a generic rejection.
- **Refs:** `PS-SSRF` (labs: basic SSRF against the local server / another back-end system) · `WSTG-SSRF`

### SR-02 · File import from URL — `HIGH` · O/R
Tags: `import` `remote-upload` · Subagent: SR-A

"Import from URL", "upload from link", CSV, contacts or calendar import, Git, SVN or Mercurial repository import, OpenAPI/Swagger "load from URL", RSS and feed readers, backup restore from URL. Repository imports have produced several GitLab SSRFs.
- **Refs:** HackerOne "SSRF vulnerability in gitlab.com via project import" · `HT`

### SR-03 · Webhook URL configuration — `HIGH` · O/R
Tags: `webhook` `integration` · Subagent: SR-A

Webhooks, Slack/Teams connectors, "test webhook" buttons, notification callbacks, payment and IPN URLs, CI integrations. These are often blind, retried and long-lived, which makes them ideal for redirect and rebinding (SR-10/09/17). Check whether delivery logs or test results show the response body.
- **Refs:** HackerOne "SSRF in CI after first run" · "GitLab::UrlBlocker validation bypass leading to full SSRF" · `PS-BLIND`

### SR-05 · Image processing / fetch from URL — `HIGH` · O/R
Tags: `image-proxy` `avatar` · Subagent: SR-A

Avatar-by-URL, image resize, crop or cache proxies (`/720,fit/https://...`), thumbnailers, link-preview images. Responses may come back as an image, so look for size or dimension differences. Image-only readers can still prove reach with a known internal image, such as Confluence `/images/icons/linkext7.gif`.
- **Refs:** [realworld_ssrf_reproduction_guide.md](realworld_ssrf_reproduction_guide.md) §1 · community tip (image-only blind SSRF)

### SR-18 · Blind SSRF via out-of-band DNS/HTTP — `MEDIUM–HIGH` · O
Tags: `blind` `oob` · Subagent: SR-A

Use labelled variants (`ssrf_probe.py --mode oob`) so each hit names the URL form that worked. **DNS only** means resolution or prefetch, which is INFO. **HTTP** means a server-side fetch: record the source IP, ASN and User-Agent (`Java/1.8`, `python-requests`, `Go-http-client`, `curl`, `wkhtmltopdf`, `HeadlessChrome`). Blind SSRF with no internal reach is usually Low or Medium. Escalate with SR-40/54.

```bash
python3 -I $S/ssrf_listener.py --port 8000 --bind 0.0.0.0     # on YOUR VPS, behind TLS if needed
```
- **Refs:** `PS-BLIND` (lab: blind SSRF with out-of-band detection) · Wallarm "Blind SSRF exploitation" · canarytokens.org when you lack a VPS

### SR-31 · SSRF-prone feature and parameter inventory — `—` · O
Tags: `inventory` · Subagent: SR-A

Map features before payloads:
- link previews and unfurlers
- screenshot and website-to-PDF tools
- "fetch title" for bookmarks
- oEmbed
- RSS
- avatars
- document converters
- payment and OAuth integrations (`redirect_uri` back-channel, `jwks_uri`, `logo_uri`)
- monitoring and uptime checkers
- "test connection" for SMTP, LDAP, DB or S3 settings
- data import
- report generation
- backup restore
- admin "proxy" endpoints
- WordPress `xmlrpc.php` pingback
- `/_includes/framer.php?base=`-style legacy endpoints

Grep URL archives:

```bash
grep -iE '[?&](url|uri|dest|redirect|src|source|feed|host|proxy|image|img|callback|webhook|next|return|site|endpoint|link|preview|file|load|fetch|base)=' artifacts/all_discovered_urls.txt | sort -u > artifacts/ssrf/candidates.txt
```
- **Refs:** `HT` · `WSTG-SSRF` · jdonsec/AllThingsSSRF

### SR-32 · Header-based SSRF (Referer, X-Forwarded-*, Host-like headers) — `MEDIUM–HIGH` · O
Tags: `headers` `analytics` · Subagent: SR-A

Analytics and anti-fraud backends fetch the `Referer`. Some apps fetch or resolve these headers:
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `Client-IP`, `True-Client-IP`
- `Forwarded`, `X-Original-URL`, `X-Wap-Profile`, `Contact`, `From`

Use Burp Intruder with a header list (or Param Miner), with a collaborator value numbered per header. Collaborator Everywhere / Taborator show the hits.

```bash
python3 -I $S/ssrf_probe.py --target example.com --url "$T/" --header "Referer: FUZZ" --mode oob --collab "$COLLAB"
```
- **Refs:** `PS-BLIND` (lab: blind SSRF with Shellshock via Referer) · `HT` (SSRF via Referer)

### SR-33 · Routing-based SSRF (Host header / absolute URI) — `HIGH–CRITICAL` · O/R
Tags: `host-header` `reverse-proxy` · Subagent: SR-A

Reverse proxies and load balancers that route on `Host` or on an absolute request line (`GET http://internal/ HTTP/1.1`). Steps:
1. Send `Host: $COLLAB` to confirm the proxy routes on it.
2. Try `Host: 192.168.0.X` to reach internal admin panels.
3. Check flawed request parsing and connection-state reuse: send a legitimate first request, then a malicious one on the same connection.
- **Refs:** `PS-ROUTE` (labs: routing-based SSRF, SSRF via flawed request parsing) · James Kettle "Cracking the lens"

### SR-51 · OAuth / OIDC / SAML federation fetchers — `HIGH` · O/R
Tags: `oidc` `dcr` `saml` · Subagent: SR-A

Dynamic Client Registration fields:
- `logo_uri`, `jwks_uri`, `sector_identifier_uri`
- `request_uris` / `request_uri`

Other back-channel fetches:
- OIDC discovery / webfinger
- SAML metadata URL import, IdP auto-config

These are fetched server-side, often unauthenticated.
- **Refs:** PortSwigger lab "SSRF via OpenID dynamic client registration" · `oauth-sso` OA checks

---

## SR-B — Document & Media Renderers

### SR-04 · PDF generators with external images — `HIGH` · O/R
Tags: `pdf` `wkhtmltopdf` · Subagent: SR-B

Invoice, report and "export to PDF" features built on HTML (wkhtmltopdf, headless Chrome, PhantomJS, Prince, WeasyPrint). Inject `<img src=//$COLLAB>` in any field that reaches the template. If scripts run, use `html_render.html` (fetch and document.write).

```bash
python3 -I $S/ssrf_files.py --out artifacts/ssrf/files --collab "$COLLAB" --internal-proof
```
- **Refs:** Appsecco "Finding SSRF via HTML injection inside a PDF file on AWS EC2" · bughunter25 "HTML to PDF converter SSRF" · HackerOne "Bypassing HTML filter in Packing Slip Template lead to SSRF to internal Kubernetes endpoints"

### SR-06 · SVG import with external references — `HIGH` · O/R
Tags: `svg` `xlink` · Subagent: SR-B

The SVG reference vectors are `<image xlink:href>`, `<use>`, `<feImage>`, `@import`, `@font-face` and `<script xlink:href>`, all in `svg_refs.svg`. Rasterisers include ImageMagick, librsvg, Batik, CairoSVG and Inkscape. Fingerprint library versions by fetching local files that exist only in certain versions: `find /usr -name "*.png"` in a matching container builds the wordlist.
- **Refs:** allanlw/svg-cheatsheet · arbazhussain "SVG xlink SSRF – fingerprinting libraries version" · 0xn3va SVG abuse

### SR-19 · PDF export with embedded resource URLs — `HIGH` · O/R
Tags: `pdf-export` `iframe` · Subagent: SR-B

The same renderer as SR-04, reached through user-controlled resource URLs. Examples: logo URL in settings, "add image by URL" in rich text, CSS URL themes, `<link rel=import>`, `<iframe src>`. The internal proof (`html_render_internal.html`) shows only `instance-id` and `/etc/hostname`.
- **Refs:** "Exploiting HTML-to-PDF converters through HTML imports" · HackTricks *Server-side XSS (dynamic PDF)* · `xss` XS-30

### SR-28 · SVG `@font-face` / CSS URI loading — `MEDIUM–HIGH` · O
Tags: `svg-font` `css` · Subagent: SR-B

`@font-face { src: url(//$COLLAB/x.woff) }` and `@import` inside SVG/HTML `<style>`. These are fetched even by renderers that block `<image>`.
- **Refs:** allanlw/svg-cheatsheet · cure53/HTTPLeaks

### SR-29 · XXE to SSRF — `HIGH–CRITICAL` · O/R
Tags: `xxe` `xml` · Subagent: SR-B

XML bodies (SOAP, SAML, RSS, Office files, SVG, `Content-Type: application/xml` swap on JSON endpoints). Use external entities and parameter-entity DTDs pointing at `$COLLAB`, then at internal URLs (`http://169.254.169.254/latest/meta-data/instance-id`). File reads go through `path-traversal` classes.

```bash
python3 -I $S/ssrf_files.py --out artifacts/ssrf/files --collab "$COLLAB"     # xxe_oob.xml
```
- **Refs:** `PS-XXE` (labs: exploiting XXE to perform SSRF, blind XXE OOB) · `PATT`

### SR-47 · Screenshot tools, link unfurlers, headless browsers — `HIGH` · O/R
Tags: `headless` `screenshot` `unfurl` · Subagent: SR-B

Headless Chrome/Puppeteer fetches the target and runs its JavaScript. An attacker page can then:
- `fetch()` internal URLs
- redirect to internal pages
- try `http://127.0.0.1:9222/json` (DevTools; report reach, do not drive it)

The screenshot returns the content.
- **Refs:** `HT` (PDF/headless) · Detectify "SSRF vulnerabilities and where to find them"

### SR-48 · Office / spreadsheet conversions — `MEDIUM–HIGH` · O
Tags: `xlsx` `webservice` `ooxml` · Subagent: SR-B

Formula-evaluating converters (XLSX/CSV to PDF or HTML via Excel or LibreOffice) run `=WEBSERVICE("http://$COLLAB/")`, `=IMAGE()` and `=IMPORTXML()`. OOXML external relationships (`TargetMode="External"`) and `attachedTemplate` fetch on open or convert. See `webservice.csv` and `ooxml_note.txt`.
- **Refs:** intigriti WEBSERVICE tip · community tip (XLSX→PDF via Excel)

### SR-49 · Media processing (FFmpeg HLS, ImageMagick, video converters) — `HIGH` · O/R
Tags: `ffmpeg` `imagemagick` · Subagent: SR-B

FFmpeg follows HLS playlists (`hls.m3u8` → `$COLLAB`). AVI+M3U tricks read local files: class R, benign files only. For ImageMagick, test URL coders (`url:`, `http:`), MSL/MVG and SVG delegates. Report only file reads limited to benign files.
- **Refs:** "Attacks on video converters: a year later" · HackerOne "SSRF and local file disclosure in wordpress.com/media/videos via FFmpeg HLS" · neex/ffmpeg-avi-m3u-xbin

### SR-50 · XML processors: XInclude, XSLT `document()`, WS-Addressing — `HIGH` · O/R
Tags: `xinclude` `xslt` `soap` · Subagent: SR-B

When you control only part of an XML document, use XInclude. XSLT upload or transform features fetch through `document('http://$COLLAB')`. SOAP `wsa:ReplyTo` / `FaultTo` cause callback fetches.
- **Refs:** `PS-XXE` (lab: XInclude) · `PATT` (XSLT)

---

## SR-C — Filter Bypass: IP Formats & DNS

Generate every form with `ssrf_payloads.py --target 127.0.0.1` or `--target 169.254.169.254`. All IPv4 forms are verified to decode through `inet_aton`.

### SR-11 · URL encoding of IP restrictions — `MEDIUM–HIGH` · R
Tags: `url-encoding` · Subagent: SR-C

Percent-encode the host or path (`http://%31%32%37.0.0.1/`, `%2e`), double-encode for proxies that decode twice, and encode only some octets. A `127.0.0.1%2f` style suffix confuses validators that decode once.
- **Refs:** `PS-URL` · `PATT`

### SR-12 · IPv6 addresses (::1, ::ffff:127.0.0.1) — `HIGH` · R
Tags: `ipv6` · Subagent: SR-C

`[::1]`, `[0000::1]`, `[::]`, `[0:0:0:0:0:0:0:1]`, `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`, `[::127.0.0.1]` (compat), NAT64 `[64:ff9b::7f00:1]`, and a zone id (`%25eth0`). For metadata, also `[::ffff:a9fe:a9fe]`, and AWS IPv6 IMDS `[fd00:ec2::254]` on Nitro.
- **Refs:** `PATT` · `HT`

### SR-13 · Decimal IP (2130706433) — `HIGH` · R
Tags: `decimal-ip` · Subagent: SR-C

`http://2130706433/` is 127.0.0.1. `http://2852039166/` is 169.254.169.254. `http://3232235521/` is 192.168.0.1.
- **Refs:** `PATT`

### SR-14 · Octal IP (0177.0.0.1) — `HIGH` · R
Tags: `octal-ip` · Subagent: SR-C

Use `0177.0.0.1`, `0177.0000.0000.0001`, dotless `017700000001`, metadata `0251.0376.0251.0376`, and partial encoding (one octet only, e.g. `0251.254.169.254`). Partial encoding was the reported $160k metadata bypass.
- **Refs:** community tip (partial octet encoding) · `PATT`

### SR-15 · IPv6-mapped IPv4 (0:0:0:0:0:ffff:7f00:1) — `HIGH` · R
Tags: `ipv4-mapped` · Subagent: SR-C

Use the expanded, compressed, hex and dotted mapped forms. Validators that call `ip.is_private` on the IPv6 object sometimes miss mapped loopback.
- **Refs:** `PATT` · Python `ipaddress` mapped-address pitfalls

### SR-16 · Alternate encoding schemes (hex, mixed, short, Unicode) — `HIGH` · R
Tags: `hex-ip` `short-ip` `enclosed-alphanumerics` · Subagent: SR-C

Forms to try:
- **Hex:** `0x7f000001`, `0x7f.0x0.0x0.0x1`, padded hex
- **Mixed:** `0x7f.0.0.1`, `00177.0x0.1`
- **Short:** `127.1`, `127.0.1`, `0`
- **Overflow (legacy):** `383.256.256.257`
- **Unicode:** enclosed alphanumerics `①②⑦.⓪.⓪.①`, full-width digits, ideographic dots `127。0。0。1`, and IPv6 plus Unicode (`[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。①⑥⑨。②⑤④]`)

Some resolvers return nothing for weird forms, so a blocklist check on the resolved IPs passes. Ruby's `Resolv::getaddresses("0x7f.1")` returning `[]` is the classic case.
- **Refs:** `PATT` · `HT` · HackerOne "Blind SSRF in Integrations by abusing a bug in Ruby's native resolver"

### SR-36 · Shorthand, padded and partially encoded IPs — `HIGH` · R
Tags: `inet_aton` · Subagent: SR-C

Mix forms per octet: dotted octal for one octet, hex for another, extra zeros (`127.000000000000.1`), alternate loopbacks (`127.127.127.127`, `127.0.1.3`, `127.0.0.0`). Blocklists often only list `127.0.0.1`.
- **Refs:** cujanovic/SSRF-Testing · m4ll0k localhost bypass list

### SR-37 · Unicode / IDNA normalisation of hosts — `MEDIUM–HIGH` · R
Tags: `idna` `unicode` · Subagent: SR-C

Hostnames normalised after validation:
- full-width letters (`ⓛⓞⓒⓐⓛⓗⓞⓢⓣ`)
- `ß` → `ss`
- ideographic and full-width dots
- `\u2044` fraction slash
- `\uff03` full-width `#` as a fake delimiter

Send raw and `--percent-unicode` forms.
- **Refs:** `HT` (URL format bypass) · `ORANGE`

### SR-38 · DNS names that resolve internally — `HIGH` · R
Tags: `wildcard-dns` · Subagent: SR-C

Third-party test services:
- `127.0.0.1.nip.io`
- `127-0-0-1.sslip.io`
- `make-127-0-0-1-rr.1u.ms`
- `localtest.me` (and any subdomain)
- `169.254.169.254.nip.io`
- `spoofed.burpcollaborator.net`
- historical internal-resolving names

Best of all: an A record on **your own domain** pointing at the internal IP. These bypass hostname-string blocklists that do not check the resolved address.
- **Refs:** `PATT` · `HT`

---

## SR-D — Filter Bypass: Parsers, Redirects & Rebinding

### SR-09 · DNS rebinding for filter bypass (TOCTOU) — `HIGH` · R
Tags: `dns-rebinding` `toctou` · Subagent: SR-D

The validator resolves once and the client resolves again. Use `make-<public>-rebind-<internal>-rr.1u.ms` (first answer public, second internal) or rbndr.us (`<hex1>.<hex2>.rbndr.us`, random). Repeat about 20 times. Success is internal content or a differential.

```bash
python3 -I $S/ssrf_payloads.py --target 169.254.169.254/latest/meta-data/instance-id --families rebind --rebind-from YOUR.PUBLIC.IP
```
- **Refs:** neex/1u.ms · lock.cmpxchg8b.com rbndr · HackerOne "GitLab DNS rebinding protection bypass"

### SR-10 · Redirect-based bypass (30x) — `HIGH` · R
Tags: `redirect` · Subagent: SR-D

The filter validates your host. The client follows `Location:` to an internal address. Try all of 301, 302, 303, 307 and 308. Cross-scheme redirects can also reach `file://` and `gopher://` in older libcurl. Use base64 targets (`/r?b64=`) so the internal address never appears in the submitted URL. URL shorteners and webhook-mock services work too.

```bash
python3 -I $S/ssrf_listener.py --port 8000 --bind 0.0.0.0 --allow-redirect-host 127.0.0.1,169.254.169.254
python3 -I $S/ssrf_payloads.py --target 169.254.169.254/latest/meta-data/instance-id --families redirect --redirector https://YOU/r
```
- **Refs:** `PS-SSRF` (lab: SSRF with filter bypass via open redirection) · `PATT`

### SR-17 · DNS rebinding to internal IPs (pinned / cached resolvers) — `HIGH` · R
Tags: `dns-rebinding` `multi-a` · Subagent: SR-D

Variants:
- multiple A records (`make-<pub>-and-<internal>-rr.1u.ms`), letting the client pick
- TTL-0 answers against resolvers that cache only the validation lookup
- long-lived workers (webhook retries, crawlers) that resolve again on each delivery
- IPv6 AAAA versus A preference differences
- **Refs:** neex/1u.ms · `OWASP-CS` (DNS pinning)

### SR-20 · HTTP method override — `MEDIUM` · R
Tags: `method` `override` · Subagent: SR-D

A validator may apply only on `POST /fetch` while `GET`, `PUT` or `PATCH`, or `X-HTTP-Method-Override` / `_method=`, reach the same fetch code unvalidated. Also check whether the fetcher's method can be chosen. For example, a `PUT` makes IMDSv2 token retrieval possible (SR-44).
- **Refs:** `access-control` PE method-override checks · `PATT`

### SR-21 · Fragmented URLs for parser confusion — `HIGH` · R
Tags: `fragment` `userinfo` · Subagent: SR-D

Forms:
- `http://127.0.0.1#@allowed.com/`, `http://127.0.0.1%23@allowed.com`
- `http://allowed.com#.127.0.0.1`
- `http://127.0.0.1?allowed.com`
- `http://127.0.0.1/allowed.com`
- `http://127.0.0.1%00allowed.com`
- `http://127.0.0.1:80?http://allowed.com/` (the "valid YouTube URL" case)

```bash
python3 -I $S/ssrf_payloads.py --target 127.0.0.1 --families parser --allowed-host allowed.example.com
```
- **Refs:** `PS-URL` · community tip (`?http://youtu.be/...` suffix)

### SR-22 · Parser differences between libraries — `HIGH` · R
Tags: `parser-differential` · Subagent: SR-D

Validator and client parse the same string differently. Examples:
- **Backslashes:** `http://127.1.1.1:80\@127.2.2.2:80/`, `http:\\host`
- **Double `@`:** `http://foo@evil:80@allowed/`
- **Space or tab:** `evil%09allowed`, `foo@evil%20@allowed`
- **Several hosts in one URL:** `1.1.1.1 &@2.2.2.2# @3.3.3.3/`
- **Scheme-less and odd slashes:** `//host`, `/\/\host`, `http:/host`
- **Parameter pollution:** `next=allowed&next=evil`

Note which form your hit came from. `ssrf_probe.py --mode oob` labels them.
- **Refs:** `ORANGE` · Orange Tsai's Tiny URL Fuzzer · "Fixing the Unfixable: Story of a Google Cloud SSRF" · "URL whitelist bypass in cxl-services.appspot.com"

### SR-26 · `@` userinfo for authentication/allowlist bypass — `HIGH` · R
Tags: `userinfo` · Subagent: SR-D

`http://allowed.com@127.0.0.1/`, `http://allowed.com:80@127.0.0.1`, `https://allowed.com%6D@evil`. Also use embedded credentials to log in to internal Basic-auth services: `http://user:pass@internal/`. Only use defaults the program documents, and never brute force.
- **Refs:** `PS-URL` · community tip (embedded credentials)

### SR-27 · Path truncation / appended-suffix bypass — `MEDIUM–HIGH` · R
Tags: `suffix` `truncation` · Subagent: SR-D

Some servers append a path or extension to your URL, or prepend their host. Countermeasures:
- **Appended text:** neutralise it with `#`, `?`, `%23`, `%3F` or `%00`.
- **Length limits:** very long paths truncate the appended part.
- **Prefixed host** (`https://their.host` + input): inject `@internal/`, `.internal`, or `/%2F//evil/` (reported to hit external hosts).
- **Refs:** community tips (`#` suffix killer, `/%2F//`) · `PATT`

### SR-30 · HTTP/HTTPS protocol switching — `MEDIUM` · R
Tags: `scheme-switch` · Subagent: SR-D

Allowlists may check only `https://`. Try `http://` (and the reverse), uppercase `HTTP://`, `https://host:80`, `http://host:443`, scheme-relative `//host`, missing slashes (`https:host`, `https:/host`), and redirects that switch scheme.
- **Refs:** `PATT` · `HT`

### SR-34 · Chaining the target's own open redirect — `HIGH` · R
Tags: `open-redirect` `chain` · Subagent: SR-D

Allowlists that permit the target's own domain plus an open redirect on that domain equal arbitrary fetch (`/next?path=http://192.168.0.12:8080/admin`). Combine with the `open-redirect` findings.
- **Refs:** `PS-SSRF` (lab: SSRF with filter bypass via open redirection vulnerability)

### SR-35 · Allowlist/blocklist logic mapping — `—` · R
Tags: `filter-model` · Subagent: SR-D

Work out what the filter does before bypassing:
- **Blocklist or allowlist:** which hosts get rejected, and which are the only ones accepted?
- **What it checks:** string `contains` / `startsWith` / regex anchored or not, or the resolved IP.
- **Redirects:** checked once or per redirect?
- **Error messages:** do they differ between DNS failure, connection refused and blocked?

`ssrf_probe.py --mode internal` groups identical "block page" responses so the filter's answer stands out.
- **Refs:** `OWASP-CS` · `PS-SSRF` (labs: blacklist-based and whitelist-based input filters)

### SR-45 · CRLF / request splitting in the fetched URL — `HIGH` · R/W
Tags: `crlf` `request-splitting` · Subagent: SR-D

`%0d%0a` in the path or host can inject headers into the outbound request. Node.js Unicode request splitting (`\u{010D}\u{010A}`) and old Python urllib CVEs are examples. This can add `Metadata-Flavor: Google` / `Metadata: true` or turn a GET into a second request. Prove it with header echo on your own host before going internal.
- **Refs:** rfk "Security bugs in practice: SSRF via request splitting" · `HT`

### SR-46 · Protocol-level tricks: HTTP/0.9, missing Host, SNI — `MEDIUM` · R
Tags: `http09` `sni` · Subagent: SR-D

Things to try:
- **Proxy fixes:** downgrade to `HTTP/0.9` or `HTTP/1.0` without `Host` to bypass fixes that keyed on Host.
- **SNI routing:** `openssl s_client -connect target:443 -servername internal.host -crlf` on TLS terminators that route by SNI.
- **Absolute-URI request lines:** combine with SR-33.
- **Refs:** community tip (HTTP/0.9, no Host) · `HT` (SSRF via SNI)

---

## SR-E — Cloud & Container Metadata

### SR-08 · Cloud metadata endpoints (169.254.169.254) — `CRITICAL` · R (S gated)
Tags: `imds` `metadata` · Subagent: SR-E

Reach is proven by `instance-id`, `ami-id`, `hostname`, or the role **name** listing (`iam/security-credentials/`). The proof stops there. The credentials path is class S: describe it as the escalation path.

```bash
python3 -I $S/ssrf_payloads.py --families metadata --cloud aws,gcp,azure
python3 -I $S/ssrf_probe.py --target example.com --url "$T/fetch?url=FUZZ" --mode internal --cloud aws
```
- **Refs:** `PS-SSRF` · Christophe Tafani-Dereeper "Abusing AWS metadata service using SSRF" · AWS IMDS docs

### SR-24 · AWS / Azure / GCP metadata APIs — `CRITICAL` · R (S gated)
Tags: `aws` `azure` `gcp` · Subagent: SR-E

- **AWS IMDSv1:** plain GET. **IMDSv2** needs `PUT /latest/api/token` and a header, so it is usually safe from simple SSRF.
- **GCP:** `Metadata-Flavor: Google` (legacy `v1beta1` needed none, and `?recursive=true` dumps everything: class S).
- **Azure:** `Metadata: true` plus `api-version`.

Record whether the header requirement blocked you. That shows defence in depth working, so it isn't a finding.
- **Refs:** cloud provider IMDS documentation · `PATT` (cloud metadata) · community tip (GCP `v1beta1/?recursive=true`, S)

### SR-25 · Internal Kubernetes services — `CRITICAL` · R (S gated)
Tags: `kubernetes` `kubelet` `etcd` · Subagent: SR-E

Endpoints to check:
- `https://kubernetes.default.svc/version` and `/metrics`; unauthenticated metrics output means the API server is reachable
- kubelet `:10250/pods` and read-only `:10255`
- etcd `:2379/version`
- cluster DNS names (`*.svc.cluster.local`)
- service-account token file reads (`file:///var/run/secrets/...`): class S

Proof stops at version or metrics.
- **Refs:** community tip (`kubernetes.default.svc/metrics`) · HackerOne packing-slip report (internal Kubernetes endpoints)

### SR-42 · Container and serverless metadata (ECS, Lambda, Docker, Consul) — `CRITICAL` · R (S gated)
Tags: `ecs` `lambda` `docker` · Subagent: SR-E

- **ECS:** task metadata `169.254.170.2/v4/`. Credentials at `/v2/credentials/<GUID>` need `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` from `/proc/self/environ`, which is class S.
- **Lambda:** runtime API `localhost:9001/2018-06-01/runtime/invocation/next` (event data, class S).
- **Docker:** API on `:2375/version`. It is reach-only: never `POST /containers`.
- **Consul:** `:8500/v1/agent/self`.
- **Nomad and Vault:** `:4646`, `:8200`.
- **Refs:** RhinoSecurity Lambda tip · community ECS tip

### SR-43 · Other cloud providers — `HIGH–CRITICAL` · R (S gated)
Tags: `oracle` `alibaba` `digitalocean` · Subagent: SR-E

- **Oracle:** `169.254.169.254/opc/v2/` (needs `Authorization: Bearer Oracle`), legacy `192.0.0.192`
- **Alibaba:** `100.100.100.200/latest/meta-data/`
- **DigitalOcean:** `/metadata/v1/`
- **OpenStack:** `/openstack/latest/meta_data.json`
- **Others:** Hetzner, Tencent `metadata.tencentyun.com`, Packet `metadata.packet.net`, IBM, HP Helion `/2009-04-04/meta-data/`

`ssrf_payloads.py --families metadata` lists the benign paths per provider.
- **Refs:** `PATT` (cloud metadata list)

### SR-44 · Header/method requirements and IMDSv2 assessment — `—` · R
Tags: `imdsv2` `defence` · Subagent: SR-E

Can the SSRF primitive:
- set headers (CRLF SR-45, header-forwarding proxies, Linkerd `l5d-dtab`)?
- choose the method (PUT for the IMDSv2 token)?
- follow redirects with method preserved (307/308)?

This decides whether IMDSv2 or GCP/Azure header checks actually protect the host. Report the answer either way.
- **Refs:** AWS IMDSv2 docs · `OWASP-CS`

---

## SR-F — Internal Network, Protocols & Impact

### SR-07 · Internal IP addresses (127.0.0.1, 10.x, 172.16-31.x, 192.168.x) — `HIGH` · R (N gated)
Tags: `loopback` `rfc1918` · Subagent: SR-F

Loopback first: the local web server, admin paths such as `localhost/admin` (PortSwigger), and `localhost/phpmyadmin`. Then a **few** likely internal hosts named in JS, headers or errors (`10.0.0.1:8080`, `192.168.0.1`). Sweeping subnets is class N. Use differential responses when the body is not reflected.
- **Refs:** `PS-SSRF` (labs: basic SSRF against the local server / another back-end system) · `WSTG-SSRF`

### SR-23 · `file://` local file read — `HIGH–CRITICAL` · R (S gated)
Tags: `file-scheme` · Subagent: SR-F

`file:///etc/hostname`, the first line of `file:///etc/passwd`, and `file:///C:/Windows/win.ini`. Bypass variants:
- `file://\/\/etc/passwd`
- `file:/etc/passwd?/`
- `file:///etc/?/../passwd`
- `file://localhost/etc/passwd`
- Java `url:file:///`, `netdoc:///`
- Node on Windows: single-letter schemes (`l://...` → `file:`)

Secret files (`/proc/self/environ`, keys, configs) are class S. File classes follow `path-traversal`.
- **Refs:** community tips (`file://\/\/`) · Rodolfo Assis "On SSRF" · `PATT`

### SR-39 · Non-HTTP schemes (gopher, dict, ftp, sftp, tftp, ldap, jar) — `HIGH` · O (W gated)
Tags: `gopher` `dict` `schemes` · Subagent: SR-F

First test scheme **support** against your own host (`ssrf_probe.py --mode oob` sends gopher, dict, ldap, ftp, jar and UNC labels to `$COLLAB`). Internal protocol interaction is class W and report-only:
- Redis / memcached / SMTP / FastCGI / MySQL via gopher (Gopherus)
- `dict://127.0.0.1:6379/info`
- RMI (remote-method-guesser)

Never send state-changing payloads such as `CONFIG SET`, `SLAVEOF`, cron or webshell writes.
- **Refs:** `PATT` (schemes) · Gopherus · Agarri "Server-side browsing considered harmful"

### SR-40 · Internal port and service fingerprinting (bounded) — `MEDIUM–HIGH` · R (N gated)
Tags: `port-scan` `differential` · Subagent: SR-F

On one host, at most 30 common ports. Compare status, size and time with a closed-port reference:
- **SSH:** `SSH-2.0` banner on 22
- **Redis:** `-ERR` on 6379
- **Web services:** Tomcat/Jenkins on 8080, Node on 3000, Elasticsearch on 9200
- **Cloud and container APIs:** Consul on 8500, Docker on 2375, kubelet on 10250
- **Bitbucket:** 7990 (the Jira SSRF to internal Bitbucket path)
- **Chrome DevTools:** 9222

```bash
python3 -I $S/ssrf_probe.py --target example.com --url "$T/fetch?url=FUZZ" --mode ports --host 127.0.0.1
```
- **Refs:** [realworld_ssrf_reproduction_guide.md](realworld_ssrf_reproduction_guide.md) §2 · Cobalt "From SSRF to port scanner"

### SR-41 · Internal admin panels and APIs (read-only) — `HIGH–CRITICAL` · R (W gated)
Tags: `admin` `actuator` · Subagent: SR-F

Read-only GETs only:
- `localhost/admin` (PortSwigger: deleting a user is W, so do not do it)
- Spring actuator `/actuator/env` (class S if secrets appear), `/actuator/health`
- Jenkins `/api/json`, Consul, Elasticsearch `/_cat/indices` (names only), Solr admin, Kibana, Grafana
- Confluence `/images/icons/linkext7.gif`
- Bitbucket `:7990` public repos via a Jira SSRF

Report what an attacker could do. Do not do it.
- **Refs:** `PS-SSRF` (lab: SSRF against the local server, admin delete — demonstrate access only) · wya.pl "Bring your own SSRF – the gateway actuator"

### SR-52 · Known SSRF-prone products and proxy headers — `HIGH` · O/R
Tags: `cve` `linkerd` `products` · Subagent: SR-F

Product endpoints:
- **Jira:** `/plugins/servlet/gadgets/makeRequest?url=` (CVE-2019-8451)
- **Confluence:** widget connector
- **GitLab:** imports and integrations
- **WordPress:** `xmlrpc.php` `pingback.ping`
- **Next.js:** `/_next/image?url=`
- **Grafana:** avatar (CVE-2020-13379)
- **ColdFusion:** `cfhttp`-based tags
- **Apache:** `mod_proxy` unix-socket SSRF (CVE-2021-40438)
- **Spring Cloud Gateway:** actuator routes
- **Legacy:** `/_includes/framer.php?base=`

Service-mesh headers:
- **Linkerd:** `l5d-dtab: /svc/* => /$/inet/$COLLAB/80` (look for `Via: linkerd` / `l5d-*`)
- **Envoy / Istio:** overrides such as `x-envoy-original-dst-host`
- **Refs:** community tips (Linkerd dtab, framer.php) · hoyahaxa "SSRF in ColdFusion/CFML tags and functions" · `server-config-audit`

### SR-53 · Windows UNC paths and WebDAV — `MEDIUM–HIGH` · O
Tags: `unc` `smb` `ntlm` · Subagent: SR-F

Replace a file path or URL with `\\$COLLAB\x`, `\\$COLLAB@80\x` (WebDAV over HTTP) or `file://$COLLAB/x`. A DNS or SMB or HTTP hit proves outbound reach and possible NTLM credential exposure. **Do not** run Responder to capture, crack or relay hashes. Note the risk in the report.
- **Refs:** community tips (UNC, Responder: not used here) · `path-traversal` PT UNC checks

### SR-54 · Blind SSRF impact amplification (safe) — `MEDIUM–HIGH` · R
Tags: `blind` `oracle` · Subagent: SR-F

Turn a blind fetch into evidence without exploitation:
- **Timing and status oracle:** open versus closed internal ports (SR-40), existing versus missing internal hosts.
- **Image-only reads:** known internal static images.
- **Redirect-to-internal:** with a differential.

Shellshock or command-injection payloads in headers to internal hosts (the PortSwigger Shellshock lab) are class W. Only with explicit permission, and only with an OOB `nslookup` marker.
- **Refs:** Wallarm "Blind SSRF exploitation" · `PS-BLIND` · notifybugme "Chaining a blind SSRF to RCE" (escalation path)

### SR-55 · Command / template injection through fetched URLs and forms — `HIGH–CRITICAL` · O
Tags: `cmd-injection` `ssti` · Subagent: SR-F

Fetchers that shell out (`curl $url`, `wget`) can run `` `id` `` in the URL. Keep the marker inert: `http://$COLLAB/?x=$(echo bbtest)` and `` `echo bbtest` ``, then watch for `bbtest` in the path received. The wget filename trick and argument injection (`-o`, `--output-document`) belong to their own skills. If a public form produces blind SSRF hits, also try SSTI markers there. Hand off any execution to the relevant skill.
- **Refs:** HackTricks (SSRF with command injection, wget file upload) · secureitmania "Unknown Linux secret that turned SSRF to OS command injection"

---

## White-box appendix — defensive architecture (CONFIG_REVIEW)

These were checks 18–25 of the v1 tracker. Assess them only with code or infrastructure access, or infer them from black-box results.

| ID | Control | What good looks like |
|---|---|---|
| WB-1 | Resolve-then-pin | Resolve once, validate **every** resolved IP (v4 + v6, mapped forms), connect to that IP; no second lookup |
| WB-2 | Strict allowlist | Exact host (and scheme/port) allowlist after canonical parsing with the same parser as the client; no `contains`/regex prefix checks |
| WB-3 | Redirect policy | Redirects disabled, or each hop re-validated (same rules), scheme changes refused |
| WB-4 | Scheme restriction | Only `http`/`https`; `file`, `gopher`, `dict`, `ftp`, `ldap`, `jar`, `netdoc` disabled in the client library |
| WB-5 | Egress control | Fetchers run in an isolated network / through an egress proxy that denies RFC 1918, loopback, link-local, metadata, IPv6 ULA/link-local |
| WB-6 | Metadata hardening | AWS IMDSv2 required with hop limit 1; GCP/Azure header requirements; ECS task-role scoping; workload identity in k8s |
| WB-7 | Response handling | Responses not reflected; size, time and content-type limits; generic errors that do not distinguish refused/timeout/blocked |
| WB-8 | Internal service auth | Redis, Elasticsearch, Docker, kubelet, actuator, admin panels require authentication even from localhost |

- **Refs:** `OWASP-CS` · AWS IMDSv2 · Google "SSRF prevention" guidance

---

## Tracker

| ID | Status | Class done | Severity | Evidence |
|---|---|---|---|---|
| SR-01 … SR-55, WB-1 … WB-8 | | | | |
