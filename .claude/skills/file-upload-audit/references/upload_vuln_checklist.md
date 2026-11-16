# File Upload Vulnerabilities Checklist (FU, 20 checks)

Extends `upload_checks.md` (UP-*). Class key: `passive` = config, version, and response review. `bounded` = harmless test files (markers, arithmetic, `alert(document.domain)`) on your own account, deleted afterward. `authorized-only` = anything that runs on the server, exhausts resources, or reaches other users.

Generate harmless test files with `scripts/upload_testfiles.py --out <dir> --marker <unique>` (add `--oob your.oob.host` for XXE files).

## Core checks (20)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| FU-001 | Upload | Unrestricted upload: any type accepted (.html, .svg, .php, .exe, .js) | bounded | Upload each harmless test file; record accepted types and served URL |
| FU-002 | Extension | Blacklist bypass with uncommon extensions (.php3/.php4/.php5/.php7/.phtml/.pht/.phar/.phps/.pgif/.inc, .asp/.aspx/.cer/.asa/.ashx/.asmx/.config, .jsp/.jspx/.jspf/.jsw/.jsv, .shtml, .cgi/.pl, .svgz, .xht/.xhtml, .htaccess/web.config) | bounded | Harmless marker content with each extension; check acceptance and served Content-Type |
| FU-003 | Extension | Whitelist bypass: case (`.pHp`), trailing dot/space (`file.php.`), `file.php;.jpg` (IIS), `file.php/` , `file.php::$DATA` (NTFS), `file.jpg.php`, `%20`, `%0a`, multiple dots | bounded | Harmless marker file per name variant |
| FU-004 | Extension | Double extension (`file.php.jpg`, `file.jsp.png`, `file.asp;.jpg`) relying on Apache AddHandler / misconfigured handlers | bounded | Upload `marker.php.jpg` with arithmetic marker; check if served as text or executed (execution = authorized-only follow-up) |
| FU-005 | Filename | Null byte in filename (`file.php%00.jpg`, raw `\x00`) on legacy stacks | bounded | Send name variants in the multipart `filename=`; check stored name |
| FU-006 | Content-Type | Content-Type header trusted (send `image/jpeg` with HTML/SVG/script content) | bounded | Same harmless file, spoofed multipart Content-Type |
| FU-007 | Magic bytes | Magic-byte spoofing: `GIF89a`/`\x89PNG`/`\xFF\xD8\xFF`/`%PDF` prefix on text content passes type detection | bounded | Generated `magic_*` files; check acceptance and served type |
| FU-008 | SVG | SVG with embedded script served inline on the app origin (stored XSS) | bounded | `svg_xss.svg` with `alert(document.domain)`; open the served URL in your own session |
| FU-009 | HTML | HTML upload served as `text/html` on the app origin (stored XSS, phishing) | bounded | `marker.html`; check origin (app vs sandbox domain) and Content-Type |
| FU-010 | Inclusion | Uploaded file path reachable by an include or template sink (LFI to RCE chain) | authorized-only | Find the include parameter (see path-traversal); report the chain; do not execute |
| FU-011 | Path traversal | Destination traversal via filename (`../../marker.txt`, `..%2f`, `..\\`), folder parameter, or archive name | bounded | `../marker.txt` name on own account; confirm placement, never overwrite real files |
| FU-012 | Race | Access before validation: file stored, then scanned/deleted; request it in the window | authorized-only | Approved test: one upload plus a few GETs for the temporary path |
| FU-013 | Polyglot | Polyglot accepted as image but also valid HTML/JS/PHP/PHAR (GIF+JS, JPEG+PHP comment, PDF+JS, phar-jpeg) | bounded | `polyglot.gif` (GIF with marker); check served type and whether content is rendered or interpreted |
| FU-014 | Archive | ZIP bomb (high-ratio archive) exhausts disk or CPU during extraction | authorized-only | Never upload a real bomb; check documented limits, and with approval upload a small high-ratio archive (for example 1 MB to 100 MB) |
| FU-015 | Cloud | Uploaded objects stored with public ACL, guessable keys, listable bucket, or signed URLs that do not expire | bounded | Own upload: request the object URL logged out; check bucket listing; check signed-URL expiry (see cloud-supplychain) |
| FU-016 | EXIF | Image metadata (EXIF, IPTC, XMP, JPEG comment) with XSS marker rendered unescaped by gallery, admin, or metadata viewer | bounded | `exif_xss.jpg` (JPEG comment marker) or `exiftool -Comment='<marker>' img.jpg`; view where metadata is displayed |
| FU-017 | Size | Oversized files: no size limit, or limit enforced only client-side or after full receipt (DoS) | bounded | One upload at limit + 1 MB; never large floods (see resource-exhaustion) |
| FU-018 | Documents | Malicious metadata in documents (DOCX/XLSX/PDF author, title, custom props) rendered unescaped, or macros/DDE accepted and redistributed | bounded | Own DOCX with marker in title/author; check preview and listings |
| FU-019 | Archive | Zip slip on extraction (`../` entries, absolute paths, symlinks) | bounded | `zipslip.zip` with `../zipslip_<marker>.txt`; confirm where it lands |
| FU-020 | SVG/XML | SVG (or DOCX/XLSX/XML) with XXE payload parsed server-side (thumbnailing, conversion) | bounded | `svg_xxe.svg` with OOB entity to your own host only (see xml-xxe-audit) |

## Bypass reference

### Extensions by stack

| Stack | Try |
|---|---|
| PHP | `.php .php2 .php3 .php4 .php5 .php7 .pht .phtm .phtml .phar .phps .pgif .inc .hphp .ctp .module` |
| ASP / ASP.NET | `.asp .aspx .cer .asa .ashx .asmx .axd .aspq .cshtml .vbhtml .config .soap .rem .shtml` |
| JSP / Java | `.jsp .jspx .jsw .jsv .jspf .jtml .war .do .action` |
| Perl / CGI | `.pl .pm .cgi .lib` |
| ColdFusion | `.cfm .cfml .cfc .dbm` |
| Node / static | `.js .mjs .html .htm .xhtml .xht .svg .svgz .xml .swf` |
| Config overrides | `.htaccess` (`AddType application/x-httpd-php .jpg`), `web.config`, `.user.ini` (`auto_prepend_file`) — authorized-only to test execution |

### Filename tricks

`file.php.jpg`, `file.jpg.php`, `file.php%00.jpg`, `file.php\x00.jpg`, `file.php%20`, `file.php.`, `file.php....`, `file.php/`, `file.php;.jpg`, `file.php::$DATA`, `file.pHp`, `file.php%0a`, `file.php#.jpg`, `.htaccess`, `../file.txt`, `..%2ffile.txt`, `..\\file.txt`, very long names (truncation to `.php`), Unicode right-to-left override (`file‮gpj.php`), names with HTML (`"><img src=x onerror=alert(1)>.jpg`, see UP-005).

### Content-Type values

`image/jpeg`, `image/png`, `image/gif`, `application/octet-stream`, `text/plain`, missing Content-Type, duplicate Content-Type, `image/svg+xml`.

### Magic bytes

| Type | Prefix |
|---|---|
| GIF | `GIF89a` / `GIF87a` |
| PNG | `\x89PNG\r\n\x1a\n` |
| JPEG | `\xFF\xD8\xFF\xE0` |
| PDF | `%PDF-1.5` |
| ZIP / DOCX | `PK\x03\x04` |

### Server-side processing to identify

ImageMagick/GraphicsMagick (thumbnails), libvips, ExifTool (metadata), Ghostscript (PDF/EPS), LibreOffice/unoconv (document preview), FFmpeg (video), antivirus scanners (race window), cloud functions (S3 triggers). Version and processing path decide which parser rows (UP-008, FU-020) apply.

## Serving checks for every accepted upload

1. Served origin: same app origin (risky) or a separate sandbox domain (`usercontent.example`)?
2. `Content-Type` and `X-Content-Type-Options: nosniff`.
3. `Content-Disposition: attachment` for non-images.
4. CSP on the upload domain (`sandbox`, `default-src 'none'`).
5. Auth required to fetch? Guessable path? (see file-download-audit FD-005, FD-006)

## Cross-references

| FU row | Related rows |
|---|---|
| FU-002, 003, 004 | UP-001 |
| FU-006 | UP-002 |
| FU-008, 009 | UP-003, xss stored rows |
| FU-011 | UP-004, path-traversal |
| FU-016 | UP-009 |
| FU-019 | UP-011 |
| FU-020 | UP-010, xml-xxe-audit |
| FU-017, 014 | UP-007, resource-exhaustion |
| FU-012 | race-conditions |
| FU-015 | cloud-supplychain, file-download-audit FD-007 |
