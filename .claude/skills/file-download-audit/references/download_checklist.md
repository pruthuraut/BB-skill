# File Download and Access Checklist

Class key: `passive` = URL, header, and JS review. `bounded` = own files, own two accounts, standard proof files for traversal. `authorized-only` = secrets beyond proof, `file://` through renderers, mass ID enumeration, real users' files.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| FD-001 | Download | Arbitrary file download via path traversal parameter (`?file=../../../../etc/passwd`, encoded, absolute path, `....//`, null byte) | bounded | Standard proof file only; follow path-traversal R-class rows |
| FD-002 | Storage | Directory listing on upload, storage, backup, or static directories (Apache/Nginx autoindex, IIS, S3 ListBucket, GCS, Azure `restype=container&comp=list`) | bounded | download_check.py parent-listing check; request the folder URL |
| FD-003 | Headers | Uploaded files served with wrong MIME type (HTML/SVG as `text/html`/`image/svg+xml` on app origin, sniffable `text/plain`, missing Content-Type) | bounded | download_check.py Content-Type vs extension; open in browser |
| FD-004 | Headers | Content-Disposition missing (`inline` for user HTML/SVG/PDF) or filename unescaped (header injection, RFD `filename=x.bat`) | bounded | Read headers; own file with quotes and CRLF-safe marker in the name |
| FD-005 | Auth | File download works without authentication (logged out, expired session, after logout) | bounded | download_check.py no-cookie request; compare status and size |
| FD-006 | IDOR | File IDOR: account B reads account A's file by ID, path, or filename | bounded | download_check.py `--other-cookie`; own two accounts only (see idor) |
| FD-007 | Cloud | Direct cloud storage URL access: public object or bucket, signed URL long-lived, reusable after logout, valid for other keys or methods | bounded | download_check.py signed-URL analysis; request object logged out; check bucket listing |
| FD-008 | Exposure | Sensitive files exposed: backups (`.bak`, `.old`, `~`, `.swp`, `.zip`, `.tar.gz`, `.sql`), configs (`.env`, `web.config`, `config.php.bak`, `application.yml`), logs (`.log`, `debug.log`, `laravel.log`), VCS (`.git/`, `.svn/`), dumps (`dump.sql`, `db.sqlite`) | bounded | contentdiscovery wordlists; record path, size, type only |
| FD-009 | Symlink | Download follows symlinks (from archive extraction, user-created links, or shared folders) outside the storage root | bounded | Own archive with a symlink to a standard proof file; see file-upload-audit FU-019 |
| FD-010 | PDF | PDF generation from user content: HTML injection, JS execution in renderer, SSRF via `<img>`/`<iframe>`/`<link>`, local file read via `file://` (wkhtmltopdf, Puppeteer, PhantomJS, mPDF, dompdf, WeasyPrint) | bounded | Marker HTML in own fields; OOB fetch to own host; `file://` is authorized-only |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| FD-V-001 | Headers | `X-Content-Type-Options: nosniff` missing on user files | passive | Header read |
| FD-V-002 | Headers | Private files cacheable (`Cache-Control: public`, no `private`/`no-store`), cached by CDN and served to others | bounded | Request own file twice, check `Age`, `X-Cache`; logged out after |
| FD-V-003 | Naming | Predictable file names or IDs (sequential, timestamp, original filename, MD5 of name) | passive | Compare own uploads |
| FD-V-004 | Sharing | Shared or public links do not expire, survive revocation, or reveal other files in the folder | bounded | Own share link: revoke, re-request |
| FD-V-005 | Exports | Export features (CSV/ZIP/report) include other tenants' data or are fetchable by job ID without auth | bounded | Own export job ID from account B |
| FD-V-006 | Previews | Thumbnails, previews, or converted versions served without the original's access checks | bounded | Own file: request preview URL logged out and as B |
| FD-V-007 | Ranges | `Range` requests bypass size or access limits | bounded | Own file with `Range: bytes=0-10` logged out |
| FD-V-008 | Signed URL | Signed URL scope too broad (prefix or bucket wide), method not bound (PUT allowed), or signature not covering query parameters | bounded | Change object key or method on own signed URL |
| FD-V-009 | Origin | User files served from the main app origin (cookies sent, XSS on app) | passive | Note host |
| FD-V-010 | RFD | Reflected file download: JSON/JSONP endpoint with `filename` from URL path (`/api/x;/setup.bat`) | bounded | Own request; check Content-Disposition and body |
| FD-V-011 | Encoding | Download name with Unicode RTLO or double extension tricks the user | passive | Own upload with RTLO name |
| FD-V-012 | Deleted | Deleted files still downloadable by old URL or ID | bounded | Own file: delete, re-request |
| FD-V-013 | Methods | Download handler accepts HEAD or OPTIONS revealing existence of others' files | bounded | HEAD with B session on A's file |
| FD-V-014 | API | Mobile or older API version serves files without checks | bounded | Same file ID on alternate API paths |

## PDF generator probes (own fields only)

| Goal | Marker |
|---|---|
| HTML rendered | `<b>MARKER</b><h1>MARKER</h1>` |
| JS executes | `<script>document.write('JS_'+(7*7))</script>` (look for `JS_49`) |
| Renderer identity | `<script>document.write(navigator.userAgent)</script>` |
| SSRF (own host) | `<img src="https://YOUR-OOB-HOST/fd010">`, `<link rel=stylesheet href="https://YOUR-OOB-HOST/css">` |
| Local file (authorized-only) | `<iframe src="file:///etc/passwd">` or `<script>x=new XMLHttpRequest;x.open('GET','file:///etc/passwd',false);x.send();document.write(x.responseText)</script>` |
| Cloud metadata (authorized-only) | Follow ssrf-audit rules; never read credentials |

## Cross-references

| FD row | Related rows |
|---|---|
| FD-001 | path-traversal |
| FD-002 | server-config-audit autoindex rows, contentdiscovery |
| FD-003, FD-004 | file-upload-audit UP-003, FU-008, FU-009 |
| FD-006, FD-V-005 | idor |
| FD-007, FD-V-008 | cloud-supplychain, file-upload-audit FU-015 |
| FD-008 | contentdiscovery exposure rows |
| FD-009 | file-upload-audit FU-019 |
| FD-010 | ssrf-audit renderer rows |
