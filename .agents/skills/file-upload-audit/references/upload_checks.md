# File Upload Checks

Class key: `passive` (review of accepted types and config), `bounded` (uploads of harmless test files on own account, benign content only), `authorized-only` (executable or polyglot uploads that could run on the server).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| UP-001 | Generic upload | Extension allowlist bypass (double extension, case, trailing dot/space) | bounded | Upload a harmless .txt disguised as `name.php.txt` style variants and check stored name and Content-Type; never upload executable code |
| UP-002 | Generic upload | Content-Type trusted instead of content sniffing | bounded | Harmless file with spoofed Content-Type header |
| UP-003 | Generic upload | Stored file served with dangerous type (text/html, image/svg+xml) | bounded | Upload harmless HTML/SVG with a marker, check Content-Type and whether it renders on the app origin |
| UP-004 | Generic upload | Path traversal in filename writes outside upload dir | bounded | Filename `../marker.txt` on own account; check location |
| UP-005 | Generic upload | Filename reflected unencoded (XSS) | bounded | Own filename marker, check reflection |
| UP-006 | Generic upload | Upload directory executes server-side scripts | authorized-only | Approved lab test; check handler config first (passive) |
| UP-007 | Generic upload | Size limit absent (storage DoS) | bounded | One request at a documented limit +1 MB, check rejection |
| UP-008 | Image processing | ImageMagick / Ghostscript / ExifTool argument or delegate injection | authorized-only | Version check; approved test |
| UP-009 | Image processing | Metadata-based XSS or PHP in EXIF retained | bounded | Own image with harmless EXIF marker, check served output |
| UP-010 | Office and SVG | XXE in DOCX/XLSX/SVG parsing | bounded | Own file with OOB entity (see server-side-injection SSI-016) |
| UP-011 | Archive extraction | Zip slip (../ entries) and symlink extraction | bounded | Archive with harmless `../marker.txt` entry on own account |
| UP-012 | Archive extraction | elFinder archive handler RCE CVE-2021-32682 | passive | Version check |
| UP-013 | Import | CSV/Excel formula injection (`=HYPERLINK`) in export | bounded | Own record with harmless formula marker, export and inspect |
| UP-014 | Import | Import endpoints accept remote URL (SSRF) | bounded | OOB host as source URL (see ssrf-audit) |
| UP-015 | PUT uploads | WebDAV or HTTP PUT enabled on static path | bounded | OPTIONS for Allow header; PUT only a harmless text file if approved |
| UP-016 | Tomcat | Default servlet write enabled CVE-2017-12617, CVE-2025-24813 | passive | Version and readonly config check |
| UP-017 | IIS | WebDAV write with script execution | passive | OPTIONS Allow and WebDAV config review |
| UP-018 | Chamilo / Gravity Forms / Fluent Forms / Elementor / Divi | Known file-upload CVEs for version | passive | Version check per advisory |
| UP-019 | Nginx | Extension parsing bypass (CVE-2013-4547 family) | passive | Version check |
| UP-020 | Jira / Confluence attachments | Attachment serving with XSS | bounded | Own attachment with harmless HTML marker |
