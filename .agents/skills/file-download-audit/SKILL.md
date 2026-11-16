---
name: file-download-audit
description: Audit authorized applications for file download and file access flaws across 10 core checks — arbitrary file download via path traversal parameters, directory listing on storage directories, wrong MIME type on served uploads, missing or unsafe Content-Disposition, downloads without authentication, IDOR on file IDs (other users' files), direct cloud storage URLs (public buckets, long-lived or reusable signed URLs), sensitive file exposure (backups, configs, logs, dumps), symlink following, and PDF/HTML-to-PDF generation from user content (SSRF and local file read) — plus variant rows (nosniff, cache headers on private files, predictable names, CDN caching, export features, thumbnails and previews, Range requests, signed-URL scope). Includes a scope-gated checker for auth, IDOR, headers, listing, and signed-URL properties. Triggers on "file download", "download endpoint", "attachment", "export", "arbitrary file read", "directory listing", "Content-Disposition", "signed URL", "S3 URL", "presigned", "backup file", "PDF generation", "invoice PDF", "file IDOR", or when route_target.py routes file, download, path, attachment, or export parameters.
---

# File Download and Access (10 core checks + variants)

Every file the app stores or generates must be served only to the right user, with headers that stop the browser from treating it as a page, and from a location that cannot be reached by guessing or traversal.

- Checklist: `references/download_checklist.md` (FD-001 to FD-010 core, FD-V-* variants, sensitive file list, PDF generator probes).
- Tracker: `references/download_tracker.md`.
- Checker: `scripts/download_check.py` (scope-gated GETs: with your session, without session, and with your second account's session; compares responses for auth and IDOR, checks Content-Type vs extension, nosniff, Content-Disposition, Cache-Control, directory listing on parent paths, and signed-URL expiry and scope).
- Related: `path-traversal` (deep traversal and LFI), `idor` (object references), `file-upload-audit` (how files get in), `contentdiscovery` (backup and config file discovery), `cloud-supplychain` (buckets), `ssrf-audit` (PDF renderers), `server-config-audit` (autoindex), `xss` (served HTML/SVG).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. If files are served from a cloud bucket or CDN host, that host must be listed in the scope file before active checks.
2. Inventory file endpoints with two own accounts (A and B): downloads, attachments, avatars, invoices, exports (CSV, PDF, ZIP), reports, backups, previews, thumbnails, shared links, and generated documents. Record the URL pattern and identifier type (path, numeric ID, UUID, signed URL).
3. Run `scripts/download_check.py --urls files.txt --cookie 'session=A' --other-cookie 'session=B'` on account A's file URLs. It reports auth required or not, IDOR (B can read A's file), header issues, parent-directory listing, and signed-URL properties.
4. Traversal (FD-001): for parameters such as `file`, `path`, `name`, `doc`, `template`, `download`, follow the path-traversal skill (R class probes such as `../../../../etc/passwd` or `..\..\windows\win.ini`, encodings, null byte, absolute paths).
5. Sensitive files (FD-008): run contentdiscovery wordlists for backups, configs, logs, and dumps on storage and app paths.
6. Symlinks (FD-009): if you can upload archives or create files, test symlink entries on your own account (bounded) and whether downloads follow them.
7. PDF generation (FD-010): put harmless HTML markers in your own invoice name, address, or report fields and check if the PDF renders HTML; then test resource fetches to your own OOB host (see ssrf-audit), and `file://` only with approval.
8. Save findings to `artifacts/<target>/file_download.json` and the tracker to `artifacts/<target>/download_tracker.md`.

## Classes

- `passive`: reading URLs, headers already captured, and JS that builds download links.
- `bounded`: GETs on your own files with your own sessions; traversal reads of standard world-readable proof files (`/etc/passwd`, `win.ini`) as the path-traversal skill defines; markers in your own generated documents.
- `authorized-only`: reading secrets or configs found through traversal beyond proof, `file://` reads through PDF generators, mass enumeration of IDs, and anything touching other users' real files.

## Rules

- For IDOR, use only files of your second own account. Stop at proof (status and size match); do not download other users' data.
- If a sensitive file is exposed, record its path, size, and type; do not download beyond what proves exposure, and redact secrets in reports.

## Mitigation guidance for reports

- Map file IDs to records server-side and check ownership on every request; never take a path from the user.
- Serve user files from a separate cookieless domain with `Content-Disposition: attachment`, a fixed safe `Content-Type`, `X-Content-Type-Options: nosniff`, and a restrictive CSP (`sandbox`).
- Private buckets only; short-lived, single-object, method-bound signed URLs.
- Disable directory listing; keep backups, logs, and configs outside the web root.
- Resolve real paths and reject symlinks outside the storage root.
- PDF/HTML renderers: escape user content, disable JavaScript and local file access, and block internal network fetches.
- `Cache-Control: private, no-store` on authenticated files.

## Sources

OWASP WSTG-ATHZ-01 (path traversal), WSTG-ATHZ-04 (IDOR), WSTG-CONF-04 (backup and unreferenced files), OWASP File Upload and Authorization cheat sheets, PortSwigger path traversal and access control labs, AWS S3 presigned URL documentation, and public reports on PDF generator SSRF.
