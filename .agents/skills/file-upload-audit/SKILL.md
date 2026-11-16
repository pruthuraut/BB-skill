---
name: file-upload-audit
description: Audit authorized applications for file upload weaknesses: extension and MIME allowlist bypass, stored file types served unsafely (HTML, SVG), path traversal in filenames, zip slip and symlink extraction, image and office parser abuse (ImageMagick, Ghostscript, ExifTool, XXE in DOCX/SVG), CSV formula injection, HTTP PUT and WebDAV write, and upload-related CVEs. Triggers on "file upload", "upload endpoint", "attachment", "avatar upload", "import file", "zip extraction", "multipart", "PUT", "WebDAV", or when route_target.py routes upload, attachment, avatar, or import parameters.
---

# File Upload Audit

Find where uploaded files are stored, named, parsed, or served in a way that breaks security. Use harmless test files with benign markers on your own account. Executable uploads and parser exploit files are authorized-only.

Checklist: `references/upload_checks.md` (20 rows).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Map upload endpoints: multipart form fields, API routes, import features. Note allowed types and size limits from the UI and error messages.
3. Name and type: upload a harmless text file with variant names (UP-001), spoofed Content-Type (UP-002), traversal name (UP-004), and reflected name marker (UP-005).
4. Serving: check the Content-Type and whether harmless HTML or SVG with a marker renders on the app origin (UP-003).
5. Parsers: use harmless SVG and office files with OOB entities (UP-010) and EXIF markers (UP-009). Check parser versions for ImageMagick, Ghostscript, and ExifTool (UP-008).
6. Archives: harmless archive with a `../marker.txt` entry on your own account (UP-011). Confirm placement, not overwrite of real files.
7. CSV export: harmless formula marker on your own record, export, inspect (UP-013).
8. PUT and WebDAV: OPTIONS Allow header first (UP-015). PUT only a harmless text file if approved.
9. Save results to `artifacts/<target>/file_upload.json`.

## Classes

- `passive`: config and version review.
- `bounded`: harmless files on own account.
- `authorized-only`: anything that could run on the server.

## Rules

- Delete your own test uploads after the test if the program allows, and note their paths.
- Never upload a web shell, even to prove execution.
