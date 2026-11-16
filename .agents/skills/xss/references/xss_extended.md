# XSS Extension (extension)

Use a unique marker string per check (for example `zq7x`) and an alert or console marker on your own origin. Class key as in other references.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XSS-X-001 | Reflected | URL parameter reflected into HTML without encoding | bounded | `?q=zq7x"'<>` and grep for raw reflection |
| XSS-X-002 | Reflected | Reflection in error page | bounded | Malformed path with marker |
| XSS-X-003 | Reflected | Reflection in header-driven page (Referer, User-Agent) | bounded | Own header with marker |
| XSS-X-004 | Reflected | Reflection in numeric, cookie, or locale field | bounded | Own cookie marker |
| XSS-X-005 | Reflected | Reflection in path segment | bounded | Path marker |
| XSS-X-006 | Stored | User-generated content rendered unencoded | bounded | Own profile or comment marker |
| XSS-X-007 | Stored | SVG upload executes script on app origin | bounded | Harmless SVG with marker |
| XSS-X-008 | Stored | Markdown or WYSIWYG renders raw HTML | bounded | Own draft with marker |
| XSS-X-009 | Stored | Email template renders user input | bounded | Own email to self with marker |
| XSS-X-010 | Stored | PDF renderer executes script | bounded | Own PDF-generation input with marker |
| XSS-X-011 | Stored | Cache poisoning delivers XSS to other users | authorized-only | See http-protocol-cache CACHE-001; no shared cache tests |
| XSS-X-012 | Blind | Blind XSS in admin panel via own callback host | bounded | Own OOB host in support form |
| XSS-X-013 | DOM | Source (hash, query, referrer) to sink (innerHTML, eval) | bounded | See client-side-js-security DOM-001 |
| XSS-X-014 | DOM | postMessage handler to sink | bounded | See client-side-js-security PM-002 |
| XSS-X-015 | Framework | AngularJS sandbox escape or Vue template injection | bounded | Own marker in compiled template |
| XSS-X-016 | Framework | React dangerouslySetInnerHTML with user data | passive | Code review and grep |
| XSS-X-017 | Sanitizer | mXSS through DOMPurify or sanitize-html version | passive | Version check |
| XSS-X-018 | Attributes | Breakout from attribute, hidden input, JS string, or template literal | bounded | Marker breakout test |
| XSS-X-019 | Vectors | javascript:, data:, srcdoc, base, form, meta, object, embed, MathML, animate | bounded | Marker per vector, benign alert text |
| XSS-X-020 | Filters | Entity, Unicode, UTF-7, UTF-16, WAF encoding bypass | bounded | Marker per encoding |
| XSS-X-021 | CSP | Analysis for bypass via JSONP or whitelisted host | bounded | See csrf-and-headers-audit CSP-003 |
| XSS-X-022 | Dangling markup | Injection without script to exfiltrate tokens | bounded | Own marker only; never capture real user data |
| XSS-X-023 | XSSI | JSONP or JS responses readable cross-origin | bounded | See client-side-js-security AJAX-001 |
| XSS-X-024 | Upload names | Filename reflected unencoded | bounded | See file-upload-audit UP-005 |
| XSS-X-025 | Self-XSS | Chain with CSRF to reach victim | bounded | Own two accounts |
| XSS-X-026 | Content type | Response served with wrong content type enabling sniffing | bounded | Content-Type on own uploaded file |
