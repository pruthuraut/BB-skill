# WAF Bypass Checklist

Class key: `passive` = fingerprinting and configuration review. `bounded` = encoding differential tests with benign test strings, capped at 40 requests. `authorized-only` = slow or resource-consuming tests (approval only).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| WAFB-001 | WAF | WAF identified (wafw00f, headers, cookies) | passive | `waf_probe.py` fingerprint (Kali: wafw00f) |
| WAFB-002 | URL encoding | Encoded test string passes where the plain one is blocked | bounded | `waf_probe.py` url-encoded |
| WAFB-003 | URL encoding | Double URL encoding passes | bounded | `waf_probe.py` double-url-encoded |
| WAFB-004 | Unicode and HTML | Unicode escape or HTML entity encoding passes | bounded | `waf_probe.py` unicode-escaped, html-entities |
| WAFB-005 | Base64 | Base64-wrapped value passes when the app decodes it | bounded | `waf_probe.py` base64-wrapped (confirm the server decodes) |
| WAFB-006 | Chunked | Chunked transfer encoding hides body content from inspection | bounded | Own body split across chunks; compare block status |
| WAFB-007 | HTTP/2 | HTTP/2 features (header case, pseudo-headers) bypass HTTP/1.1 rules | bounded | Same benign request over HTTP/1.1 and HTTP/2 (curl --http2) |
| WAFB-008 | Content type | Switching content type (form, JSON, XML) changes inspection | bounded | Same benign test sent in each content type |
| WAFB-009 | Content type | JSON or XML parsing differences between WAF and app | bounded | Benign marker in JSON and XML bodies |
| WAFB-010 | Multipart | Multipart form encoding hides the value from inspection | bounded | Own multipart upload with benign marker |
| WAFB-011 | Null byte | Null byte inserted before a blocked string | bounded | `waf_probe.py` null-byte-prefix |
| WAFB-012 | SQL comments | Inline comment (`/*!...*/`) inside a keyword | bounded | `waf_probe.py` inline-comment (benign string) |
| WAFB-013 | Case | Case variation of keywords | bounded | `waf_probe.py` case-variation |
| WAFB-014 | SQL syntax | Alternative SQL syntax for the same meaning | bounded | Review SQLi WAF rows in sqli skill; benign markers only |
| WAFB-015 | Headers | Header manipulation (X-Forwarded-For, X-Original-URL) changes rule matching | bounded | One header at a time on own path |
| WAFB-016 | Method | Request method variation (GET to POST) changes inspection | bounded | Same benign request by method |
| WAFB-017 | Path | Path normalization tricks (dot segments, double slash, encoded slash) | bounded | Own path variants; compare status |
| WAFB-018 | Parameters | HTTP parameter pollution (duplicate names) | bounded | Duplicate parameter with benign marker |
| WAFB-019 | Parameters | Fragmented payload across parameters | bounded | Benign string split over two parameters; confirm the app joins them |
| WAFB-020 | JSON | JSON array injection wraps a value in an array | bounded | Own JSON body with array-wrapped benign marker |
| WAFB-021 | GraphQL | Query obfuscation (aliases, fragments, whitespace) | bounded | Benign GraphQL query variants |
| WAFB-022 | GET body | Request body sent with GET is not inspected | bounded | Own GET with body; compare |
| WAFB-023 | Slow HTTP | Slowloris-style slow requests pass inspection or exhaust workers | authorized-only | Approval only; never flood production |
| WAFB-024 | Pipelining | HTTP pipelining changes which request the WAF inspects | authorized-only | Lab only |
| WAFB-025 | Source IP | IP spoofing via X-Forwarded-For bypasses IP-based rules | bounded | Single request with a spoofed header; compare status |
| WAFB-026 | Reporting | Evidence: block status per encoding, verified bypass with the server decoding it | passive | Include the differential table |
