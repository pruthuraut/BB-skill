# Server-Side Injection: SSTI, OS Command, XXE, NoSQL, LDAP, Deserialization, Input Validation

Class key: `passive` (review, headers, error text), `bounded` (harmless math or syntax probes on own inputs and OOB callbacks), `authorized-only` (anything that runs commands, reads files, or changes data).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSI-001 | Template engines (generic) | SSTI: arithmetic probe reflected as evaluated result | bounded | `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` in own input; look for 49 |
| SSI-002 | Template engines | Syntax error text reveals engine | bounded | Malformed `{{` input; compare error text to engine signatures |
| SSI-003 | Jinja2 / Twig / Freemarker | SSTI escalation to code execution | authorized-only | Requires approved lab test; report probe evidence only |
| SSI-004 | Handlebars / Mustache | Triple-stash or unescaped rendering of user input | bounded | Own input with markup, check raw output |
| SSI-005 | Craft CMS (Twig) | Unescaped user content rendered through Twig | bounded | Arithmetic probe in own content |
| SSI-006 | Jira | Contact-admin SSTI CVE-2019-11581 | passive | Version check |
| SSI-007 | Struts 2 | OGNL evaluation in URL or Content-Type (version-gated) | passive | Version check; URL probe `${7*7}` only if approved |
| SSI-008 | OS command | Separator injection (`;`, `\|`, `&&`, backticks, newline) | bounded | Timing probe on own test value (sleep 0 vs sleep 5 with approval) or harmless `echo` marker |
| SSI-009 | OS command | Blind command injection via time delay | bounded | Single delayed request with approval, compare baseline |
| SSI-010 | Node.js | child_process with user input | authorized-only | Code review first; approved test only |
| SSI-011 | Ghostscript / ImageMagick / FFmpeg | Media tool argument injection | authorized-only | Version check; approved upload test |
| SSI-012 | XML parsers | External entity file read | bounded | Entity pointing to your OOB host; confirm DNS/HTTP hit only |
| SSI-013 | XML parsers | Local file read via XXE | authorized-only | Approved test on non-sensitive file (e.g., /etc/hostname) |
| SSI-014 | XML parsers | Billion laughs DoS | passive | Review parser config; do not send payload |
| SSI-015 | XInclude / XSLT | XSLT or XInclude processing of user input | bounded | OOB-host probe only |
| SSI-016 | DOCX / XLSX / SVG / SOAP | XXE in uploaded office or SVG files | bounded | Own file with OOB entity |
| SSI-017 | MongoDB / NoSQL | Operator injection (`$ne`, `$gt`, `$regex`) in login or filters | bounded | Own test account; compare responses with operator vs without |
| SSI-018 | MongoDB | $where JavaScript injection | authorized-only | Approved test only |
| SSI-019 | Express / Node login | JSON operator injection `{"$ne": null}` | bounded | Own test account; response diff only |
| SSI-020 | Mongo Express | Query evaluation RCE CVE-2019-10758 | passive | Version check |
| SSI-021 | LDAP | Filter injection in login or search (`*`, `)(`, `\|`) | bounded | Own test username with `*`; check result count difference |
| SSI-022 | LDAP | Null bind and anonymous enumeration | bounded | Anonymous rootDSE and search on own OU only |
| SSI-023 | Java | Deserialization of untrusted objects (rO0AB, aced prefixes) | passive | Identify serialized blobs in cookies/params; report, do not send gadget chains |
| SSI-024 | Java | ysoserial-class gadget exposure | authorized-only | Lab-only confirmation with approval |
| SSI-025 | PHP | unserialize() on user input | passive | Look for `O:` serialized strings in cookies; code review |
| SSI-026 | ASP.NET | ViewState and BinaryFormatter deserialization | passive | MAC enabled check in config |
| SSI-027 | Ruby / Python pickle | Unsafe loaders on user-supplied data | passive | Code review; identify pickle/YAML loads |
| SSI-028 | JBoss / Liferay / Jenkins CLI | Deserialization CVEs (see tech-stack-audit) | passive | Version checks only |
| SSI-029 | Input validation | Type confusion (array vs string, negative, huge numbers) | bounded | Own test values; compare error vs 500 |
| SSI-030 | Input validation | Null byte and encoding bypass of validators | bounded | Own test inputs |
| SSI-031 | Input validation | Stack trace or SQL error on malformed input | bounded | Malformed inputs on one endpoint at a time |
| SSI-032 | Input validation | Oversized input (10k chars) accepted without limit | bounded | One request of 10k characters, check status |
| SSI-033 | Input validation | Unicode normalization differences in validators | bounded | Own input with full-width chars |
