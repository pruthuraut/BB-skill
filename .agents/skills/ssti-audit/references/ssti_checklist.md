# SSTI Checklist

Class key: `passive` = source, template, and error reading. `bounded` = arithmetic, syntax-break, and marker probes on your own input, at most 40 requests per parameter. `authorized-only` = anything that evaluates beyond arithmetic (execution, file reads, object traversal, gadget chains).

Engine results vary by version and configuration. Confirm every matrix result on a test instance you own before you report the engine.

## Detection probes (all engines)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-DET-001 | Generic | Marker reflected unchanged (baseline) | bounded | Send a unique marker, confirm it appears verbatim |
| SSTI-DET-002 | Generic | `{{7*7}}` evaluated to 49 | bounded | Probe, check for `49` absent from baseline |
| SSTI-DET-003 | Generic | `${7*7}` evaluated to 49 | bounded | Probe, check for `49` |
| SSTI-DET-004 | Generic | `#{7*7}` evaluated to 49 | bounded | Probe, check for `49` |
| SSTI-DET-005 | Generic | `<%= 7*7 %>` evaluated to 49 | bounded | Probe, check for `49` |
| SSTI-DET-006 | Generic | `${{7*7}}` evaluated | bounded | Probe, check for `49` or engine error |
| SSTI-DET-007 | Generic | Syntax-break set `${{<%[%'"}}%\.` produces template error text | bounded | Single probe, grep error signatures (see engine matrix) |
| SSTI-DET-008 | Generic | Long-form confirmation `7*77777` evaluated to 544439 | bounded | Confirms a true evaluation, not a coincidence |
| SSTI-DET-009 | Generic | Probe echoed literally (not evaluated) | bounded | Literal output means the sink is data-only for that engine; continue with other engines |
| SSTI-DET-010 | Generic | Probe evaluated only on a later GET or from another feature | bounded | Blind section below |
| SSTI-DET-011 | Generic | Input echoed in a page that the browser never renders (JSON, PDF source) | bounded | Check the content type and rendered artifact |

## Engine matrix (differential fingerprinting)

Use the expected results below to narrow the engine. Confirm on a lab instance before reporting.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-ENG-001 | Jinja2 (Python, Flask, Django templates in Jinja mode) | `{{7*'7'}}` returns `7777777` (string repetition) | bounded | Probe and compare with the Twig result |
| SSTI-ENG-002 | Jinja2 | `{{'<marker>'.upper()}}` returns uppercase marker (method call works) | bounded | Own marker only |
| SSTI-ENG-003 | Jinja2 | Syntax error on unmatched brackets names Jinja2 or TemplateSyntaxError | bounded | Syntax-break probe, grep error text |
| SSTI-ENG-004 | Twig (PHP, Symfony) | `{{7*'7'}}` returns `49` (numeric coercion) | bounded | Probe and compare with Jinja2 |
| SSTI-ENG-005 | Twig | `{{1/0}}` produces a division error | bounded | Probe, grep for error text |
| SSTI-ENG-006 | Twig | `${7*7}` stays literal | bounded | Probe, confirm literal output |
| SSTI-ENG-007 | Tornado (Python) | `{{7*'7'}}` returns `7777777` | bounded | Probe, compare with Jinja2 |
| SSTI-ENG-008 | Tornado | `{% debug %}` style debug tags accepted (documentation-level only) | passive | Read the template docs for the debug tag; do not run it on production |
| SSTI-ENG-009 | FreeMarker (Java, Spring) | `${7*7}` returns `49`; `#{7*7}` returns `49` | bounded | Probe and compare with Velocity |
| SSTI-ENG-010 | FreeMarker | `${7*'7'}` produces no value or a template error | bounded | Probe and grep |
| SSTI-ENG-011 | FreeMarker | Error text names freemarker (ParseException, freemarker.core) | bounded | Syntax-break probe, grep |
| SSTI-ENG-012 | Velocity (Java) | `#set($x=7*7)$x` returns `49` | bounded | Probe directive form |
| SSTI-ENG-013 | Velocity | Error text names velocity (ParseErrorException) | bounded | Syntax-break probe, grep |
| SSTI-ENG-014 | Thymeleaf (Java, Spring) | `${{7*7}}` or `[[${7*7}]]` evaluated; error names Thymeleaf | bounded | Probe and grep |
| SSTI-ENG-015 | Pebble (Java) | `{{7*7}}` evaluated with Pebble error text on malformed input | bounded | Probe and grep |
| SSTI-ENG-016 | Mako (Python) | `${7*7}` returns `49` | bounded | Probe and compare with FreeMarker |
| SSTI-ENG-017 | ERB (Ruby) | `<%= 7*7 %>` returns `49`; `${7*7}` stays literal | bounded | Probe and compare |
| SSTI-ENG-018 | ERB | Error text names ERB or SyntaxError | bounded | Syntax-break probe, grep |
| SSTI-ENG-019 | Smarty (PHP) | `{7*7}` returns `49`; `{$smarty.version}` returns a version string | bounded | Probe the version variable (harmless) |
| SSTI-ENG-020 | Handlebars / Mustache (JavaScript) | `{{this}}` renders `[object Object]`; double-brace arithmetic stays literal | bounded | Probe and compare |
| SSTI-ENG-021 | Dust.js (JavaScript) | Dust tags evaluated, error text names dust | bounded | Syntax-break probe, grep |
| SSTI-ENG-022 | .NET Razor | `@(1+2)` returns `3` | bounded | Probe |
| SSTI-ENG-023 | Client-side Angular | `{{constructor}}` or `{{7*7}}` evaluated in the browser (client-side template injection, not server SSTI) | bounded | Own page DOM check; report as client-side template injection |
| SSTI-ENG-024 | Client-side Vue | `{{_context}}` or `{{7*7}}` evaluated in the browser | bounded | Own page DOM check; report as client-side template injection |
| SSTI-ENG-025 | Node.js template rendering | Object properties reachable through `this` (constructor chain) | authorized-only | Lab review only; do not chain to execution |

## Injection points

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-IP-001 | Parameters | `template`, `preview`, `id`, `view`, `activity`, `name`, `content`, `redirect` in GET or POST | bounded | Route with `route_target.py --params` and probe each |
| SSTI-IP-002 | GET request | `?name={{7*7}}` on any page that greets or displays the value | bounded | Probe with marker first |
| SSTI-IP-003 | POST form | Same probe in form fields | bounded | Probe with marker first |
| SSTI-IP-004 | POST JSON | `{"name":"{{7*7}}"}` in JSON bodies | bounded | Probe with the JSON mode of the probe script |
| SSTI-IP-005 | Search | Search term rendered through a template in results or no-results page | bounded | Probe in own search text |
| SSTI-IP-006 | Error pages | Reflected input on 404 or error pages | bounded | Probe on a missing path with marker |
| SSTI-IP-007 | Contact and feedback forms | Message body rendered in an internal template or notification | bounded | Own address and marker only |
| SSTI-IP-008 | Profile fields | Name or username rendered in templated pages, emails, or PDFs | bounded | Own profile, marker only |
| SSTI-IP-009 | Email templates | Templates that merge user fields into the body | bounded | Own address; read the delivered mail |
| SSTI-IP-010 | Notifications | Notification text built from user content | bounded | Own notification with marker |
| SSTI-IP-011 | Reports | Report title or filter values rendered through a template | bounded | Own report with marker |
| SSTI-IP-012 | Invoices | Invoice fields (customer name, notes) rendered through a template | bounded | Own invoice with marker |
| SSTI-IP-013 | PDF generation | Text in generated PDFs rendered through a template engine | bounded | Own PDF with marker; read the rendered text |
| SSTI-IP-014 | Theme and template editors | Admin template editors that accept expressions | bounded | Own test theme, marker only |
| SSTI-IP-015 | Page builders | Custom HTML or template blocks | bounded | Own draft page, arithmetic probe |
| SSTI-IP-016 | CMS admin | Template overrides and custom fields | bounded | Own test template only |
| SSTI-IP-017 | Headers | User-Agent, Referer, or custom headers rendered in templates | bounded | Own header marker |
| SSTI-IP-018 | Cookies | Cookie values rendered in templates | bounded | Own cookie marker |
| SSTI-IP-019 | Uploads | Filenames or metadata rendered in templates | bounded | Harmless filename marker |

## Blind SSTI

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-BLD-001 | Replay | Replay the probe across a crawled URL set and search responses for the computed value | bounded | `waybackurls <t> \| qsreplace "ssti{{9*9}}" > fuzz.txt`, replay through a local proxy, search for `81` in captured responses |
| SSTI-BLD-002 | Delayed reflection | Result appears on a later page or in an email rather than the same response | bounded | Probe with marker, check the other feature |
| SSTI-BLD-003 | Out-of-band | Blind confirmation through an OOB host | authorized-only | Requires a lab and approval. Arithmetic results are enough for evidence; do not run OOB payloads that execute commands |
| SSTI-BLD-004 | Tool-assisted | Use SSTImap in detection mode with the engine hint | bounded | `python3 /opt/SSTImap/sstimap.py -u <url> --marker fuzzer` (detection only, no `--os-cmd`) |
| SSTI-BLD-005 | Tool-assisted | POST data and session cookie passed to SSTImap | bounded | `--method POST --data '<form>' --cookie '<own session>'` |

## Methodology notes

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-METH-001 | Detect | Fuzz with the special-character set `${{<%[%'"}}%\.` and compare responses | bounded | Single probe per parameter, diff status and length |
| SSTI-METH-002 | Identify | Use the engine matrix differential results | bounded | Two or three differential probes |
| SSTI-METH-003 | Confirm | Second, different probe returns the expected result | bounded | Long-form 7*77777 = 544439 |
| SSTI-METH-004 | Scope | Stop at evaluated arithmetic; report with evidence | passive | Write-up with request, response excerpt, and engine hint |
| SSTI-METH-005 | Escalation | Any evaluation beyond arithmetic requires written approval and an isolated lab | authorized-only | Record the approval reference in the report |

## Reporting and mitigation

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-RPT-001 | Impact | Describe the template feature, the data path, and the confirmed evaluation | passive | Include the probe and the evaluated output |
| SSTI-RPT-002 | Mitigation | Use a logic-less engine such as Mustache where possible | passive | Recommendation only |
| SSTI-RPT-003 | Mitigation | Keep user input out of template text; pass it as data | passive | Recommendation only |
| SSTI-RPT-004 | Mitigation | Sandbox any feature that lets users author templates, and remove dangerous modules | passive | Recommendation only |
| SSTI-RPT-005 | Mitigation | Run template rendering in a locked-down container with least privilege | passive | Recommendation only |

## Public references for triage (not for payload copying)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSTI-REF-001 | HackerOne | Public SSTI reports reviewed for patterns (1104349, 125980, 423541, 164224, 942103, 3031518) | passive | Read the report for the affected feature type, not for payloads |
| SSTI-REF-002 | PortSwigger | Server-side template injection (Web Security Academy) | passive | Read the detection and identification sections |
| SSTI-REF-003 | CWE | CWE-1336 improper neutralization in a template engine | passive | Classification for the report |
| SSTI-REF-004 | PayloadsAllTheThings | SSTI payload collection | passive | Use for engine names and detection characters only |
| SSTI-REF-005 | SSTImap / tplmap | Detection-mode tooling | passive | Install per SETUP.md; use detection flags only |
