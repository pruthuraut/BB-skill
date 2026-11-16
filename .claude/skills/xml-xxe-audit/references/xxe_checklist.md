# XML Injection and XXE Checklist

Class key: `passive` = parser configuration, WSDL, and source review. `bounded` = internal entity and UTF-16 probes, out-of-band callbacks to your host, benign XInclude and XPath tests, at most 20 requests per endpoint. `authorized-only` = local file entities (benign path, approval), XSLT that reaches the system, and resource-expansion checks (never sent).

## XXE core

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-CORE-001 | XML endpoint | Internal entity expanded (proves entity resolution) | bounded | `xxe_probe.py` internal entity probe |
| XXE-CORE-002 | XML endpoint | External SYSTEM entity fetched to host you control | bounded | `--oob-host`; check the host log for the token |
| XXE-CORE-003 | XML endpoint | Parameter entity loads external DTD from host you control | bounded | `--oob-host`; check for the DTD request |
| XXE-CORE-004 | XML endpoint | Local file entity returns content (benign file) | authorized-only | `--allow-file-read --file-path /etc/hostname` with approval |
| XXE-CORE-005 | XML endpoint | Response changes when a file entity is used (no content shown) | authorized-only | Same approval; compare hash only |
| XXE-CORE-006 | Blind XXE | DNS exfiltration tokens arrive at your DNS host | bounded | OOB token in entity domain; check DNS log |
| XXE-CORE-007 | Blind XXE | HTTP exfiltration tokens arrive at your HTTP host | bounded | OOB token in URL path; check HTTP log |
| XXE-CORE-008 | Blind XXE | Data exfiltration of a file through DNS or HTTP | authorized-only | Not run by this skill |

## Endpoints and formats

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-EP-001 | XML body | Direct XML POST accepts DOCTYPE | bounded | Probe with the default template |
| XXE-EP-002 | SOAP | SOAP envelope body with DOCTYPE in the message | bounded | Probe with a SOAP template (`--template-file`) |
| XXE-EP-003 | AJAX | `Content-Type: application/xml` or `text/xml` from front-end XHR | bounded | Probe with the same content type the front end uses |
| XXE-EP-004 | SVG upload | SVG with external entity processed by server-side renderer | bounded | Own SVG file with OOB entity (no file read) |
| XXE-EP-005 | DOCX and XLSX | External entity in document XML inside the archive | bounded | Own document with OOB entity |
| XXE-EP-006 | SAML | XXE in SAML assertions parsed before signature check | bounded | Own IdP test or own captured assertion; OOB entity only |
| XXE-EP-007 | WSDL | WSDL fetcher resolves external entities or imports | bounded | Own WSDL URL with OOB import |
| XXE-EP-008 | RSS and Atom | Feed parser resolves external entities | bounded | Own feed URL with OOB entity |
| XXE-EP-009 | Office and PDF tools | Converter parses external entities in uploaded XML | bounded | Own file with OOB entity |

## Encoding and filter bypass

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-ENC-001 | UTF-16 | Entity expansion works with UTF-16 bodies (byte-level filter bypass) | bounded | `xxe_probe.py` UTF-16 probe |
| XXE-ENC-002 | Encodings | UTF-7 or other charset declarations accepted | bounded | Own body in an alternate charset with an internal entity |
| XXE-ENC-003 | Content type | Filter checks Content-Type but parser ignores it | bounded | Probe with alternate content type |
| XXE-ENC-004 | Keyword filter | `DOCTYPE` or `ENTITY` keyword filter bypassed by whitespace or comments | bounded | Probe with benign internal entity |

## XInclude, XSLT, XPath

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-XI-001 | XInclude | `xi:include` processes a remote href | bounded | `xxe_probe.py` XInclude to out-of-band host |
| XXE-XI-002 | XInclude | `parse="text"` returns file content | authorized-only | Benign file only, approval required |
| XXE-XSL-001 | XSLT | Stylesheet accepted from user input | passive | Review the transform code |
| XXE-XSL-002 | XSLT | `system-property('xsl:version')` returns a version (benign capability check) | bounded | Own stylesheet with harmless property read |
| XXE-XSL-003 | XSLT | Extension functions allow system calls | authorized-only | Not run by this skill; report from configuration review |
| XXE-XP-001 | XPath | Quote break in an XPath query changes results | bounded | Own record, quote probe, differential |
| XXE-XP-002 | XPath | Boolean XPath condition changes results | bounded | `' or '1'='1` pair against an impossible control on own record |
| XXE-XP-003 | XPath | Data extraction through XPath functions | authorized-only | Not run by this skill |

## Denial of service (never sent)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-DOS-001 | XML parsers | Billion laughs (nested entity expansion) | passive | Never sent. Check the parser config for entity expansion limits |
| XXE-DOS-002 | XML parsers | Quadratic blowup from large attributes | passive | Config review only |

## Parser and source review

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-SRC-001 | Java | DocumentBuilderFactory without `disallow-doctype-decl` | passive | `xml_parser_scan.py` high findings |
| XXE-SRC-002 | Java | SAXParserFactory and XMLInputFactory defaults | passive | `xml_parser_scan.py` |
| XXE-SRC-003 | Python | lxml with `resolve_entities=True` | passive | `xml_parser_scan.py` |
| XXE-SRC-004 | Python | xml.dom and xml.sax defaults | passive | Review; check which stdlib parser is used |
| XXE-SRC-005 | PHP | simplexml or DOMDocument with `LIBXML_NOENT` | passive | `xml_parser_scan.py` |
| XXE-SRC-006 | PHP | `libxml_disable_entity_loader(false)` on user input | passive | Grep |
| XXE-SRC-007 | .NET | XmlDocument with `DtdProcessing.Parse` or a non-null XmlResolver | passive | `xml_parser_scan.py` |
| XXE-SRC-008 | Node.js | libxmljs with `noent: true` | passive | `xml_parser_scan.py` |
| XXE-SRC-009 | Ruby | Nokogiri with `NOENT` | passive | `xml_parser_scan.py` |

## Reporting

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| XXE-RPT-001 | Evidence | Request, entity marker in response, OOB token and timestamp | passive | Include in report |
| XXE-RPT-002 | Fix | Disable DTDs (`disallow-doctype-decl`) where possible | passive | Recommendation |
| XXE-RPT-003 | Fix | Disable external entities and XInclude; use secure-processing features | passive | Recommendation |
| XXE-RPT-004 | Fix | Use less complex formats (JSON) for data exchange where possible | passive | Recommendation |
