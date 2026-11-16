---
name: xml-xxe-audit
description: Audit authorized applications for XML injection and XXE, covering XML and SOAP endpoints, AJAX XML bodies, file uploads (SVG, DOCX, XLSX), SAML assertions, WSDL, RSS and Atom parsers, XInclude, XSLT, XPath, UTF-16 and encoding bypasses, and entity expansion risk. Probes confirm entity expansion safely, send out-of-band checks only to a host you control, and never send resource-expansion payloads. Includes a passive parser-configuration scanner for source review. Triggers on "XXE", "XML injection", "SOAP", "WSDL", "SAML", "DOCTYPE", "ENTITY", "XInclude", "XSLT", "XPath injection", "RSS parser", "SVG upload", or when route_target.py routes xml, soap, feed, saml, or xslt parameters.
---

# XML Injection and XXE Audit

Find XML parsers that resolve entities, fetch external resources, or process XInclude and XSLT on user input. The probe proves entity expansion with an internal entity (no external access), then tests out-of-band fetches only to your own host. Local file reads are behind an explicit approval flag.

Checklist: `references/xxe_checklist.md`. Tools: `scripts/xxe_probe.py` (black-box, scope-gated) and `scripts/xml_parser_scan.py` (passive source review).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Find XML inputs: XML and SOAP bodies, `Content-Type: application/xml` or `text/xml`, SAML `SAMLResponse`, file imports (SVG, DOCX, XLSX), RSS or Atom feed URLs, and WSDL fetchers. Route with `route_target.py --params`.
3. Run the probe against an endpoint that accepts XML. Provide a template matching the real request when one is known:

   ```
   python3 .agents/skills/xml-xxe-audit/scripts/xxe_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --url https://example.com/api/import \
     --template-file templates/soap.xml --oob-host <your-oast-host> \
     --out artifacts/example.com/xxe.json
   ```

   The probe sends at most 20 requests. Check your out-of-band host for the tokens listed in `oob_tokens`.
4. Read `entity_expanded` and `utf16_expanded`. Entity expansion is the prerequisite for XXE; report it with the response excerpt even if no external fetch happens.
5. Source review: `python3 .agents/skills/xml-xxe-audit/scripts/xml_parser_scan.py <source-dir> --out artifacts/<target>/xml_parsers.json`. Treat `high` findings first and check whether DTDs or external entities are disabled.
6. Feature checks (SVG upload, DOCX or XLSX import, SAML, feed parsers, XSLT and XPath): follow the checklist rows, using your own files and your own accounts.
7. Save evidence to `artifacts/<target>/xxe.json`.

## Classes

- `passive`: parser configuration review, WSDL and schema reading, error text.
- `bounded`: internal entity and UTF-16 probes, out-of-band callbacks to your host, XInclude to your host, benign XPath quote tests.
- `authorized-only`: local file entities (behind `--allow-file-read` and a benign path), XSLT processing that reaches the system, and any resource-expansion test (billion laughs is never sent).

## Rules

- Never send resource-expansion payloads. Report the parser configuration instead.
- Out-of-band callbacks go only to a host you control.
- Read only a benign file (default `/etc/hostname`) and only with written approval. Do not read credentials, keys, or other users' data.
- For SAML, use your own IdP test tenant or your own captured assertion. Do not forge assertions for accounts you do not own.
- Report the endpoint, the parser behaviour, the evidence, and the fix: disable DTDs (`disallow-doctype-decl`), disable external entities and XInclude, and use secure-processing settings.

## SOAP services

- For SOAP-specific checks (SOAPAction spoofing, WSDL enumeration, WS-Security, replay, faults, namespaces), use `soap-api-audit` (`../soap-api-audit/SKILL.md`) and `scripts/soap_probe.py`; return here for deep XXE, XInclude, XSLT, and XPath testing.
