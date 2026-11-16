---
name: soap-api-audit
description: Audit authorized SOAP and XML web services across 10 checks — SOAPAction manipulation (action spoofing, empty/mismatched action, SOAP 1.2 action parameter), XML injection in message bodies (tag injection, CDATA, comments), XXE in SOAP requests (internal-entity detection, own OOB host only), WSDL disclosure and service enumeration (?wsdl, ?singleWsdl, disco, Axis/CXF service lists, MEX, internal endpoint addresses), WS-Security implementation (missing/strippable Security header, Timestamp and Nonce checks, signature wrapping exposure, UsernameToken PasswordText), replay of stateful operations, SOAP fault information disclosure, SOAP attachments (SwA/MTOM/XOP), encoding attacks and type confusion (UTF-16/UTF-7 declarations, xsi:type, SOAP-ENC arrays), and namespace manipulation. Includes a scope-gated probe that discovers and parses WSDLs and runs fault, action, injection, entity, replay, WS-Security stripping, encoding, and namespace tests on one of your own harmless sample requests. Triggers on "SOAP", "WSDL", "SOAPAction", "web service", ".asmx", ".svc", "Axis", "CXF", "WS-Security", "wsse", "SOAP fault", "MTOM", "XML API", "XML-RPC", or when route_target.py routes soap/wsdl/xml parameters.
---

# SOAP and XML API Audit (10 checks)

SOAP services describe themselves (WSDL), carry routing information in two places (the `SOAPAction` header and the body element), and parse XML with features that are dangerous by default (DTDs, entities, XInclude). Many also implement WS-Security in ways that can be stripped or replayed. Every active test runs on one of your own harmless sample requests.

- Checklist: `references/soap_checklist.md` (SOAP-001 to SOAP-010, discovery paths, payload notes, WS-Security checklist).
- Templates: `references/soap_templates.md` (envelopes for SOAP 1.1/1.2, action spoofing, XML injection, internal-entity and OOB XXE, WS-Security variants, SwA/MTOM, encoding and namespace tricks).
- Tracker: `references/soap_tracker.md`.
- `scripts/soap_probe.py`: WSDL discovery and parsing (operations, actions, namespaces, endpoint addresses, imports), then on `--request` (your own envelope) and `--action`: fault disclosure, SOAPAction spoofing, XML injection markers at `FUZZ`, internal-entity expansion (and OOB with `--oob`), replay, WS-Security stripping and timestamp tampering, UTF-16 and `xsi:type` confusion, and namespace/prefix changes.
- Related: `xml-xxe-audit` (deep XXE, XInclude, XSLT, XPath; `xxe_probe.py`), `error-handling-audit`, `api-security` (AA rows), `access-control` (operation-level authorization), `oauth-sso` (SAML shares XML signature issues), `tls-audit`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Discover services: `soap_probe.py --url https://host/Service.svc --discover` tries WSDL/disco/MEX/service-list paths and prints operations, SOAPActions, and endpoint addresses (internal hostnames in `soap:address` are findings for SOAP-004).
3. Build a sample request for a harmless read operation on your own data (SoapUI, Burp, or `soap_templates.md`). Put `FUZZ` in one string element for injection tests.
4. Run the tests:

   ```bash
   python3 .agents/skills/soap-api-audit/scripts/soap_probe.py --target example.com \
     --url https://api.example.com/UserService.svc --request own_getprofile.xml \
     --action "http://example.com/IUserService/GetProfile" --header 'Cookie: session=OWN' \
     --out artifacts/example.com/soap.json
   ```

   Add `--oob your.oob.host` to include an out-of-band entity probe to your own host (SOAP-003).
5. Operation-level authorization: call privileged operations listed in the WSDL with your low-privilege credentials only when they are read-only; never call destructive operations (access-control rules).
6. Attachments (SOAP-008): if the WSDL declares SwA/MTOM, test with harmless files per file-upload-audit.
7. Save findings to `artifacts/<target>/soap.json` and the tracker to `artifacts/<target>/soap_tracker.md`.

## Classes

- `passive`: WSDL/XSD review, fault messages already captured.
- `bounded`: WSDL discovery, tests on your own harmless sample request (faults, action spoofing toward read-only operations, markers, internal entity, OOB to own host, replay of a read operation, WS-Security stripping on own messages).
- `authorized-only`: calling write/delete operations, entity expansion bombs (billion laughs), file reads via XXE beyond proof, and replaying state-changing operations.

## Rules

- Use read-only operations for spoofing and replay tests; never replay payments, transfers, or account changes.
- XXE: internal-entity proof or OOB to your own host; never `file:///` reads of secrets or expansion bombs.
- Redact credentials from WS-Security headers in evidence.

## Mitigation guidance for reports

- Disable DTDs and external entities in every XML parser (see xml-xxe-audit); reject `DOCTYPE`.
- Route by the body element and verify it matches `SOAPAction`; authorize every operation.
- Do not publish WSDL/MEX in production (or require authentication); remove internal addresses.
- WS-Security: require signed Timestamp and Body, enforce Timestamp expiry and Nonce caching, use `PasswordDigest` only with TLS or prefer token-based auth, validate signature references to prevent wrapping.
- Generic faults (`faultstring` without stack traces, `includeExceptionDetailInFaults=false`).
- Strict schema validation (types, namespaces), fixed encoding (UTF-8), size limits for messages and attachments.

## Sources

W3C SOAP 1.1/1.2, WS-Security 1.1 (OASIS), OWASP Web Service Security Cheat Sheet and XML External Entity Prevention Cheat Sheet, OWASP WSTG-APIT, WS-Attacker research (signature wrapping, SOAPAction spoofing), CWE-611, CWE-91, CWE-294, CWE-347.
