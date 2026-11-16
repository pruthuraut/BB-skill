# SOAP and XML API Checklist

Class key: `passive` = WSDL/XSD and captured faults. `bounded` = discovery and tests on your own harmless sample request. `authorized-only` = write/delete operations, entity bombs, file reads beyond proof, replay of state-changing operations.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SOAP-001 | SOAPAction | SOAPAction manipulation: body operation and `SOAPAction` mismatch accepted (action spoofing past action-based authz/WAF), empty action, SOAP 1.2 `action=` parameter in Content-Type | bounded | soap_probe.py spoofs the action with other (read-only) operations from the WSDL and an empty action |
| SOAP-002 | XML injection | XML injection in message body: injected tags change structure (`</a><admin>true</admin><a>`), CDATA breakout, comments, unescaped reflection | bounded | soap_probe.py markers at `FUZZ`; check reflection and behavior change |
| SOAP-003 | XXE | XXE in SOAP requests (and responses parsed by clients): DTD allowed, internal entities expanded, external entities fetched | bounded | soap_probe.py internal-entity proof; `--oob` to own host; xml-xxe-audit for depth |
| SOAP-004 | WSDL | WSDL disclosure and service enumeration (`?wsdl`, `?singleWsdl`, `?disco`, MEX, `/services`, `/axis2/services/listServices`, `/cxf/services`), internal endpoint addresses, hidden admin operations | bounded | soap_probe.py `--discover` |
| SOAP-005 | WS-Security | WS-Security implementation: missing or strippable `wsse:Security`, Timestamp not enforced, Nonce not cached, `PasswordText` over the wire, unsigned Body, signature wrapping exposure | bounded | soap_probe.py strips/alters Security on own message; manual signature-wrapping review |
| SOAP-006 | Replay | Replay of stateful operations (no nonce/timestamp/sequence; same message accepted twice) | bounded | soap_probe.py replays the own read-only request; state-changing replay is authorized-only |
| SOAP-007 | Faults | SOAP fault information disclosure (stack traces, `exceptionDetail`, framework versions, file paths, SQL, internal hosts) | bounded | soap_probe.py malformed XML, wrong types, unknown operation |
| SOAP-008 | Attachments | Attachment handling (SwA multipart/related, MTOM/XOP `xop:Include href`): type checks, size limits, path handling, XOP include of local files | bounded | Harmless files per file-upload-audit; `xop:Include` to own OOB host only |
| SOAP-009 | Encoding / types | Encoding attacks and type confusion: UTF-16/UTF-7/UTF-32 declarations bypassing filters, `xsi:type` changes (string→int/array/anyType), SOAP-ENC arrays, nil handling | bounded | soap_probe.py UTF-16 re-encoding and `xsi:type` variants |
| SOAP-010 | Namespaces | Namespace manipulation for injection: prefix changes, default namespace swap, duplicate elements in other namespaces (validation/signature confusion), envelope version mismatch | bounded | soap_probe.py namespace variants |

## Discovery paths

`?wsdl`, `?WSDL`, `?singleWsdl`, `?wsdl=wsdl0`, `?xsd=xsd0`, `?disco`, `.asmx?WSDL`, `.svc?wsdl`, `/mex`, `/services`, `/services/listServices`, `/axis/services`, `/axis2/services/listServices`, `/cxf/services`, `/ws`, `/soap`, `/webservices`, `/jaxws`, `/ws/*.wsdl`.

## WS-Security review list

| Item | Expected |
|---|---|
| Timestamp | Present, signed, `Expires` short and enforced |
| Nonce | Present with UsernameToken, cached to block replay |
| Password type | Not `PasswordText` (or TLS-only with strong policy) |
| Signed parts | Body, Timestamp, and addressing headers signed |
| Signature references | Resolved by ID strictly; wrapping (duplicate Body elsewhere) rejected |
| Algorithms | No RSA-SHA1/HMAC-SHA1 where avoidable; no `none` |

## Cross-references

| SOAP row | Related rows |
|---|---|
| SOAP-001 | access-control (operation authz), api-security AA-017 |
| SOAP-002 | xml-xxe-audit XML injection rows |
| SOAP-003 | xml-xxe-audit, ssrf-audit |
| SOAP-005 | oauth-sso SAML signature rows, crypto-audit |
| SOAP-006 | race-conditions, business-logic-vulns |
| SOAP-007 | error-handling-audit |
| SOAP-008 | file-upload-audit |
