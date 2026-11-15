#!/usr/bin/env python3
"""Offline SAML message inspector for OA-12..15, OA-21, OA-22, OA-45..47.

Usage:
  saml_inspect.py FILE      # base64 SAMLResponse/SAMLRequest (URL-encoded OK), deflated redirect binding, or raw XML
  saml_inspect.py -         # read from stdin

Reports issuer, destination, InResponseTo, assertions (count, encrypted), signature
placement and algorithms, transforms (XSLT/XPath), embedded certificates, NameID
(including comments), conditions/validity window, audience, subject confirmation,
and DOCTYPE presence. Does not verify signatures (use xmlsec1 for that).
"""
import base64
import re
import sys
import zlib
from datetime import datetime
from urllib.parse import unquote
import xml.etree.ElementTree as ET

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
WEAK_ALGS = ("rsa-sha1", "dsa-sha1", "#sha1", "hmac-sha1", "md5")


def decode(raw):
    raw = raw.strip()
    if raw.startswith("<"):
        return raw
    if "SAMLResponse=" in raw or "SAMLRequest=" in raw:
        raw = re.split(r"SAML(?:Response|Request)=", raw, 1)[1].split("&", 1)[0]
    raw = unquote(raw).replace(" ", "+")
    data = base64.b64decode(raw + "=" * (-len(raw) % 4))
    if data.lstrip().startswith(b"<"):
        return data.decode("utf-8", "replace")
    try:
        return zlib.decompress(data, -15).decode("utf-8", "replace")  # HTTP-Redirect binding (raw DEFLATE)
    except zlib.error:
        sys.exit("could not decode input as XML, base64 XML, or deflated base64")


def local(tag):
    return tag.split("}", 1)[-1] if isinstance(tag, str) else "#comment"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    raw = sys.stdin.read() if sys.argv[1] == "-" else open(sys.argv[1], encoding="utf-8", errors="replace").read()
    xml = decode(raw)
    flags = []
    if re.search(r"<!DOCTYPE", xml, re.I):
        flags.append(("OA-47", "DOCTYPE present in message - SP parser behaviour with DTDs must be checked (XXE)"))
        xml = re.sub(r"<!DOCTYPE[^>\[]*(\[.*?\])?\s*>", "", xml, flags=re.S | re.I)  # never resolve entities here

    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring(xml, parser=parser)
    print(f"# SAML analysis\n\nroot: {local(root.tag)}  ID={root.get('ID')}  Destination={root.get('Destination')}  "
          f"InResponseTo={root.get('InResponseTo')}  IssueInstant={root.get('IssueInstant')}")
    iss = root.find("saml:Issuer", NS)
    print(f"issuer: {iss.text.strip() if iss is not None and iss.text else '-'}")
    st = root.find(".//samlp:StatusCode", NS)
    if st is not None:
        print(f"status: {st.get('Value')}")

    if local(root.tag) == "Response" and not root.get("InResponseTo"):
        flags.append(("OA-21", "no InResponseTo - unsolicited / IdP-initiated response (test login CSRF and replay)"))

    assertions = root.findall(".//saml:Assertion", NS)
    enc = root.findall(".//saml:EncryptedAssertion", NS)
    print(f"assertions: {len(assertions)}  encrypted assertions: {len(enc)}")
    if len(assertions) > 1:
        flags.append(("OA-13", "more than one Assertion in the message - possible wrapping; check which one the SP reads"))

    # Signatures
    ids = {el.get("ID"): local(el.tag) for el in root.iter() if isinstance(el.tag, str) and el.get("ID")}
    sigs = root.findall(".//ds:Signature", NS)
    print(f"\n## Signatures ({len(sigs)})")
    parent_of = {c: p for p in root.iter() for c in p}
    resp_signed = assert_signed = False
    for s in sigs:
        parent = parent_of.get(s)
        ref = s.find(".//ds:Reference", NS)
        uri = ref.get("URI") if ref is not None else None
        target = ids.get((uri or "").lstrip("#"), "?")
        pname = local(parent.tag) if parent is not None else "?"
        sm = s.find(".//ds:SignatureMethod", NS)
        dm = s.find(".//ds:DigestMethod", NS)
        smv = sm.get("Algorithm") if sm is not None else "-"
        dmv = dm.get("Algorithm") if dm is not None else "-"
        print(f"- in <{pname}> Reference URI={uri} -> <{target}>  SignatureMethod={smv}  DigestMethod={dmv}")
        if pname == "Response":
            resp_signed = True
        if pname == "Assertion":
            assert_signed = True
        if parent is not None and uri and uri.lstrip("#") != parent.get("ID"):
            flags.append(("OA-13", f"signature inside <{pname}> references a different element ({uri}) - wrapping indicator"))
        if any(w in (smv + dmv).lower() for w in WEAK_ALGS):
            flags.append(("OA-45", f"weak signature/digest algorithm: {smv} / {dmv}"))
        for t in s.findall(".//ds:Transform", NS):
            alg = t.get("Algorithm", "")
            print(f"    transform: {alg}")
            if "xslt" in alg.lower():
                flags.append(("OA-15", "XSLT transform present inside Signature"))
            if "xpath" in alg.lower():
                flags.append(("OA-15", "XPath transform present (unusual; check processing before verification)"))
        if s.find(".//ds:X509Certificate", NS) is not None:
            flags.append(("OA-45", f"X509Certificate embedded in <{pname}> signature - SP must not trust it (test self-signed re-signing)"))
    if not sigs:
        flags.append(("OA-45", "message is not signed at all"))
    elif not assert_signed and assertions:
        flags.append(("OA-45", "assertion(s) not individually signed (only Response) - test assertion manipulation/XSW"))
    elif not resp_signed and local(root.tag) == "Response":
        print("note: Response envelope unsigned (common); Destination/InResponseTo are then unprotected unless assertion covers them")

    # Assertion details
    for i, a in enumerate(assertions, 1):
        print(f"\n## Assertion {i}  ID={a.get('ID')}")
        ai = a.find("saml:Issuer", NS)
        print(f"issuer: {ai.text.strip() if ai is not None and ai.text else '-'}")
        nid = a.find(".//saml:Subject/saml:NameID", NS)
        if nid is not None:
            parts = [nid.text or ""]
            has_comment = False
            for c in nid:
                if c.tag is ET.Comment:
                    has_comment = True
                    parts.append(f"<!--{c.text}-->")
                parts.append(c.tail or "")
            full = "".join(parts)
            print(f"NameID: {full!r}  Format={nid.get('Format')}")
            print(f"  first text node only (what a vulnerable SP may read): {(nid.text or '')!r}")
            if has_comment:
                flags.append(("OA-22", "comment inside NameID - truncation / comment-injection candidate"))
        cond = a.find("saml:Conditions", NS)
        if cond is not None:
            nb, na = cond.get("NotBefore"), cond.get("NotOnOrAfter")
            print(f"conditions: NotBefore={nb} NotOnOrAfter={na}")
            try:
                f = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
                if nb and na:
                    win = (f(na) - f(nb)).total_seconds()
                    print(f"  validity window: {win / 60:.1f} min")
                    if win > 3600:
                        flags.append(("OA-14", f"long assertion validity window ({win / 3600:.1f} h) - replay exposure"))
            except ValueError:
                pass
            aud = [x.text for x in cond.findall(".//saml:Audience", NS)]
            print(f"audience: {aud or '-'}")
            if not aud:
                flags.append(("OA-46", "no AudienceRestriction - test cross-SP assertion reuse"))
        else:
            flags.append(("OA-46", "assertion has no Conditions element"))
        for sc in a.findall(".//saml:SubjectConfirmationData", NS):
            print(f"subject confirmation: Recipient={sc.get('Recipient')} NotOnOrAfter={sc.get('NotOnOrAfter')} "
                  f"InResponseTo={sc.get('InResponseTo')}")
            if not sc.get("Recipient"):
                flags.append(("OA-46", "SubjectConfirmationData without Recipient"))
        attrs = a.findall(".//saml:Attribute", NS)
        if attrs:
            print("attributes:")
            for at in attrs:
                vals = [v.text for v in at.findall("saml:AttributeValue", NS)]
                print(f"  - {at.get('Name')}: {vals}")
                if any(v and re.search(r"[<>&]", v) for v in vals):
                    flags.append(("OA-12", f"attribute {at.get('Name')} contains XML metacharacters"))

    print("\n## Flags")
    for cid, msg in flags or [("-", "none")]:
        print(f"- **{cid}** {msg}")


if __name__ == "__main__":
    main()
