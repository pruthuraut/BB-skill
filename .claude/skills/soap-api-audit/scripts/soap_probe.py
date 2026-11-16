#!/usr/bin/env python3
"""SOAP / XML web service probe (SOAP rows), scope-gated.

  --discover            WSDL/disco/MEX/service-list paths on --url; parse operations, SOAPActions,
                        target namespace, soap:address locations, imports (SOAP-004)
  --wsdl FILE|URL       parse a WSDL you already have
  --request FILE        your own harmless envelope; FUZZ marks one string value
  --action VALUE        SOAPAction of that request
Tests on --request:
  faults (SOAP-007), action spoofing with other WSDL actions and empty action (SOAP-001),
  XML injection markers at FUZZ (SOAP-002), internal entity and optional --oob entity (SOAP-003),
  replay (SOAP-006), WS-Security stripping / expired timestamp (SOAP-005),
  UTF-16 and xsi:type variants (SOAP-009), namespace/prefix variants (SOAP-010).

Example:
  soap_probe.py --target example.com --url https://api.example.com/UserService.svc --discover \
     --request own.xml --action "http://example.com/IUserService/GetProfile" --header 'Cookie: session=OWN'
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
WSDL_SUFFIXES = ["?wsdl", "?WSDL", "?singleWsdl", "?wsdl=wsdl0", "?disco", "/mex", "?xsd=xsd0"]
LIST_PATHS = ["/services", "/services/listServices", "/axis/services", "/axis2/services/listServices", "/cxf/services", "/ws", "/soap", "/webservices"]
LEAK = re.compile(r"(?is)<(?:\w+:)?(?:detail|stackTrace|exceptionDetail|StackTrace|Message)>.{0,400}|at [\w.$]+\([\w.]+:\d+\)|"
                  r"System\.\w+Exception|java\.\w+\.\w+Exception|org\.apache\.(?:axis|cxf)|Microsoft\.\w+|SQLSTATE|ORA-\d{5}|"
                  r"[A-Z]:\\[\w\\]+|/var/www|/opt/\w+|/usr/local/\w+|\b10\.\d+\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b")
NS = {"wsdl": "http://schemas.xmlsoap.org/wsdl/", "soap": "http://schemas.xmlsoap.org/wsdl/soap/", "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
      "wsdl2": "http://www.w3.org/ns/wsdl"}


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class C:
    def __init__(self, a):
        self.a, self.n = a, 0

    def req(self, url, method="GET", body=None, headers=None):
        if self.n:
            time.sleep(self.a.delay)
        self.n += 1
        p = urlsplit(url)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if self.a.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=self.a.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=self.a.timeout)
        h = {"User-Agent": "Mozilla/5.0 soap-api-audit"}
        for hv in self.a.header:
            k, _, v = hv.partition(":")
            h[k.strip()] = v.strip()
        h.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read(3_000_000)
            return {"status": r.status, "text": data.decode("utf-8", errors="replace"), "sha": hashlib.sha1(data).hexdigest()[:12], "len": len(data)}
        except Exception as e:
            return {"status": None, "text": "", "sha": "", "len": 0, "error": str(e)}
        finally:
            conn.close()


def parse_wsdl(text):
    out = {"operations": [], "actions": {}, "addresses": [], "target_ns": None, "imports": []}
    try:
        root = ET.fromstring(text.encode("utf-8", errors="replace"))
    except ET.ParseError:
        return None
    out["target_ns"] = root.get("targetNamespace")
    for op in root.iter():
        tag = op.tag.split("}")[-1]
        if tag == "operation" and op.get("name"):
            for child in op:
                ct = child.tag.split("}")[-1]
                if ct == "operation" and child.get("soapAction") is not None:
                    out["actions"][op.get("name")] = child.get("soapAction")
            if op.get("name") not in out["operations"]:
                out["operations"].append(op.get("name"))
        if tag == "address" and op.get("location"):
            out["addresses"].append(op.get("location"))
        if tag in ("import", "include") and (op.get("location") or op.get("schemaLocation")):
            out["imports"].append(op.get("location") or op.get("schemaLocation"))
    return out


def ctype_for(body, action):
    if "http://www.w3.org/2003/05/soap-envelope" in body:
        return {"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'}
    return {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{action}"'}


def is_fault(t):
    return bool(re.search(r"<(?:\w+:)?Fault\b", t))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="service endpoint")
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--wsdl")
    ap.add_argument("--request")
    ap.add_argument("--action", default="")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--oob", help="your own OOB host for the external entity probe")
    ap.add_argument("--max-spoof", type=int, default=5)
    ap.add_argument("--delay", type=float, default=0.4)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    target = a.target.lower()
    host = (urlsplit(a.url).hostname or "").lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, a.workspace, target)
    c = C(a)
    F: list[str] = []
    rep: dict = {"url": a.url}
    wsdl = None

    if a.discover:
        found = []
        base = a.url.split("?")[0]
        for suf in WSDL_SUFFIXES:
            r = c.req(base + suf)
            if r["status"] == 200 and re.search(r"<(\w+:)?(definitions|description|discovery|schema)\b|Metadata", r["text"]):
                found.append(base + suf)
                if wsdl is None and re.search(r"<(\w+:)?(definitions|description)\b", r["text"]):
                    wsdl = parse_wsdl(r["text"])
        p = urlsplit(a.url)
        for lp in LIST_PATHS:
            r = c.req(f"{p.scheme}://{p.netloc}{lp}")
            if r["status"] == 200 and re.search(r"(?i)wsdl|available (soap )?services|service list", r["text"]):
                found.append(f"{p.scheme}://{p.netloc}{lp}")
        rep["discovered"] = found
        if found:
            F.append(f"SOAP-004: service description/listing exposed: {found}")
    if a.wsdl and wsdl is None:
        text = open(a.wsdl, encoding="utf-8").read() if os.path.exists(a.wsdl) else c.req(a.wsdl)["text"]
        wsdl = parse_wsdl(text)
    if wsdl:
        rep["wsdl"] = wsdl
        print(f"WSDL: {len(wsdl['operations'])} operations, {len(wsdl['actions'])} actions, addresses {wsdl['addresses']}")
        internal = [x for x in wsdl["addresses"] if re.search(r"localhost|127\.0\.0\.1|\b10\.|\b192\.168\.|\.local\b|\.internal\b|\.corp\b|:\d{4,5}/", x)
                    or (urlsplit(x).hostname and urlsplit(x).hostname.lower() != host)]
        if internal:
            F.append(f"SOAP-004: WSDL exposes internal/other endpoint addresses: {internal[:5]}")
        priv = [o for o in wsdl["operations"] if re.search(r"(?i)admin|delete|remove|set_?role|grant|export|debug|internal|reset|impersonat|config", o)]
        if priv:
            F.append(f"SOAP-004 lead: privileged-looking operations to test for authorization: {priv[:10]}")

    if a.request:
        tmpl = open(a.request, encoding="utf-8").read()
        fill = lambda v: tmpl.replace("FUZZ", v)
        base_body = fill("smxbase")
        base = c.req(a.url, "POST", base_body.encode(), ctype_for(base_body, a.action))
        rep["baseline"] = {"status": base["status"], "fault": is_fault(base["text"])}
        print(f"baseline {base['status']} fault={is_fault(base['text'])}")
        if base["status"] is None:
            print(f"baseline failed: {base.get('error')}")
        # faults
        fres = []
        for label, body, hd in (("malformed", base_body.replace("</", "<", 1).encode(), ctype_for(base_body, a.action)),
                                ("unknown-op", re.sub(r"(<(?:\w+:)?Body[^>]*>\s*<)([\w:]+)", r"\1\2SmxUnknown", base_body, count=1).encode(), ctype_for(base_body, a.action)),
                                ("bad-type", fill("-999999999999999999999" + "A" * 300).encode(), ctype_for(base_body, a.action)),
                                ("not-xml", b"smx-not-xml", {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{a.action}"'})):
            r = c.req(a.url, "POST", body, hd)
            leaks = sorted(set(m.group(0)[:80] for m in LEAK.finditer(r["text"])))
            fres.append({"case": label, "status": r["status"], "leaks": leaks[:5]})
            if leaks:
                F.append(f"SOAP-007: {label} fault discloses {leaks[:3]}")
        rep["faults"] = fres
        # action spoofing
        if wsdl and wsdl["actions"]:
            sres = []
            others = [v for k, v in wsdl["actions"].items() if v and v != a.action][: a.max_spoof]
            for act in others + [""]:
                r = c.req(a.url, "POST", base_body.encode(), ctype_for(base_body, act))
                same = r["sha"] == base["sha"]
                sres.append({"action": act, "status": r["status"], "same_as_baseline": same, "fault": is_fault(r["text"])})
                if r["status"] == base["status"] and not is_fault(r["text"]) and act != a.action:
                    F.append(f"SOAP-001: body operation executed with SOAPAction '{act}' (action not validated against body)")
            rep["action_spoofing"] = sres
        # XML injection
        if "FUZZ" in tmpl:
            ires = []
            mk = "smx" + secrets.token_hex(3)
            for label, val in (("tag-close", f"{mk}</x><smxInjected>1</smxInjected><x>"), ("cdata", f"{mk}]]><smx>1</smx><![CDATA["),
                               ("comment", f"{mk}<!--"), ("entity-escaped", f"{mk}&lt;b&gt;"), ("raw-lt", f"{mk}<b>")):
                body = fill(val)
                r = c.req(a.url, "POST", body.encode(), ctype_for(body, a.action))
                refl = f"<smxInjected>1</smxInjected>" in r["text"] or (label == "raw-lt" and f"{mk}<b>" in r["text"])
                ires.append({"payload": label, "status": r["status"], "fault": is_fault(r["text"]), "reflected_raw": refl})
                if refl:
                    F.append(f"SOAP-002: {label} payload reflected unescaped in the response")
                if label == "tag-close" and r["status"] == base["status"] and not is_fault(r["text"]) and r["sha"] != base["sha"]:
                    F.append("SOAP-002 lead: injected element accepted without fault and changed the response")
            rep["xml_injection"] = ires
            # internal entity
            m = re.match(r"\s*(<\?xml[^>]*\?>)?\s*", tmpl)
            decl = m.group(1) or ""
            rest = tmpl[m.end():]
            root_name = re.match(r"<([\w:]+)", rest).group(1)
            ent_body = f'{decl}\n<!DOCTYPE {root_name} [<!ENTITY smx "smx-entity-expanded">]>\n' + rest.replace("FUZZ", "&smx;")
            r = c.req(a.url, "POST", ent_body.encode(), ctype_for(ent_body, a.action))
            rep["internal_entity"] = {"status": r["status"], "expanded": "smx-entity-expanded" in r["text"], "fault": is_fault(r["text"])}
            if "smx-entity-expanded" in r["text"]:
                F.append("SOAP-003: DTD processed and internal entity expanded in the response (XXE likely; use xml-xxe-audit)")
            elif r["status"] == base["status"] and not is_fault(r["text"]):
                F.append("SOAP-003 lead: DOCTYPE accepted without fault (DTDs not rejected); test OOB with --oob")
            if a.oob:
                oob_body = f'{decl}\n<!DOCTYPE {root_name} [<!ENTITY % x SYSTEM "http://{a.oob}/soap-{secrets.token_hex(3)}"> %x;]>\n' + rest.replace("FUZZ", "smx")
                r = c.req(a.url, "POST", oob_body.encode(), ctype_for(oob_body, a.action))
                rep["oob_entity"] = {"status": r["status"], "note": f"check {a.oob} for an HTTP/DNS hit"}
        # replay
        r2 = c.req(a.url, "POST", base_body.encode(), ctype_for(base_body, a.action))
        rep["replay"] = {"status": r2["status"], "identical": r2["sha"] == base["sha"]}
        if r2["status"] == base["status"] and not is_fault(r2["text"]):
            has_ts = re.search(r"Timestamp|Nonce", tmpl)
            F.append("SOAP-006 lead: identical message accepted twice" + ("" if has_ts else " and it carries no Timestamp/Nonce"))
        # WS-Security
        if re.search(r"<(\w+:)?Security\b", tmpl):
            stripped = re.sub(r"(?s)<(\w+:)?Security\b.*?</(\w+:)?Security>", "", base_body)
            r = c.req(a.url, "POST", stripped.encode(), ctype_for(stripped, a.action))
            ws = {"stripped_status": r["status"], "stripped_fault": is_fault(r["text"])}
            if r["status"] == base["status"] and not is_fault(r["text"]):
                F.append("SOAP-005: request accepted with the wsse:Security header removed")
            if re.search(r"Expires>", base_body):
                expired = re.sub(r"(<(?:\w+:)?Expires>)[^<]+", r"\g<1>2001-01-01T00:00:00Z", base_body)
                r = c.req(a.url, "POST", expired.encode(), ctype_for(expired, a.action))
                ws["expired_status"] = r["status"]
                if r["status"] == base["status"] and not is_fault(r["text"]):
                    F.append("SOAP-005: expired wsu:Timestamp accepted")
            if "#PasswordText" in tmpl:
                F.append("SOAP-005 info: UsernameToken uses PasswordText")
            rep["wssecurity"] = ws
        elif base["status"] == 200 and not is_fault(base["text"]):
            rep["wssecurity"] = "no wsse:Security in sample"
        # encoding / types
        eres = []
        u16 = re.sub(r'encoding="[^"]+"', 'encoding="UTF-16"', base_body) if "encoding=" in base_body else '<?xml version="1.0" encoding="UTF-16"?>' + base_body
        hd = ctype_for(base_body, a.action)
        hd = {k: (v.replace("utf-8", "utf-16") if k == "Content-Type" else v) for k, v in hd.items()}
        r = c.req(a.url, "POST", u16.encode("utf-16"), hd)
        eres.append({"case": "utf-16", "status": r["status"], "fault": is_fault(r["text"])})
        if "FUZZ" in tmpl:
            typed = re.sub(r"<([\w:]+)([^>]*)>FUZZ<", r'<\1\2 xsi:type="xsd:int" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">smx<', tmpl, count=1)
            r = c.req(a.url, "POST", typed.encode(), ctype_for(typed, a.action))
            leaks = [m.group(0)[:60] for m in LEAK.finditer(r["text"])]
            eres.append({"case": "xsi:type int on string", "status": r["status"], "fault": is_fault(r["text"]), "leaks": leaks[:3]})
            if leaks:
                F.append(f"SOAP-009/SOAP-007: xsi:type confusion fault discloses {leaks[:2]}")
        rep["encoding"] = eres
        if eres and eres[0]["status"] == base["status"] and not eres[0]["fault"]:
            F.append("SOAP-009 info: UTF-16 encoded message accepted (check WAF/filters inspect UTF-16 bodies)")
        # namespaces
        nres = []
        m2 = re.search(r"<(\w+):Envelope", base_body)
        if m2:
            pfx = m2.group(1)
            renamed = re.sub(rf"(</?){pfx}:", r"\1smxns:", base_body).replace(f"xmlns:{pfx}=", "xmlns:smxns=")
            r = c.req(a.url, "POST", renamed.encode(), ctype_for(renamed, a.action))
            nres.append({"case": "envelope prefix renamed", "status": r["status"], "fault": is_fault(r["text"])})
            if "schemas.xmlsoap.org/soap/envelope" in base_body:
                v12 = base_body.replace("http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/2003/05/soap-envelope")
                r = c.req(a.url, "POST", v12.encode(), {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{a.action}"'})
                nres.append({"case": "1.2 envelope with 1.1 content-type", "status": r["status"], "fault": is_fault(r["text"])})
                if r["status"] == base["status"] and not is_fault(r["text"]):
                    F.append("SOAP-010 info: SOAP 1.2 envelope accepted with a SOAP 1.1 Content-Type (lenient envelope handling)")
        rep["namespaces"] = nres

    F = list(dict.fromkeys(F))
    rep["findings"], rep["requests"] = F, c.n
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    print(f"requests sent: {c.n}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
