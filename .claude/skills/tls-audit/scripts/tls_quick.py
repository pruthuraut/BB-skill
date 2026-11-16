#!/usr/bin/env python3
"""Quick TLS and HTTPS-layer check with the Python ssl module.

Checks (TLSX IDs in brackets):
  - protocol acceptance TLS 1.0/1.1/1.2/1.3 [001] (limited by the local OpenSSL build)
  - weak cipher acceptance RC4/3DES/DES/NULL/EXPORT where the local OpenSSL still has them [002, 015]
  - negotiated protocol and cipher, forward secrecy [014], TLS compression [020]
  - certificate: trust, hostname, expiry, SAN, wildcard, key size, signature, OCSP/CRL URLs [008, 009, 012, E-008]
  - HSTS on HTTPS, HTTP->HTTPS redirect, Set-Cookie Secure, mixed content on the landing page [007, 010, 011, E-009]
Local OpenSSL builds often refuse TLS 1.0/1.1 and legacy ciphers; such results
are reported as "not testable locally" — confirm with testssl.sh.

Safety: host must be the target or its subdomain and pass scripts/scope_check.sh.
A handful of handshakes and two HTTP requests.

Example:
  tls_quick.py --target example.com --host www.example.com --out artifacts/example.com/tls_quick.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
WEAK_CIPHER_SETS = {"RC4": "RC4", "3DES (Sweet32)": "3DES", "DES": "DES", "NULL": "eNULL", "EXPORT": "EXP", "anon": "aNULL"}


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def handshake(host: str, port: int, version=None, ciphers: str | None = None, verify=False, timeout=10.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if verify:
        ctx = ssl.create_default_context()
    try:
        if version is not None:
            ctx.minimum_version = version
            ctx.maximum_version = version
        if ciphers:
            ctx.set_ciphers(ciphers + ":@SECLEVEL=0")
        elif version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError) as e:
        return {"result": "not testable locally", "detail": str(e)}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return {"result": "accepted", "protocol": s.version(), "cipher": s.cipher(),
                        "compression": s.compression(), "cert_der": s.getpeercert(binary_form=True),
                        "cert": s.getpeercert() if verify else None}
    except ssl.SSLCertVerificationError as e:
        return {"result": "cert-verify-failed", "detail": e.verify_message}
    except ssl.SSLError as e:
        msg = str(e)
        if re.search(r"NO_PROTOCOLS_AVAILABLE|UNSUPPORTED_PROTOCOL|NO_CIPHERS_AVAILABLE|no ciphers available", msg, re.I):
            return {"result": "not testable locally", "detail": msg}
        return {"result": "rejected", "detail": msg}
    except OSError as e:
        return {"result": "error", "detail": str(e)}


def cert_details(der: bytes) -> dict:
    out: dict = {}
    try:
        from cryptography import x509  # optional
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        c = x509.load_der_x509_certificate(der)
        pk = c.public_key()
        out["key"] = (f"RSA {pk.key_size}" if isinstance(pk, rsa.RSAPublicKey)
                      else f"EC {pk.curve.name}" if isinstance(pk, ec.EllipticCurvePublicKey) else type(pk).__name__)
        out["signature_algorithm"] = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "unknown"
        try:
            aia = c.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            out["ocsp_urls"] = [d.access_location.value for d in aia if d.access_method._name == "OCSP"]
        except Exception:
            out["ocsp_urls"] = []
        try:
            crl = c.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            out["crl_urls"] = [n.value for d in crl for n in (d.full_name or [])]
        except Exception:
            out["crl_urls"] = []
        try:
            c.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
            out["embedded_scts"] = True
        except Exception:
            out["embedded_scts"] = False
    except ImportError:
        out["note"] = "install 'cryptography' for key size, signature, OCSP/CRL, and SCT details"
    return out


def http_get(host: str, scheme: str, path: str = "/", timeout=10.0):
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(host, 80, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 tls-audit"})
        r = conn.getresponse()
        body = r.read(500_000).decode("utf-8", errors="replace")
        return r.status, r.getheaders(), body
    except Exception as e:
        return None, [], str(e)
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--workspace")
    ap.add_argument("--no-http", action="store_true", help="skip HSTS/redirect/cookie/mixed-content checks")
    ap.add_argument("--out")
    args = ap.parse_args()
    host, target = args.host.lower(), args.target.lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, args.target.lower())

    rep: dict = {"host": host, "port": args.port, "findings": []}
    add = lambda tid, msg: rep["findings"].append(f"{tid}: {msg}")

    protos = {}
    for name, v in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                    ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]:
        r = handshake(host, args.port, v)
        protos[name] = r["result"] + (f" ({r.get('detail', '')[:80]})" if r["result"] not in ("accepted", "rejected") else "")
    rep["protocols"] = protos
    if all(v.startswith("error") for v in protos.values()):
        print(f"cannot connect to {host}:{args.port}: {protos['TLSv1.2']}")
        return 2
    for old in ("TLSv1.0", "TLSv1.1"):
        if protos[old].startswith("accepted"):
            add("TLSX-001", f"{old} accepted")
    if not protos["TLSv1.2"].startswith("accepted") and not protos["TLSv1.3"].startswith("accepted"):
        add("TLSX-001", "neither TLS 1.2 nor 1.3 accepted")

    weak = {}
    for label, spec in WEAK_CIPHER_SETS.items():
        r = handshake(host, args.port, ssl.TLSVersion.TLSv1_2, ciphers=spec)
        weak[label] = r["result"] + (f" {r['cipher'][0]}" if r.get("cipher") else "")
        if r["result"] == "accepted":
            add("TLSX-015" if "3DES" in label else "TLSX-002", f"weak cipher accepted: {r['cipher'][0]}")
    rep["weak_ciphers"] = weak

    d = handshake(host, args.port)
    if d["result"] == "accepted":
        cipher = d["cipher"][0]
        rep["negotiated"] = {"protocol": d["protocol"], "cipher": cipher, "bits": d["cipher"][2], "compression": d["compression"]}
        if d["protocol"] != "TLSv1.3" and not re.search(r"ECDHE|DHE", cipher):
            add("TLSX-014", f"default negotiated cipher lacks forward secrecy: {cipher}")
        if d["compression"]:
            add("TLSX-020", f"TLS compression enabled: {d['compression']}")
        rep["certificate"] = cert_details(d["cert_der"])
        k = rep["certificate"].get("key", "")
        m = re.match(r"RSA (\d+)", k)
        if m and int(m.group(1)) < 2048:
            add("TLSX-E-008", f"RSA key {m.group(1)} bits")
        if rep["certificate"].get("signature_algorithm") in ("sha1", "md5"):
            add("TLSX-008", f"weak signature algorithm {rep['certificate']['signature_algorithm']}")
        if rep["certificate"].get("embedded_scts") is False:
            rep["certificate"]["note_ct"] = "no embedded SCTs (may be delivered via TLS extension or OCSP; confirm with testssl -S)"
        if "ocsp_urls" in rep["certificate"] and not rep["certificate"]["ocsp_urls"] and not rep["certificate"].get("crl_urls"):
            add("TLSX-012", "no OCSP or CRL URL in certificate")
    else:
        rep["negotiated"] = d

    v = handshake(host, args.port, verify=True)
    if v["result"] == "cert-verify-failed":
        add("TLSX-008", f"certificate verification failed: {v.get('detail')}")
    elif v["result"] == "accepted" and v.get("cert"):
        c = v["cert"]
        exp = dt.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        days = (exp - dt.datetime.now(dt.timezone.utc)).days
        sans = [x[1] for x in c.get("subjectAltName", [])]
        rep["certificate"] = {**rep.get("certificate", {}), "not_after": c["notAfter"], "days_left": days,
                              "issuer": dict(x[0] for x in c["issuer"]).get("organizationName"), "san": sans}
        if days < 30:
            add("TLSX-008", f"certificate expires in {days} days")
        wild = [s for s in sans if s.startswith("*.")]
        if wild:
            add("TLSX-009", f"wildcard certificate {wild}: list hosts sharing it (crt.sh) and check low-trust holders")

    if not args.no_http and args.port == 443:
        st, hdrs, body = http_get(host, "https")
        h = {}
        for k, val in hdrs:
            h.setdefault(k.lower(), []).append(val)
        hsts = (h.get("strict-transport-security") or [""])[0]
        rep["hsts"] = hsts or None
        if not hsts:
            add("TLSX-007", "HSTS header missing")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 31536000:
                add("TLSX-007", f"HSTS max-age below 1 year: '{hsts}'")
            if "includesubdomains" not in hsts.lower():
                add("TLSX-007", "HSTS without includeSubDomains")
        for ck in h.get("set-cookie", []):
            if "secure" not in [p.strip().lower() for p in ck.split(";")[1:]]:
                add("TLSX-011", f"cookie without Secure: {ck.split(';')[0].split('=')[0]}")
        mixed = sorted(set(re.findall(r"""<(?:script|link|iframe|img|form|embed|object|source)[^>]+(?:src|href|action)\s*=\s*["'](http://[^"']+)""", body, re.I)))
        if mixed:
            add("TLSX-010", f"{len(mixed)} http:// subresources on landing page, e.g. {mixed[:3]}")
        rep["mixed_content"] = mixed[:50]
        st80, hdrs80, _ = http_get(host, "http")
        loc = dict((k.lower(), v) for k, v in hdrs80).get("location", "")
        rep["http_redirect"] = {"status": st80, "location": loc}
        if st80 is not None and not (st80 in (301, 302, 307, 308) and loc.startswith("https://")):
            add("TLSX-E-009", f"HTTP does not redirect to HTTPS (status {st80}, location '{loc}')")
        for k, val in hdrs80:
            if k.lower() == "set-cookie":
                add("TLSX-011", f"cookie set over plain HTTP: {val.split(';')[0].split('=')[0]}")

    print(json.dumps({k: v for k, v in rep.items() if k != "findings"}, indent=2, default=str)[:4000])
    print("findings:")
    for f in rep["findings"] or ["none from quick check (run testssl.sh for full coverage)"]:
        print(f"  - {f}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
