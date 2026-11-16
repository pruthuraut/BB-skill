#!/usr/bin/env python3
"""Map testssl.sh JSON output to tls-audit checklist IDs (offline).

Input: one or more files written by `testssl.sh --jsonfile FILE ...` (flat
list) or `--jsonfile-pretty` (object with scanResult). Each testssl finding id
is matched against the rules below; findings with severity other than OK/INFO
are reported under their TLSX ID. Unmapped non-OK findings are listed as
"other" so nothing is lost.

Example:
  tls_map_testssl.py artifacts/example.com/testssl_www.json --out artifacts/example.com/tls_mapped.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys

RULES = [
    (r"^(SSLv2|SSLv3|TLS1|TLS1_1)$", "TLSX-001", "Old protocol offered"),
    (r"^(TLS1_2|TLS1_3)$", "TLSX-001", "Modern protocol support"),
    (r"^(cipherlist_(NULL|aNULL|EXPORT|LOW|3DES_IDEA|OBSOLETED|AVERAGE)|RC4|cipher_order.*|cipher-.*rc4.*)$", "TLSX-002", "Weak ciphers"),
    (r"^POODLE", "TLSX-003", "POODLE"),
    (r"^BEAST", "TLSX-004", "BEAST"),
    (r"^BREACH", "TLSX-005", "BREACH"),
    (r"^CRIME", "TLSX-020", "TLS compression (CRIME)"),
    (r"^heartbleed", "TLSX-006", "Heartbleed"),
    (r"^HSTS", "TLSX-007", "HSTS"),
    (r"^cert_(notAfter|notBefore|expirationStatus|chain_of_trust|trust|signatureAlgorithm|commonName|subjectAltName|caIssuers|validityPeriod)", "TLSX-008", "Certificate"),
    (r"^(cert_keySize|cert_keyUsage)", "TLSX-E-008", "Key size / usage"),
    (r"^(cert_crlDistributionPoints|cert_ocspURL|OCSP_stapling|cert_mustStapleExtension|cert_ocspRevoked|cert_crlRevoked)", "TLSX-012", "Revocation"),
    (r"^(FS|FS_ciphers|FS_ECDHE_curves|DH_groups|FS_TLS12_sig_algs)", "TLSX-014", "Forward secrecy"),
    (r"^SWEET32", "TLSX-015", "Sweet32"),
    (r"^certificate_transparency", "TLSX-016", "Certificate Transparency"),
    (r"^fallback_SCSV", "TLSX-017", "Downgrade protection"),
    (r"^secure_client_renego", "TLSX-018", "Client-initiated renegotiation"),
    (r"^secure_renego", "TLSX-019", "Secure renegotiation (RFC 5746)"),
    (r"^ROBOT", "TLSX-E-001", "ROBOT"),
    (r"^FREAK", "TLSX-E-002", "FREAK"),
    (r"^LOGJAM", "TLSX-E-003", "Logjam"),
    (r"^DROWN", "TLSX-E-004", "DROWN"),
    (r"^ticketbleed", "TLSX-E-005", "Ticketbleed"),
    (r"^CCS", "TLSX-E-006", "CCS injection"),
    (r"^LUCKY13", "TLSX-E-007", "Lucky13"),
    (r"^cipher_order", "TLSX-E-012", "Cipher order"),
]
RULES_RE = [(re.compile(p, re.I), i, t) for p, i, t in RULES]
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARN": 4, "INFO": 5, "OK": 6}


def load(path: str) -> list[dict]:
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, list):
        return data
    out = []
    for sr in data.get("scanResult", []):
        for key, val in sr.items():
            if isinstance(val, list):
                for f in val:
                    if isinstance(f, dict) and "id" in f:
                        f.setdefault("ip", sr.get("ip")); f.setdefault("port", sr.get("port"))
                        out.append(f)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--all", action="store_true", help="also list OK and INFO findings")
    ap.add_argument("--out")
    args = ap.parse_args()

    mapped: dict[str, list] = {}
    other = []
    for path in args.files:
        for f in load(path):
            fid, sev = str(f.get("id", "")), str(f.get("severity", "INFO")).upper()
            if fid in ("scanTime", "engine_problem", "scanProblem", "service", "pre_128cipher") or fid.startswith("clientsimulation"):
                continue
            rec = {"id": fid, "severity": sev, "finding": f.get("finding", ""), "host": f.get("ip", ""),
                   "port": f.get("port", ""), "cve": f.get("cve", ""), "file": path}
            hit = next(((i, t) for r, i, t in RULES_RE if r.search(fid)), None)
            # TLS1_2/TLS1_3 "not offered" is a problem; "offered" is fine
            if hit and fid in ("TLS1_2", "TLS1_3"):
                if "not offered" in rec["finding"].lower() and fid == "TLS1_2":
                    rec["severity"] = sev = "MEDIUM"
            if not args.all and sev in ("OK", "INFO"):
                continue
            if hit:
                mapped.setdefault(hit[0], []).append({**rec, "title": hit[1]})
            elif sev not in ("OK", "INFO"):
                other.append(rec)

    def key(k: str) -> tuple:
        return (0 if k.startswith("TLSX-0") else 1, k)

    for tid in sorted(mapped, key=key):
        items = sorted(mapped[tid], key=lambda x: SEV_ORDER.get(x["severity"], 9))
        print(f"{tid}  {items[0]['title']}")
        for x in items:
            print(f"    [{x['severity']}] {x['id']}: {x['finding'][:140]}  {x['host']}:{x['port']}")
    if other:
        print("other (unmapped, not OK):")
        for x in other:
            print(f"    [{x['severity']}] {x['id']}: {x['finding'][:140]}")
    if not mapped and not other:
        print("no findings above INFO")
    if args.out:
        json.dump({"mapped": mapped, "other": other}, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
