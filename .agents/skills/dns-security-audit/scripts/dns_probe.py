#!/usr/bin/env python3
"""DNS security probe for authorized nameservers and zones (Kali: dig, dnsrecon, nmap, openssl).

Read-only queries only. No amplification, no spoofing, no rate floods.
Scope gate runs first. Zone transfer and open-recursion checks are sent only to
nameservers of an in-scope zone.

Checks: AXFR (bounded), DNSSEC signature presence, TXT/SRV/PTR/NAPTR/DNAME/CNAME
records, wildcard detection, open recursion (nmap dns-recursion), DNS cookie
support (dig +cookie), DoT reachability (TCP 853 via openssl), DoH endpoint
probe, query name minimization hint (dig +trace).

Example:
  dns_probe.py --target example.com --workspace ~/Documents/bugbounty --out artifacts/example.com/dns.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
SRV_COMMON = ["_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_kerberos._tcp",
              "_ldap._tcp", "_imaps._tcp", "_submission._tcp", "_autodiscover._tcp", "_caldav._tcp"]


def run(cmd: list[str], timeout: int = 20) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def dig(name: str, rtype: str, server: str | None = None, extra: list[str] | None = None) -> str:
    cmd = ["dig", "+time=5", "+tries=1"] + (extra or []) + [name, rtype]
    if server:
        cmd.insert(1, f"@{server}")
    return run(cmd)


def nameservers(zone: str) -> list[str]:
    out = dig(zone, "NS", extra=["+short"])
    return [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="zone name, for example example.com")
    ap.add_argument("--workspace")
    ap.add_argument("--ip", action="append", default=[], help="in-scope IP for PTR checks")
    ap.add_argument("--axfr", action="store_true", help="attempt zone transfer (only if the program allows zone checks)")
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    zone = args.target
    ns = nameservers(zone)
    report: dict = {"zone": zone, "nameservers": ns, "checks": {}}

    # AXFR (bounded): only with --axfr and only against the zone's own nameservers
    axfr = {}
    for server in ns:
        if args.axfr and shutil.which("dig"):
            out = run(["dig", f"@{server}", zone, "AXFR", "+time=5"], timeout=30)
            axfr[server] = "transfer-returned-records" if ("IN" in out and "Transfer failed" not in out and "XFR size" in out) else "refused-or-not-run"
        else:
            axfr[server] = "not-run (pass --axfr when the program allows zone checks)" if not args.axfr else "dig missing"
    report["checks"]["AXFR-001 zone transfer"] = axfr

    # DNSSEC presence
    dnssec = dig(zone, "DNSKEY", extra=["+dnssec", "+short"])
    report["checks"]["DNSSEC-001 DNSKEY present"] = "yes" if dnssec.strip() else "no"

    # TXT, SRV, CAA, NAPTR, CNAME, DNAME summaries
    report["checks"]["TXT-001 records"] = [l for l in dig(zone, "TXT", extra=["+short"]).splitlines() if l.strip()][:20]
    report["checks"]["CAA-001 records"] = [l for l in dig(zone, "CAA", extra=["+short"]).splitlines() if l.strip()]
    report["checks"]["NAPTR-001 records"] = [l for l in dig(zone, "NAPTR", extra=["+short"]).splitlines() if l.strip()]
    report["checks"]["DNAME-001 records"] = [l for l in dig(zone, "DNAME", extra=["+short"]).splitlines() if l.strip()]
    srv_hits = {}
    for svc in SRV_COMMON:
        out = dig(f"{svc}.{zone}", "SRV", extra=["+short"]).strip()
        if out:
            srv_hits[svc] = out.splitlines()
    report["checks"]["SRV-001 common services"] = srv_hits

    # Wildcard detection with a random label
    rnd = "wc" + secrets.token_hex(5) + "." + zone
    wild = dig(rnd, "A", extra=["+short"]).strip()
    report["checks"]["WILDCARD-001 random label resolves"] = bool(wild)

    # PTR for in-scope IPs
    report["checks"]["PTR-001 reverse lookups"] = {ip: dig(ip, "PTR", extra=["+short", "-x"]).strip() for ip in args.ip}

    # DNS cookie support (RFC 7873) on each nameserver
    report["checks"]["COOKIE-001 DNS cookie support"] = {
        s: ("requested" if "COOKIE" in dig(zone, "SOA", s, ["+cookie"]) else "not-seen") for s in ns}

    # Open recursion (nmap NSE, bounded; only against the zone's own nameservers)
    if shutil.which("nmap") and ns:
        out = run(["nmap", "-sU", "-p", "53", "--script", "dns-recursion", "-Pn", "-n", ns[0]], timeout=120)
        report["checks"]["RECURSION-001 open resolver (nmap dns-recursion)"] = (
            "recursion-appears-enabled" if "recursion" in out.lower() and "true" in out.lower() else "not-indicated")
    else:
        report["checks"]["RECURSION-001 open resolver (nmap dns-recursion)"] = "nmap not installed or no nameserver"

    # DoT: TCP 853 with TLS handshake
    dot = {}
    for s in ns:
        try:
            with socket.create_connection((s, 853), timeout=5) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=s) as _:
                    dot[s] = "tls-on-853"
        except (OSError, ssl.SSLError):
            dot[s] = "not-available"
    report["checks"]["DOT-001 DNS over TLS (853)"] = dot

    # DoH probe on a well-known path (reachability only)
    doh = {}
    for s in ns:
        try:
            req = urllib.request.Request(f"https://{s}/dns-query?name={zone}&type=A",
                                         headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as r:
                doh[s] = f"http-{r.status}"
        except urllib.error.HTTPError as e:
            doh[s] = f"http-{e.code}"
        except (urllib.error.URLError, OSError):
            doh[s] = "not-available"
    report["checks"]["DOH-001 DNS over HTTPS (/dns-query)"] = doh

    # Query name minimization hint: a trace shows the query path (bounded)
    trace = run(["dig", "+trace", "+time=3", zone, "A"], timeout=30)
    report["checks"]["QNAME-001 minimization hint (dig +trace)"] = (
        "trace-collected: inspect whether intermediate servers receive the full name" if trace else "not-run")

    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
