#!/usr/bin/env python3
"""Timing-based HTTP/1.1 request smuggling detection (CL.TE, TE.CL, TE.TE).

Order (PortSwigger guidance):
  1. Baseline: 3 normal POSTs to measure response time.
  2. CL.TE probe: Content-Length 4, body "1\\r\\nA\\r\\nX". A TE back end waits
     for the next chunk -> response near the timeout. Leaves nothing behind.
  3. TE.CL probe: only if CL.TE was not detected (otherwise the "X" byte could
     poison the back-end connection). Content-Length 6, body "0\\r\\n\\r\\nX".
  4. The same pair for each Transfer-Encoding obfuscation (TE.TE).
A variant is a candidate when it takes >= 80% of the timeout while baselines
are fast, and a repeat of that variant (one more request) agrees.

No confirmation prefix is ever sent. One request per variant (plus one repeat
for candidates). Scope-gated.

Example:
  smuggle_timing.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://www.example.com/robots.txt --out artifacts/example.com/smuggle_timing.json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
CRLF = "\r\n"
TE_VARIANTS = [
    ("plain", "Transfer-Encoding: chunked"),
    ("space-before-colon", "Transfer-Encoding : chunked"),
    ("tab", "Transfer-Encoding:\tchunked"),
    ("xchunked", "Transfer-Encoding: xchunked"),
    ("chunked-identity", "Transfer-Encoding: chunked, identity"),
    ("identity-chunked", "Transfer-Encoding: identity, chunked"),
    ("case", "Transfer-encoding: cHuNkEd"),
    ("quoted", 'Transfer-Encoding: "chunked"'),
    ("double", "Transfer-Encoding: chunked" + CRLF + "Transfer-Encoding: x"),
    ("folding", "Transfer-Encoding:" + CRLF + " chunked"),
    ("vtab", "Transfer-Encoding: chunked\x0b"),
]


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def send_raw(host: str, port: int, tls: bool, data: bytes, timeout: float, insecure: bool) -> tuple[float, str]:
    start = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            if insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        s.sendall(data)
        try:
            first = s.recv(4096)
            status = first.split(b"\r\n", 1)[0].decode(errors="replace")
        except socket.timeout:
            status = "TIMEOUT"
    finally:
        s.close()
    return time.perf_counter() - start, status


def build(host: str, path: str, te_line: str | None, cl: int | None, body: str, extra: list[str]) -> bytes:
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}", "User-Agent: Mozilla/5.0 smuggling-audit",
             "Content-Type: application/x-www-form-urlencoded", "Connection: close"] + extra
    if cl is not None:
        lines.append(f"Content-Length: {cl}")
    if te_line:
        lines.append(te_line)
    return (CRLF.join(lines) + CRLF + CRLF + body).encode("latin-1")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="idempotent endpoint (static file, robots.txt, own page)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--variants", default="all", help="comma list of TE variant names, or 'all'")
    ap.add_argument("--header", action="append", default=[], help="extra header (for example own Cookie)")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    p = urlsplit(args.url)
    host = (p.hostname or "").lower()
    target = args.target.lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, args.target.lower())
    tls = p.scheme == "https"
    port = p.port or (443 if tls else 80)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    hosthdr = p.netloc
    variants = TE_VARIANTS if args.variants == "all" else [v for v in TE_VARIANTS if v[0] in args.variants.split(",")]

    def go(te, cl, body):
        return send_raw(host, port, tls, build(hosthdr, path, te, cl, body, args.header), args.timeout, args.insecure)

    report: dict = {"url": args.url, "timeout": args.timeout, "baseline": [], "results": [], "candidates": []}
    for _ in range(3):
        t, st = go(None, 3, "x=1")
        report["baseline"].append({"seconds": round(t, 3), "status": st})
        time.sleep(0.5)
    base = max(b["seconds"] for b in report["baseline"])
    print(f"baseline max {base:.2f}s: {[b['status'] for b in report['baseline']]}")
    if base > args.timeout * 0.5:
        print("baseline too slow for timing detection; raise --timeout or pick a faster endpoint")
        return 2
    threshold = args.timeout * 0.8

    def probe(kind, name, te, cl, body):
        t, st = go(te, cl, body)
        rec = {"kind": kind, "variant": name, "seconds": round(t, 3), "status": st}
        if t >= threshold:
            time.sleep(1)
            t2, st2 = go(te, cl, body)
            rec["repeat_seconds"], rec["repeat_status"] = round(t2, 3), st2
            rec["candidate"] = t2 >= threshold
        else:
            rec["candidate"] = False
        report["results"].append(rec)
        flag = "CANDIDATE" if rec["candidate"] else ""
        print(f"{kind:5} {name:20} {rec['seconds']:6.2f}s {st[:40]:40} {flag}")
        time.sleep(0.5)
        return rec["candidate"]

    for name, te in variants:
        clte = probe("CL.TE", name, te, 4, "1\r\nA\r\nX")
        if clte:
            report["candidates"].append({"id": "RS-001" if name == "plain" else "RS-003", "type": "CL.TE", "variant": name})
            print(f"  skipping TE.CL for {name}: CL.TE candidate (TE.CL probe could poison the connection)")
            continue
        tecl = probe("TE.CL", name, te, 6, "0\r\n\r\nX")
        if tecl:
            report["candidates"].append({"id": "RS-002" if name == "plain" else "RS-003", "type": "TE.CL", "variant": name})

    report["note"] = ("Timing candidates are leads. Confirmation with a smuggled prefix is authorized-only on production; "
                      "use templates 3/4 against a unique path in an approved window or lab.")
    print(f"candidates: {report['candidates'] or 'none'}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(report, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
