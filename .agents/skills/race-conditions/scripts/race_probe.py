#!/usr/bin/env python3
"""Send a small, synchronized burst of identical requests to test a race window.

Technique: last-byte synchronization over HTTP/1.1. Every connection is opened
and the whole request except its final byte is sent; then all final bytes are
released together, so the server receives N complete requests within a few
milliseconds. For HTTP/2 single-packet attacks use Burp Repeater
("Send group in parallel") or Turbo Intruder instead.

Safety:
  - The scope gate (scripts/scope_check.sh) runs on the request's Host first.
  - Default burst is 5 requests. More than 5 needs --approved (explicit
    approval for that check). Hard cap is 20.
  - The tool sends exactly one burst per run. It never loops.

Example:
  race_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --request req.txt --count 5 --out artifacts/example.com/race_coupon.json

req.txt is a raw HTTP request (as saved from Burp: "Copy to file").
Output: status, length, and body hash per response, grouped so that
"N successes where 1 was expected" stands out.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
DEFAULT_COUNT = 5
HARD_CAP = 20


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def load_request(path: str) -> tuple[bytes, str, int | None]:
    """Return (normalized raw request, host, explicit port or None)."""
    raw = open(path, "rb").read()
    sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    head, _, body = raw.partition(sep)
    lines = [l.rstrip(b"\r") for l in head.split(b"\n") if l.strip()]
    if not lines:
        sys.exit("empty request file")
    request_line, headers = lines[0], lines[1:]
    kept: list[bytes] = []
    host = ""
    for h in headers:
        name = h.split(b":", 1)[0].strip().lower()
        if name in (b"content-length", b"connection", b"transfer-encoding", b"keep-alive"):
            continue
        if name == b"host":
            host = h.split(b":", 1)[1].strip().decode()
        kept.append(h)
    if not host:
        sys.exit("request has no Host header")
    kept.append(b"Connection: close")
    if body or request_line.split(b" ")[0].upper() in (b"POST", b"PUT", b"PATCH", b"DELETE"):
        kept.append(b"Content-Length: " + str(len(body)).encode())
    out = b"\r\n".join([request_line] + kept) + b"\r\n\r\n" + body
    port = None
    if ":" in host and not host.endswith("]"):
        host, p = host.rsplit(":", 1)
        port = int(p)
    return out, host.lower(), port


def read_response(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def summarize(resp: bytes) -> dict:
    head, _, body = resp.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status_line.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    return {
        "status": status,
        "length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest()[:16],
        "body_preview": body[:200].decode(errors="replace"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="in-scope target; the request Host must be this or a subdomain")
    ap.add_argument("--workspace", help="workspace root holding <target>/scope.txt")
    ap.add_argument("--request", required=True, help="raw HTTP request file")
    ap.add_argument("--count", type=int, default=DEFAULT_COUNT, help="parallel requests (default 5)")
    ap.add_argument("--approved", action="store_true", help="confirm explicit approval for more than 5 requests")
    ap.add_argument("--http", action="store_true", help="plain HTTP instead of TLS")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (own lab only)")
    ap.add_argument("--out", help="write JSON results here")
    args = ap.parse_args()

    if args.count < 2:
        sys.exit("--count must be at least 2")
    if args.count > HARD_CAP:
        sys.exit(f"--count above the hard cap of {HARD_CAP}")
    if args.count > DEFAULT_COUNT and not args.approved:
        sys.exit("more than 5 parallel requests needs explicit approval: pass --approved")

    raw, host, port = load_request(args.request)
    target = args.target.lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"request Host {host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, args.target.lower())

    port = port or (80 if args.http else 443)
    ctx = None
    if not args.http:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    socks: list[socket.socket] = []
    for _ in range(args.count):
        s = socket.create_connection((host, port), timeout=args.timeout)
        if ctx:
            s = ctx.wrap_socket(s, server_hostname=host)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(raw[:-1])
        socks.append(s)

    time.sleep(0.1)  # let the partial requests reach the server
    barrier = threading.Barrier(args.count)
    sent_at: list[float] = [0.0] * args.count
    responses: list[bytes] = [b""] * args.count

    def fire(i: int) -> None:
        barrier.wait()
        socks[i].sendall(raw[-1:])
        sent_at[i] = time.perf_counter()
        responses[i] = read_response(socks[i], args.timeout)
        socks[i].close()

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(args.count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    results = [dict(index=i, **summarize(r)) for i, r in enumerate(responses)]
    groups: dict[str, int] = {}
    for r in results:
        key = f"{r['status']}|{r['length']}|{r['body_sha256']}"
        groups[key] = groups.get(key, 0) + 1
    report = {
        "target": target,
        "host": host,
        "count": args.count,
        "release_spread_ms": round((max(sent_at) - min(sent_at)) * 1000, 3),
        "response_groups": [{"status|length|sha": k, "count": v} for k, v in groups.items()],
        "results": results,
        "note": "Compare against the expected limit. Re-check server state (balance, coupon use, votes) after the burst.",
    }
    text = json.dumps(report, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
