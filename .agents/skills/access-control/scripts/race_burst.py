#!/usr/bin/env python3
"""Last-byte-synchronised parallel burst of one raw HTTP/1.1 request (race conditions). Scope-gated.

Usage:
  race_burst.py --target example.com --request accept_invite.req [--count 10] [--http] [--port 443]
                [--vary 'PLACEHOLDER=v1,v2,...'] [--insecure]

  --request  raw HTTP/1.1 request file (Burp: right-click > Copy to file), request line + headers + body.
  --count    parallel copies (max 20).
  --vary     replace PLACEHOLDER in each copy with successive values (e.g. different roles or invite codes).

Technique: open all connections, send every request except its final byte, wait on a barrier,
then release the final bytes together (approximates the single-packet attack for HTTP/1.1).
Use only on your own tenant's role-assignment / invite / approval flows (PE-13/28/31, AB-09).
"""
import argparse
import os
import socket
import ssl
import subprocess
import sys
import threading
import time


def gate(host):
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


def load(path):
    raw = open(path, "rb").read().replace(b"\r\n", b"\n")
    head, _, body = raw.partition(b"\n\n")
    lines = head.decode("latin-1").split("\n")
    reqline, headers = lines[0], [l for l in lines[1:] if l.strip()]
    host = next((l.split(":", 1)[1].strip() for l in headers if l.lower().startswith("host:")), None)
    if not host:
        sys.exit("request has no Host header")
    headers = [l for l in headers if not l.lower().startswith(("content-length:", "connection:"))]
    return reqline, headers, body.rstrip(b"\n") if body.strip() else b"", host


def build(reqline, headers, body):
    h = [reqline] + headers + ["Connection: close"]
    if body or reqline.split(" ", 1)[0].upper() in ("POST", "PUT", "PATCH"):
        h.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(h) + "\r\n\r\n").encode("latin-1") + body


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--request", required=True)
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--http", action="store_true", help="plain HTTP instead of TLS")
    ap.add_argument("--port", type=int)
    ap.add_argument("--vary", help="PLACEHOLDER=v1,v2,...")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    if not 1 <= a.count <= 20:
        sys.exit("--count must be 1..20")

    reqline, headers, body, hostport = load(a.request)
    host = hostport.split(":")[0].lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"Host {host} outside target {a.target}")
    gate(host)
    port = a.port or (int(hostport.split(":")[1]) if ":" in hostport else (80 if a.http else 443))

    variants = [None] * a.count
    if a.vary:
        ph, _, vals = a.vary.partition("=")
        vlist = vals.split(",")
        variants = [(ph, vlist[i % len(vlist)]) for i in range(a.count)]

    payloads = []
    for v in variants:
        rl, hd, bd = reqline, list(headers), body
        if v:
            rl = rl.replace(v[0], v[1])
            hd = [x.replace(v[0], v[1]) for x in hd]
            bd = bd.replace(v[0].encode(), v[1].encode())
        payloads.append(build(rl, hd, bd))

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    socks = []
    for _ in payloads:
        s = socket.create_connection((hostport.split(":")[0], port), timeout=20)
        if not a.http:
            s = ctx.wrap_socket(s, server_hostname=hostport.split(":")[0])
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        socks.append(s)
    for s, p in zip(socks, payloads):
        s.sendall(p[:-1])
    time.sleep(0.2)
    barrier = threading.Barrier(len(socks))
    results = [None] * len(socks)

    def fire(i):
        barrier.wait()
        t0 = time.perf_counter()
        socks[i].sendall(payloads[i][-1:])
        data = b""
        try:
            while True:
                chunk = socks[i].recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 200000:
                    break
        except (socket.timeout, OSError):
            pass
        results[i] = (time.perf_counter() - t0, data)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(len(socks))]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    for s in socks:
        try:
            s.close()
        except OSError:
            pass

    print(f"{'#':>3} {'variant':<20} {'status':<6} {'bytes':>7} {'ms':>8}  first body bytes")
    for i, (dt, data) in enumerate(results):
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        status = line.split(" ")[1] if len(line.split(" ")) > 1 else "?"
        bodytxt = data.split(b"\r\n\r\n", 1)[-1][:80].decode("utf-8", "replace").replace("\n", " ")
        v = variants[i][1] if variants[i] else "-"
        print(f"{i:>3} {v:<20} {status:<6} {len(data):>7} {dt * 1000:>8.1f}  {bodytxt}")
    print("\nCheck the resulting state from an independent session (roles, members, invites) - "
          "more than one success where only one is allowed indicates a race.")


if __name__ == "__main__":
    main()
