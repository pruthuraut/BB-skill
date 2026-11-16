#!/usr/bin/env python3
"""gRPC exposure probe (GRPC rows), scope-gated.

Built-in (no dependencies):
  - TCP reachability
  - TLS handshake with ALPN ["h2", "http/1.1"]: negotiated protocol, TLS version, certificate subject/issuer/expiry (GRPC-007)
  - plaintext HTTP/2: send the client preface + empty SETTINGS; a SETTINGS frame back means h2c is served (GRPC-004/GRPC-007)
  - gRPC-Web over HTTP/1.1 (TLS or plain): POST grpc.health.v1.Health/Check with application/grpc-web+proto (GRPC-007)
With grpcurl (PATH or --grpcurl):
  - reflection list with and without --auth metadata (GRPC-001), describe each service, flag sensitive names (GRPC-008)
  - health check, verbose metadata capture on the health call (GRPC-005)
  - --calls FILE: lines "package.Service/Method {json}" (own read-only calls) run with --auth, --auth-b, and no metadata (GRPC-002, GRPC-010)

Example:
  grpc_probe.py --target example.com --addr grpc.example.com:443 --auth 'authorization: Bearer OWN_A' \
     --auth-b 'authorization: Bearer OWN_B' --calls calls.txt --out artifacts/example.com/grpc.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_EMPTY = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
SENSITIVE = re.compile(r"(?i)channelz|admin|debug|internal|management|config|migrat|backup|exec|shell|impersonat|csds|ClientStatusDiscovery|v1alpha")
META_SENS = re.compile(r"(?i)^(server|x-powered-by|x-envoy-[\w-]+|x-backend[\w-]*|x-internal[\w-]*|via):|grpc-message:.*(at |Exception|Traceback|SQL|/home/|/var/)")


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def tls_info(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                info = {"tls": True, "version": s.version(), "alpn": s.selected_alpn_protocol(), "cipher": s.cipher()[0]}
        v = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with v.wrap_socket(raw, server_hostname=host) as s2:
                    c = s2.getpeercert()
                    info["cert_valid"] = True
                    info["not_after"] = c.get("notAfter")
        except ssl.SSLCertVerificationError as e:
            info["cert_valid"] = False
            info["cert_error"] = e.verify_message
        except Exception:
            pass
        info["cert_sha256"] = __import__("hashlib").sha256(der).hexdigest()[:16] if der else None
        return info
    except (ssl.SSLError, OSError) as e:
        return {"tls": False, "error": str(e)[:120]}


def h2c_check(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(PREFACE + SETTINGS_EMPTY)
            s.settimeout(timeout)
            data = s.recv(64)
            if len(data) >= 9 and data[3] == 0x04:
                return {"h2c": True, "first_frame": "SETTINGS"}
            return {"h2c": False, "first_bytes": data[:20].hex()}
    except OSError as e:
        return {"h2c": False, "error": str(e)[:120]}


def grpc_web_check(host, port, tls, timeout):
    body = b"\x00\x00\x00\x00\x00"
    req = (f"POST /grpc.health.v1.Health/Check HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/grpc-web+proto\r\n"
           f"X-Grpc-Web: 1\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        s = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])
            s = ctx.wrap_socket(raw, server_hostname=host)
        s.sendall(req)
        s.settimeout(timeout)
        data = b""
        while len(data) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
        return {"grpc_web": bool(re.search(r"(?im)^grpc-status:|application/grpc-web", head + data[:2000].decode(errors="replace"))),
                "status_line": head.split("\r\n")[0][:80]}
    except OSError as e:
        return {"grpc_web": False, "error": str(e)[:120]}


def grpcurl(binary, args, timeout=30):
    try:
        r = subprocess.run([binary] + args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--addr", required=True, help="host:port")
    ap.add_argument("--auth", action="append", default=[], help="own metadata 'key: value'")
    ap.add_argument("--auth-b", action="append", default=[], help="second own account metadata")
    ap.add_argument("--calls", help='file: "package.Service/Method {json}" per line (own read-only calls)')
    ap.add_argument("--grpcurl", default=shutil.which("grpcurl"))
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out")
    a = ap.parse_args()
    host, _, port_s = a.addr.rpartition(":")
    if not host or not port_s.isdigit():
        sys.exit("--addr must be host:port")
    port, host = int(port_s), host.lower().strip("[]")
    target = a.target.lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, a.workspace, target)
    F: list[str] = []
    rep: dict = {"addr": a.addr}

    try:
        socket.create_connection((host, port), timeout=a.timeout).close()
    except OSError as e:
        print(f"cannot connect to {a.addr}: {e}")
        return 2
    t = tls_info(host, port, a.timeout)
    rep["tls"] = t
    h = h2c_check(host, port, a.timeout) if not t.get("tls") else {"h2c": None, "note": "TLS port"}
    rep["h2c"] = h
    gw = grpc_web_check(host, port, bool(t.get("tls")), a.timeout)
    rep["grpc_web"] = gw
    print(f"tls={t.get('tls')} alpn={t.get('alpn')} version={t.get('version')} cert_valid={t.get('cert_valid')} h2c={h.get('h2c')} grpc-web={gw.get('grpc_web')}")
    if t.get("tls"):
        if t.get("alpn") != "h2":
            F.append(f"GRPC-007: TLS service does not negotiate ALPN h2 (got {t.get('alpn')})")
        if t.get("version") in ("TLSv1", "TLSv1.1"):
            F.append(f"GRPC-007: legacy {t['version']} negotiated")
        if t.get("cert_valid") is False:
            F.append(f"GRPC-004/GRPC-007: certificate not trusted ({t.get('cert_error')}); clients may disable verification")
    if h.get("h2c"):
        F.append("GRPC-004/GRPC-007: plaintext HTTP/2 (h2c) accepted - traffic and metadata (tokens) unencrypted")
    if gw.get("grpc_web"):
        F.append(f"GRPC-007 info: gRPC-Web gateway answers over HTTP/1.1 ({gw.get('status_line')}); check CORS and auth parity")

    if not a.grpcurl:
        rep["grpcurl"] = "not installed"
        F.append("note: grpcurl not found; reflection, describe, health, metadata, and call tests skipped "
                 "(go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)")
    else:
        mode = [] if t.get("tls") else ["-plaintext"]
        if t.get("tls") and t.get("cert_valid") is False:
            mode = ["-insecure"]
        meta = sum((["-H", m] for m in a.auth), [])
        rc, out, err = grpcurl(a.grpcurl, mode + ["-max-time", "15", a.addr, "list"])
        rc2, out2, err2 = grpcurl(a.grpcurl, mode + meta + ["-max-time", "15", a.addr, "list"]) if meta else (rc, out, err)
        services = [s.strip() for s in (out or out2).splitlines() if s.strip()]
        rep["reflection"] = {"anonymous": rc == 0, "with_auth": rc2 == 0, "services": services, "error": (err or err2)[:200]}
        if rc == 0 and services:
            F.append(f"GRPC-001: reflection enabled without authentication ({len(services)} services)")
        elif rc2 == 0 and services:
            F.append(f"GRPC-001 info: reflection enabled for authenticated clients ({len(services)} services)")
        sens = [s for s in services if SENSITIVE.search(s)]
        if sens:
            F.append(f"GRPC-008: sensitive services exposed via reflection: {sens}")
        desc = {}
        for s in services[:30]:
            rc3, o3, _ = grpcurl(a.grpcurl, mode + meta + ["-max-time", "15", a.addr, "describe", s])
            if rc3 == 0:
                methods = re.findall(r"rpc (\w+) \(", o3)
                desc[s] = methods
                hidden = [m for m in methods if SENSITIVE.search(m) or re.search(r"(?i)delete|remove|set|grant|reset|admin", m)]
                if hidden:
                    F.append(f"GRPC-008 lead: {s} exposes privileged-looking methods {hidden[:6]} (do not call without approval)")
        rep["describe"] = desc
        rc4, o4, e4 = grpcurl(a.grpcurl, mode + ["-v", "-max-time", "10", a.addr, "grpc.health.v1.Health/Check"])
        rep["health"] = {"rc": rc4, "out": (o4 + e4)[:600]}
        leaks = [l.strip() for l in (o4 + e4).splitlines() if META_SENS.search(l.strip())]
        if leaks:
            F.append(f"GRPC-005: response metadata reveals {leaks[:4]}")
        if a.calls:
            cres = []
            for line in open(a.calls, encoding="utf-8"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                method, _, body = line.partition(" ")
                if re.search(r"(?i)delete|remove|create|update|set|grant|reset|admin|exec|write|put", method.split("/")[-1]):
                    cres.append({"method": method, "skipped": "write/admin-looking method"})
                    continue
                row = {"method": method}
                for label, md in (("A", a.auth), ("B", a.auth_b), ("none", [])):
                    if label == "B" and not a.auth_b:
                        continue
                    args = mode + sum((["-H", m] for m in md), []) + ["-max-time", "15"] + (["-d", body] if body else []) + [a.addr, method]
                    rc5, o5, e5 = grpcurl(a.grpcurl, args)
                    code = re.search(r"Code: (\w+)", e5)
                    row[label] = "OK" if rc5 == 0 else (code.group(1) if code else f"rc={rc5}")
                cres.append(row)
                if row.get("none") == "OK":
                    F.append(f"GRPC-002: {method} succeeds without metadata")
                if row.get("B") == "OK" and row.get("A") == "OK":
                    F.append(f"GRPC-010 lead: {method} with account A's object also succeeds for account B; confirm object ownership")
                print(f"call {method}: {row}")
            rep["calls"] = cres

    F = list(dict.fromkeys(F))
    rep["findings"] = F
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
