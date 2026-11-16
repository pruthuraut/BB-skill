#!/usr/bin/env python3
"""Dependency-free WebSocket security probe (RFC 6455) for WSK rows.

Steps (each on its own short-lived connection):
  1. Handshake matrix: legit Origin + cookie (baseline), no cookie (WSK-001), evil / null /
     suffix / prefix / missing Origin with cookie (WSK-002, WSK-007), Sec-WebSocket-Version 8 (WSK-015),
     ws:// on the same host when the URL is wss:// (WSK-008, WSK-015).
  2. --messages FILE: send each own message on an authenticated connection, record replies;
     resend on a fresh connection (replay, WSK-004); send on the no-cookie connection if it
     upgraded (WSK-001 data check).
  3. --fuzz-field NAME: for the first JSON message containing NAME, send marker variants
     (XSS, SQL, NoSQL, template, command) and look for unencoded reflection or error signatures
     (WSK-011, WSK-012, WSK-013).
  4. --idor-message JSON: send a message referencing your second account's object/room (WSK-009).
  5. --burst N: N copies of the first message as fast as allowed; N ≤ 50 unless --approved (WSK-010).
  6. Every received frame is scanned for secrets and PII (WSK-006); token-in-URL is flagged (WSK-014).

Safety: scope-gated; short timeouts; sockets closed after each step.

Example:
  ws_probe.py --target example.com --url wss://ws.example.com/socket --cookie 'session=A' \
     --origin https://www.example.com --messages msgs.txt --fuzz-field text \
     --idor-message '{"action":"join","room":"ROOM_B"}' --out artifacts/example.com/websocket.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SECRET_RE = re.compile(r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
                       r"\"(?i:password|passwd|secret|api_?key|access_?token|refresh_?token|ssn|card_?number)\"\s*:\s*\"[^\"]{4,}")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ERR_RE = re.compile(r"(?i)SQLSTATE|syntax error|ORA-\d{5}|MySQL|PG::|sqlite|MongoError|CastError|\$where|Traceback|Exception|at [\w.$]+\(|sh: |/bin/sh|command not found|TemplateSyntaxError|undefined method")


def run_scope_check(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class WS:
    def __init__(self, url, headers, timeout, insecure, version="13"):
        self.url, self.headers, self.timeout, self.insecure, self.version = url, headers, timeout, insecure, version
        self.sock, self.status, self.resp_headers, self.buf = None, None, {}, b""

    def connect(self):
        p = urlsplit(self.url)
        tls = p.scheme == "wss"
        port = p.port or (443 if tls else 80)
        s = socket.create_connection((p.hostname, port), timeout=self.timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            if self.insecure:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=p.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        lines = [f"GET {path} HTTP/1.1", f"Host: {p.netloc}", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", f"Sec-WebSocket-Version: {self.version}", "User-Agent: Mozilla/5.0 websocket-audit"]
        lines += [f"{k}: {v}" for k, v in self.headers.items() if v is not None]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        hl = head.decode(errors="replace").split("\r\n")
        self.status = int(hl[0].split(" ")[1]) if len(hl[0].split(" ")) > 1 and hl[0].split(" ")[1].isdigit() else None
        self.resp_headers = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in hl[1:] if ":" in l}
        expect = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.accept_ok = self.resp_headers.get("sec-websocket-accept") == expect
        self.sock, self.buf = s, rest
        if self.status != 101:
            self.close()
        return self.status

    def send(self, text: str):
        payload = text.encode()
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536
                               else bytes([0x80 | 127]) + struct.pack(">Q", n))
        self.sock.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_all(self, wait: float) -> list[str]:
        msgs, end = [], time.time() + wait
        while time.time() < end:
            try:
                self.sock.settimeout(max(0.05, end - time.time()))
                b1, b2 = self._read(2)
                op, ln = b1 & 0x0F, b2 & 0x7F
                if ln == 126:
                    ln = struct.unpack(">H", self._read(2))[0]
                elif ln == 127:
                    ln = struct.unpack(">Q", self._read(8))[0]
                if b2 & 0x80:
                    m = self._read(4)
                    data = bytes(b ^ m[i % 4] for i, b in enumerate(self._read(ln)))
                else:
                    data = self._read(ln)
                if op == 0x8:
                    msgs.append(f"<close {struct.unpack('>H', data[:2])[0] if len(data) >= 2 else ''}>")
                    break
                if op == 0x9:
                    pm = os.urandom(4)
                    pdata = data[:125]
                    self.sock.sendall(bytes([0x8A, 0x80 | len(pdata)]) + pm + bytes(b ^ pm[i % 4] for i, b in enumerate(pdata)))
                    continue
                msgs.append(data.decode("utf-8", errors="replace") if op in (0x1, 0x0) else f"<binary {len(data)} bytes>")
            except (socket.timeout, TimeoutError):
                break
            except (ConnectionError, OSError):
                msgs.append("<connection closed>")
                break
        return msgs

    def close(self):
        try:
            if self.sock:
                self.sock.sendall(bytes([0x88, 0x82]) + b"\x00\x00\x00\x00" + struct.pack(">H", 1000))
                self.sock.close()
        except OSError:
            pass
        self.sock = None


def scan_frames(frames, F, label, own_emails):
    for f in frames:
        if SECRET_RE.search(f):
            F.append(f"WSK-006: secret-like value in frame ({label}): {SECRET_RE.search(f).group(0)[:40]}...")
        others = [e for e in EMAIL_RE.findall(f) if e.lower() not in own_emails]
        if others:
            F.append(f"WSK-006: emails not yours in frame ({label}): {sorted(set(others))[:3]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="ws:// or wss:// URL")
    ap.add_argument("--cookie")
    ap.add_argument("--header", action="append", default=[], help="extra handshake header (e.g. Authorization)")
    ap.add_argument("--origin", help="legitimate Origin (default https://<host>)")
    ap.add_argument("--subprotocol", help="Sec-WebSocket-Protocol value")
    ap.add_argument("--messages", help="file with own messages, one per line")
    ap.add_argument("--fuzz-field", help="JSON field to fuzz in the first message that has it")
    ap.add_argument("--idor-message", action="append", default=[], help="message referencing your second account's object")
    ap.add_argument("--burst", type=int, default=0)
    ap.add_argument("--approved", action="store_true", help="explicit approval for bursts above 50")
    ap.add_argument("--own-email", action="append", default=[])
    ap.add_argument("--wait", type=float, default=2.0, help="seconds to wait for replies")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    p = urlsplit(args.url)
    host = (p.hostname or "").lower()
    target = args.target.lower()
    if p.scheme not in ("ws", "wss"):
        sys.exit("--url must be ws:// or wss://")
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"{host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, target)
    if args.burst > 50 and not args.approved:
        sys.exit("--burst above 50 needs --approved (flooding is authorized-only)")

    own = {e.lower() for e in args.own_email}
    legit = args.origin or f"https://{p.netloc}"
    base_h = {"Origin": legit, "Cookie": args.cookie}
    if args.subprotocol:
        base_h["Sec-WebSocket-Protocol"] = args.subprotocol
    for hv in args.header:
        k, _, v = hv.partition(":")
        base_h[k.strip()] = v.strip()
    msgs = [l.rstrip("\n") for l in open(args.messages, encoding="utf-8") if l.strip()] if args.messages else []
    F: list[str] = []
    rep: dict = {"url": args.url, "handshakes": [], "messages": [], "fuzz": [], "idor": [], "burst": None}

    tok = [k for k, _ in parse_qsl(p.query) if re.search(r"(?i)token|auth|session|jwt|key|ticket", k)]
    if tok:
        F.append(f"WSK-014: credential-like parameter in socket URL {tok} (logged by proxies, leaks via Referer/history)")

    def hs(label, url=None, headers=None, version="13"):
        h = dict(base_h if headers is None else headers)
        w = WS(url or args.url, h, args.timeout, args.insecure, version)
        try:
            st = w.connect()
        except Exception as e:
            st, w.sock = None, None
            rep["handshakes"].append({"case": label, "status": None, "error": str(e)})
            print(f"  {label:22} error {e}")
            return None
        rep["handshakes"].append({"case": label, "status": st, "accept_ok": getattr(w, "accept_ok", False),
                                  "subprotocol": w.resp_headers.get("sec-websocket-protocol")})
        print(f"  {label:22} {st}")
        return w if st == 101 else None

    print("handshakes:")
    base = hs("baseline")
    if not base:
        print("baseline handshake did not upgrade; check URL, cookie, Origin, subprotocol")
    else:
        rep["baseline_frames"] = base.recv_all(min(args.wait, 1.5))
        base.close()
    nocookie_h = {k: v for k, v in base_h.items() if k.lower() not in ("cookie", "authorization")}
    nc = hs("no-credentials", headers=nocookie_h)
    evil = {"origin-evil": "https://evil.example", "origin-null": "null", "origin-suffix": f"https://evil{p.hostname}",
            "origin-prefix": f"https://{p.hostname}.evil.example", "origin-missing": None, "origin-http": f"http://{p.netloc}"}
    accepted_evil = []
    for label, o in evil.items():
        h = dict(base_h)
        h["Origin"] = o
        w = hs(label, headers=h)
        if w:
            accepted_evil.append(label)
            w.close()
    if accepted_evil and args.cookie:
        F.append(f"WSK-002/WSK-007: cookie-authenticated handshake accepted with {accepted_evil} (CSWSH candidate; confirm data/actions)")
    v8 = hs("version-8", version="8")
    if v8:
        F.append("WSK-015 lead: server accepts Sec-WebSocket-Version 8")
        v8.close()
    if p.scheme == "wss":
        wsurl = "ws://" + p.hostname + (p.path or "/") + (("?" + p.query) if p.query else "")
        w = hs("ws-plaintext", url=wsurl)
        if w:
            F.append("WSK-008/WSK-015: plaintext ws:// upgrade accepted on the same host")
            w.close()

    def send_one(msg, headers=None, label="auth"):
        w = WS(args.url, dict(base_h if headers is None else headers), args.timeout, args.insecure)
        try:
            if w.connect() != 101:
                return None
            w.recv_all(0.3)
            w.send(msg)
            frames = w.recv_all(args.wait)
            scan_frames(frames, F, label, own)
            return frames
        except Exception as e:
            return [f"<error {e}>"]
        finally:
            w.close()

    if msgs:
        print("messages:")
        for m in msgs:
            r1 = send_one(m, label="auth")
            r2 = send_one(m, label="replay")
            r3 = send_one(m, headers=nocookie_h, label="no-credentials") if nc else None
            rec = {"message": m[:200], "auth": (r1 or [])[:5], "replay": (r2 or [])[:5], "no_credentials": (r3 or [])[:5] if r3 is not None else None}
            rep["messages"].append(rec)
            print(f"  sent {m[:50]!r}: auth={len(r1 or [])} replay={len(r2 or [])} nocred={'-' if r3 is None else len(r3)}")
            internal = lambda x: x.startswith(("<close", "<connection closed", "<error", "<binary"))
            if r1 and r2 and r1 == r2 and not all(internal(x) for x in r1):
                F.append(f"WSK-004 lead: message replayed with identical result: {m[:60]}")
            if r3 and r1 and [x for x in r3 if not internal(x)] and r3[:3] == r1[:3]:
                F.append(f"WSK-001: unauthenticated socket returns the same data as authenticated for {m[:60]}")

    if args.fuzz_field and msgs:
        mk = "wsk" + secrets.token_hex(3)
        tmpl = next((m for m in msgs if m.strip().startswith("{") and args.fuzz_field in json.loads(m)), None)
        if tmpl:
            print("fuzz:")
            payloads = [("xss", f"<img src=x onerror=alert('{mk}')>"), ("sql-quote", f"{mk}'"), ("sql-bool", f"{mk}' OR '1'='1"),
                        ("nosql", {"$ne": mk}), ("template", "{{7*7}}" + mk), ("cmd", f"{mk};echo $((7*7))"), ("type", [mk])]
            for name, val in payloads:
                d = json.loads(tmpl)
                d[args.fuzz_field] = val
                frames = send_one(json.dumps(d), label=f"fuzz-{name}") or []
                blob = "\n".join(frames)
                notes = []
                if name == "xss" and f"<img src=x onerror=alert('{mk}')>" in blob:
                    notes.append("payload reflected unencoded (WSK-012)")
                if name == "template" and "49" + mk in blob:
                    notes.append("template evaluated (server-side-injection)")
                if name == "cmd" and re.search(r"\b49\b", blob) and mk in blob:
                    notes.append("possible command evaluation (WSK-013)")
                if ERR_RE.search(blob):
                    notes.append(f"error signature: {ERR_RE.search(blob).group(0)} (WSK-011/WSK-013)")
                rep["fuzz"].append({"payload": name, "frames": frames[:3], "notes": notes})
                print(f"  {name:10} {notes or ''}")
                for n in notes:
                    F.append(f"{n.split('(')[-1].rstrip(')') if '(' in n else 'WSK'}: field {args.fuzz_field} payload {name}: {n}")

    for im in args.idor_message:
        frames = send_one(im, label="idor") or []
        rep["idor"].append({"message": im[:200], "frames": frames[:5]})
        denied = any(re.search(r"(?i)forbidden|unauthori[sz]ed|denied|not allowed|403|401|error", f) for f in frames)
        print(f"idor {im[:50]!r}: {len(frames)} frames {'(denied)' if denied else ''}")
        if frames and not denied and not all(f.startswith(("<close", "<connection closed", "<error")) for f in frames):
            F.append(f"WSK-009 lead: message for second account's object returned data without an error: {im[:60]}")

    if args.burst and msgs:
        w = WS(args.url, dict(base_h), args.timeout, args.insecure)
        if w.connect() == 101:
            t0 = time.time()
            for _ in range(args.burst):
                w.send(msgs[0])
            frames = w.recv_all(args.wait + 1)
            w.close()
            limited = any(re.search(r"(?i)rate|too many|slow down|throttl|429|<close", f) for f in frames)
            rep["burst"] = {"sent": args.burst, "replies": len(frames), "seconds": round(time.time() - t0, 2), "limited": limited}
            print(f"burst: sent {args.burst}, replies {len(frames)}, limited={limited}")
            if not limited and len(frames) >= args.burst * 0.9:
                F.append(f"WSK-010: {args.burst} messages accepted without throttling")

    F = list(dict.fromkeys(F))
    rep["findings"] = F
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
