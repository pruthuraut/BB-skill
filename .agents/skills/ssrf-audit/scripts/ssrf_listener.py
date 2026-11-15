#!/usr/bin/env python3
"""SSRF helper server for infrastructure YOU control: OOB logger, redirector, TOCTOU and timing endpoints.

Usage:
  ssrf_listener.py --port 8000 [--bind 0.0.0.0] [--log artifacts/ssrf/listener_hits.jsonl]
                   [--allow-redirect-host 127.0.0.1,169.254.169.254,localhost]

Endpoints (all requests are logged with source IP, method, path and headers - the User-Agent identifies the
fetcher library, e.g. Java/1.8, python-requests, Go-http-client, curl, wkhtmltopdf, HeadlessChrome):
  /r?to=URL&code=302         redirect (301/302/303/307/308) - filter checks your host, client follows to URL
  /r?b64=BASE64URL&code=302  same, target base64url-encoded so it never appears in the submitted URL
  /toctou?to=URL             first request per source returns a valid 1x1 PNG, later requests redirect to URL
                             (validator fetches once, worker fetches again)
  /png  /svg  /html          small valid documents (pass content-type / magic-byte checks)
  /slow?s=5                  responds after s seconds (max 20) - measures fetch timeouts for blind SSRF
  anything else              200 "bbtest" (OOB confirmation)
Redirect targets are restricted to --allow-redirect-host (default: loopback and link-local metadata IPs plus any
hostname you list), so the server cannot be used as an open redirector by others.
"""
import argparse
import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>'
HTML = b"<!doctype html><title>bbtest</title><p>bbtest ssrf canary</p>"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--log", default="artifacts/ssrf/listener_hits.jsonl")
    ap.add_argument("--allow-redirect-host", default="127.0.0.1,localhost,169.254.169.254,169.254.170.2,"
                                                     "metadata.google.internal,100.100.100.200,[::1]")
    a = ap.parse_args()
    allowed = {h.strip().lower() for h in a.allow_redirect_host.split(",") if h.strip()}
    seen = set()
    os.makedirs(os.path.dirname(a.log) or ".", exist_ok=True)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def record(self, body=b""):
            hit = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "ip": self.client_address[0], "method": self.command,
                   "path": self.path[:500], "headers": {k: v[:300] for k, v in self.headers.items()},
                   "body": body[:2048].decode("utf-8", "replace")}
            with open(a.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(hit) + "\n")
            print(f"[hit] {hit['time']} {hit['ip']:<15} {self.command} {self.path[:70]}  UA={self.headers.get('User-Agent', '')[:60]}")

        def send(self, code, body=b"", ctype="text/plain", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def handle_any(self, body=b""):
            self.record(body)
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path in ("/r", "/toctou"):
                to = q.get("to", "")
                if "b64" in q:   # base64url target hides the internal address from substring filters
                    try:
                        to = base64.urlsafe_b64decode(q["b64"] + "=" * (-len(q["b64"]) % 4)).decode()
                    except Exception:  # noqa: BLE001
                        to = ""
                th = (urlsplit(to).hostname or "").lower()
                if not to or (th not in allowed and f"[{th}]" not in allowed and urlsplit(to).scheme != "file"):
                    return self.send(400, b"redirect target not in --allow-redirect-host")
                if u.path == "/toctou":
                    key = (self.client_address[0], to)
                    if key not in seen:
                        seen.add(key)
                        return self.send(200, PNG, "image/png")
                code = int(q.get("code", "302"))
                code = code if code in (301, 302, 303, 307, 308) else 302
                return self.send(code, b"", extra={"Location": to})
            if u.path == "/png":
                return self.send(200, PNG, "image/png")
            if u.path == "/svg":
                return self.send(200, SVG, "image/svg+xml")
            if u.path == "/html":
                return self.send(200, HTML, "text/html")
            if u.path == "/slow":
                time.sleep(min(float(q.get("s", "5")), 20))
                return self.send(200, b"bbtest-slow")
            self.send(200, b"bbtest")

        def do_GET(self):
            self.handle_any()

        def do_HEAD(self):
            self.handle_any()

        def do_POST(self):
            n = min(int(self.headers.get("Content-Length", 0) or 0), 65536)
            self.handle_any(self.rfile.read(n))

        do_PUT = do_POST

    print(f"[*] SSRF listener on {a.bind}:{a.port}; redirects allowed to {sorted(allowed)}; log {a.log}")
    ThreadingHTTPServer((a.bind, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
