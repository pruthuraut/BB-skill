#!/usr/bin/env python3
"""Microservices and API gateway probe (bounded GET requests and single marker headers).

Checks: service discovery endpoints (Eureka, Consul, Nacos), health and actuator
disclosure, backend reachability with and without gateway routing headers,
tracing-header reflection (X-B3-TraceId marker), CORS on the gateway, and error
disclosure on malformed routes. Optional nmap service scan of in-scope internal
ports (Kali nmap). No writes, no registry changes, no flooding.

Scope gate runs first.

Example:
  gateway_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --base https://api.example.com --backend https://10.0.0.5:8443 --out artifacts/example.com/gateway.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
DISCOVERY = ["/eureka/apps", "/eureka/", "/v1/catalog/services", "/v1/agent/services", "/v1/health/state/any",
             "/nacos/v1/ns/service/list", "/actuator", "/actuator/health", "/actuator/env", "/health",
             "/metrics", "/api/health", "/swagger-ui.html", "/v3/api-docs"]
ROUTE_HEADERS = ["X-Forwarded-For: 127.0.0.1", "X-Original-URL: /internal", "X-Forwarded-Host: internal.local"]
MAX_REQUESTS = 40


def get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status, dict(r.headers), r.read(8000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(8000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, {}, str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--base", required=True, help="gateway base URL (in scope)")
    ap.add_argument("--backend", action="append", default=[], help="in-scope backend URL reached directly")
    ap.add_argument("--ports", help="in-scope host ports to scan with nmap, for example 80,443,8080,8500,8761")
    ap.add_argument("--host", help="host for nmap port scan (in scope)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    base = args.base.rstrip("/")
    sent = 0
    report: dict = {"base": base, "discovery": [], "headers": {}, "routing": [], "cors": None, "errors": None,
                    "ports": None}

    for path in DISCOVERY:
        if sent >= MAX_REQUESTS: break
        code, hdrs, body = get(base + path, {}, args.timeout); sent += 1
        if code and code < 400:
            report["discovery"].append({"path": path, "status": code, "length": len(body),
                                        "note": "reachable without authentication"})

    # Tracing header reflection with a benign marker
    marker = "tr" + secrets.token_hex(6)
    code, hdrs, body = get(base + "/", {"X-B3-TraceId": marker, "X-B3-SpanId": marker[:8]}, args.timeout); sent += 1
    report["headers"]["X-B3-TraceId reflected in response"] = marker in str(hdrs) or marker in body

    # Routing headers: compare with and without
    if sent < MAX_REQUESTS:
        c0, _, b0 = get(base + "/", {}, args.timeout); sent += 1
        for h in ROUTE_HEADERS:
            if sent >= MAX_REQUESTS: break
            k, v = h.split(": ", 1)
            c1, _, b1 = get(base + "/", {k: v}, args.timeout); sent += 1
            report["routing"].append({"header": h, "status_without": c0, "status_with": c1,
                                      "changed": c0 != c1 or len(b0) != len(b1)})

    # Direct backend reachability (in scope)
    for be in args.backend:
        if sent >= MAX_REQUESTS: break
        code, _, _ = get(be.rstrip("/") + "/", {}, args.timeout); sent += 1
        report.setdefault("backends", []).append({"backend": be, "status": code,
                                                  "note": "answers without the gateway: check auth parity"})

    # CORS on the gateway (single Origin probe, own marker origin)
    if sent < MAX_REQUESTS:
        code, hdrs, _ = get(base + "/", {"Origin": "https://gateway-cors-probe.invalid"}, args.timeout); sent += 1
        acao = hdrs.get("Access-Control-Allow-Origin") or hdrs.get("access-control-allow-origin")
        report["cors"] = {"acao": acao, "reflects_probe_origin": acao == "https://gateway-cors-probe.invalid"}

    # Error disclosure on a malformed route
    if sent < MAX_REQUESTS:
        code, _, body = get(base + "/%00../gateway-error-" + secrets.token_hex(3), {}, args.timeout); sent += 1
        markers = [m for m in ("Exception", "at com.", "Traceback", "stacktrace", "Whitelabel Error", "eureka", "consul", "nginx/", "Server:") if m.lower() in body.lower()]
        report["errors"] = {"status": code, "disclosure_markers": markers}

    # Port exposure for in-scope internal services (Kali nmap)
    if args.ports and args.host and shutil.which("nmap"):
        out = subprocess.run(["nmap", "-Pn", "-n", "-p", args.ports, "-sV", "--open", args.host],
                             capture_output=True, text=True, timeout=300).stdout
        report["ports"] = [l for l in out.splitlines() if "/tcp" in l and "open" in l]

    report["requests_sent"] = sent
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
