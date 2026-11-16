#!/usr/bin/env python3
"""WAF bypass differential probe (Kali: wafw00f for fingerprinting when installed).

Sends a small set of benign attack-shaped test strings in several encodings and
compares the block signal with the plain form. A bypass candidate is an encoding
that passes where the plain form was blocked. Candidates must be verified by a
person on an in-scope endpoint before reporting. Bounded: capped at 40 requests.
Scope gate runs first.

Example:
  waf_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/search --param q --out artifacts/example.com/waf.json
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 40
# Benign test strings that most WAF rule sets flag. They do nothing on the server.
TEST_STRINGS = ["<script>waftest</script>", "' or 'waftest'='waftest", "../waftest/../"]
BLOCK_CODES = {403, 406, 429, 501, 503}


def encodings(s: str) -> dict[str, str]:
    url1 = urllib.parse.quote(s, safe="")
    return {
        "plain": s,
        "url-encoded": url1,
        "double-url-encoded": urllib.parse.quote(url1, safe=""),
        "unicode-escaped": "".join(f"\\u{ord(c):04x}" for c in s),
        "html-entities": "".join(f"&#{ord(c)};" for c in s),
        "base64-wrapped": base64.b64encode(s.encode()).decode(),
        "case-variation": "".join(c.upper() if i % 2 else c for i, c in enumerate(s)),
        "inline-comment": s.replace(" ", "/**/"),
        "null-byte-prefix": "%00" + url1,
    }


def send(url: str, param: str, value: str, method: str, timeout: float) -> tuple[int, str]:
    if method == "GET":
        sep = "&" if "?" in url else "?"
        req_url = f"{url}{sep}{urllib.parse.urlencode({param: value})}"
        req = urllib.request.Request(req_url, method="GET")
    else:
        req = urllib.request.Request(url, data=urllib.parse.urlencode({param: value}).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    fingerprint = None
    if shutil.which("wafw00f"):
        out = subprocess.run(["wafw00f", args.url, "-a"], capture_output=True, text=True, timeout=120).stdout
        fingerprint = [l.strip() for l in out.splitlines() if "is behind" in l or "No WAF" in l][:3]

    sent = 0
    results = []
    for s in TEST_STRINGS:
        for name, value in encodings(s).items():
            if sent >= MAX_REQUESTS:
                break
            code, body = send(args.url, args.param, value, args.method, args.timeout)
            sent += 1
            results.append({"test": s, "encoding": name, "status": code,
                            "blocked": code in BLOCK_CODES})
            time.sleep(args.delay)

    candidates = []
    for s in TEST_STRINGS:
        rows = [r for r in results if r["test"] == s]
        plain = next((r for r in rows if r["encoding"] == "plain"), None)
        if plain and plain["blocked"]:
            candidates += [r["encoding"] for r in rows if not r["blocked"]]

    report = {"url": args.url, "param": args.param, "method": args.method, "requests_sent": sent,
              "wafw00f": fingerprint, "bypass_candidates": sorted(set(candidates)),
              "results": results,
              "next_step": "Verify each candidate manually on an in-scope endpoint, confirm the server decodes it, "
                           "and report with the request and response. Do not send real attack payloads."}
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
