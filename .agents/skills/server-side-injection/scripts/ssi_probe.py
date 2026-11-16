#!/usr/bin/env python3
"""Server-Side Include (SSI) injection probe (bounded: harmless echo directives only).

Sends SSI echo directives for built-in variables and checks whether the server
evaluated them. No exec directives are sent (exec runs commands and is
authorized-only). Scope gate runs first.

Example:
  ssi_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/search --param q
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
DATE_RX = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}:\d{2}|(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*day?")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    marker = "ssi" + secrets.token_hex(4)
    directives = ['<!--#echo var="DATE_LOCAL" -->', '<!--#echo var="DOCUMENT_NAME" -->',
                  f'{marker}<!--#echo var="DOCUMENT_NAME" -->']
    results = []
    for d in directives:
        sep = "&" if "?" in args.url else "?"
        url = f"{args.url}{sep}{urllib.parse.urlencode({args.param: d})}"
        try:
            with urllib.request.urlopen(url, timeout=args.timeout, context=ssl.create_default_context()) as r:
                body, status = r.read(20000).decode("utf-8", "replace"), r.status
        except urllib.error.HTTPError as e:
            body, status = e.read(20000).decode("utf-8", "replace"), e.code
        except (urllib.error.URLError, OSError) as e:
            body, status = str(e), 0
        # Evaluated: the directive text is gone and the output looks like a date or the page name.
        evaluated = ("<!--#echo" not in body) and bool(DATE_RX.search(body) or (marker in body))
        results.append({"directive": d, "status": status, "evaluated": evaluated})

    report = {"url": args.url, "param": args.param, "requests_sent": len(directives),
              "verdict": "ssi-evaluated" if any(r["evaluated"] for r in results) else "not-indicated",
              "results": results,
              "next_step": "Confirm with a second SSI echo. exec directives are authorized-only and are not sent."}
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
