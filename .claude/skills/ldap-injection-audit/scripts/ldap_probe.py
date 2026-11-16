#!/usr/bin/env python3
"""Differential LDAP filter injection detection (login and search fields).

No directory enumeration. Each probe is compared with a baseline (random value,
should match nothing) and with a control (escaped wildcard \\2a, which must
behave like a literal asterisk). Boolean pairs use objectClass, which every
entry has, so a true and a false condition are compared without extracting data.

Scope gate runs first. Login tests use your own account and a wrong password.

Example:
  ldap_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/search --param cn --out artifacts/example.com/ldap.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 25
ERROR_SIGS = ["bad search filter", "invalid filter", "unbalanced", "invalidsearchfilter",
              "filter error", "ldap", "bad filter", "malformed filter", "parenthes"]


def send(url: str, method: str, param: str, value: str, others: dict[str, str],
         headers: dict[str, str], timeout: float) -> tuple[int, str]:
    pairs = [(param, value)] + list(others.items())
    ctx = ssl.create_default_context()
    if method == "GET":
        target = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(pairs)
        req = urllib.request.Request(target, method="GET", headers=headers)
    else:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(pairs).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read(200_000).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, str(err)


def fp(status: int, body: str) -> dict:
    return {"status": status, "length": len(body), "sha": hashlib.sha256(body.encode()).hexdigest()[:16]}


def differs(a: dict, b: dict) -> bool:
    if a["status"] != b["status"]:
        return True
    if a["length"] and abs(a["length"] - b["length"]) / max(a["length"], 1) > 0.10:
        return True
    return a["sha"] != b["sha"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--other", action="append", default=[], help="other field name=value")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    others = dict(o.split("=", 1) for o in args.other if "=" in o)
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    rnd = "lq" + secrets.token_hex(4)
    sent = 0
    results = []

    def run(label: str, value: str, technique: str):
        nonlocal sent
        status, body = send(args.url, args.method, args.param, value, others, headers, args.timeout)
        sent += 1
        f = fp(status, body)
        err = any(s in body.lower() for s in ERROR_SIGS)
        results.append({"probe": label, "value": value, "technique": technique,
                        "fingerprint": f, "error_signature": err})
        time.sleep(args.delay)
        return f

    base = run("baseline (random value)", rnd, "baseline")
    escaped = run("control: escaped wildcard \\2a", rnd + "\\2a", "control-escaped")
    escape_is_literal = not differs(escaped, base)

    wildcard = run("wildcard *", "*", "wildcard")
    wildcard_hit = differs(wildcard, base) and escape_is_literal

    run("syntax: unbalanced parenthesis", rnd + ")(", "syntax")
    run("syntax: unbalanced OR", rnd + ")(|(", "syntax")
    run("syntax: lone backslash", rnd + "\\", "syntax")

    true_f = run("boolean TRUE: *)(objectClass=*", "*)(objectClass=*", "boolean-true")
    false_f = run("boolean FALSE: *)(objectClass=" + rnd + "-never", "*)(objectClass=" + rnd + "-never", "boolean-false")
    boolean_hit = differs(true_f, false_f)

    error_hit = any(r["error_signature"] for r in results)
    if wildcard_hit and boolean_hit:
        verdict = "ldap-filter-injection-indicated"
    elif wildcard_hit or boolean_hit:
        verdict = "partial-indication: confirm with a second pair"
    elif error_hit:
        verdict = "syntax-error-signature"
    else:
        verdict = "not-indicated"

    report = {"target": args.target, "url": args.url, "param": args.param, "method": args.method,
              "requests_sent": sent, "escaped_wildcard_literal": escape_is_literal,
              "wildcard_differs": wildcard_hit, "boolean_pair_differs": boolean_hit,
              "verdict": verdict, "results": results,
              "next_step": "Confirm on a second field and report the differential evidence. Do not enumerate "
                           "directory entries or attributes; stop at the boolean oracle."}
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
