#!/usr/bin/env python3
"""Detect server-side template injection with harmless arithmetic probes.

Only arithmetic and marker probes are sent. Execution, file-read, and gadget
payloads are intentionally not part of this tool. The scope gate runs first.

Example:
  ssti_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url 'https://example.com/preview' --param template --method POST --json-body

Output: JSON with one result per probe and an engine hint. Stop at detection;
hand confirmed injections to a human for approved, lab-only follow-up.
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

# (probe, expected evaluated output, engine hint if it matches)
# "{m}" is replaced by a per-run marker so responses can be matched exactly.
PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig/Tornado/Nunjucks/Pebble family"),
    ("${7*7}", "49", "FreeMarker/Mako/Velocity-style ${} evaluation"),
    ("#{7*7}", "49", "FreeMarker/Ruby-style #{} evaluation"),
    ("<%= 7*7 %>", "49", "ERB or EJS-style evaluation"),
    ("${{7*7}}", "49", "Java EL/Thymeleaf-style double evaluation"),
    ("{{7*'7'}}", "7777777", "Jinja2 or Tornado (string repetition)"),
    ("{{7*'7'}}", "49", "Twig (numeric coercion)"),
    ("{{'{m}'|length}}", None, "Jinja2 filter support (marker length)"),
    ("{7*7}", "49", "Smarty/Groovy-style brace evaluation"),
    ("${7*77777}", "544439", "FreeMarker/Mako long-form confirmation"),
    ("{{7*77777}}", "544439", "Jinja2/Twig long-form confirmation"),
    ("<%= 7*77777 %>", "544439", "ERB long-form confirmation"),
    ("#{7*77777}", "544439", "FreeMarker long-form confirmation"),
    ("{{'{m}'.upper()}}", "{MU}", "Jinja2 method call on string (marker uppercased)"),
    ("${{<%[%'\"}}%\\.", None, "Syntax-break characters (look for error text, not output)"),
    ("{{<%[%'\"}}%\\.", None, "Syntax-break characters (Jinja2/Twig error signature)"),
    ("@(1+2)", "3", ".NET Razor evaluation"),
    ("{{this}}", "[object Object]", "Handlebars or Dust-style object rendering"),
    ("{$smarty.version}", None, "Smarty version variable (evaluated if output differs from the literal)"),
    ("#set($x=7*7)$x", "49", "Apache Velocity directive evaluation"),
]

ERROR_HINTS = {
    "jinja2": ["jinja2", "templatesyntaxerror", "undefined", "unexpected '}'"],
    "twig": ["twig\\error", "unexpected token", "twig_error"],
    "freemarker": ["freemarker", "parseexception", "freemarker.core"],
    "velocity": ["velocity", "parseerrorexception", "methodinvocationexception"],
    "erb": ["syntaxerror", "erb", "undefined local variable"],
    "smarty": ["smarty", "smarty_internal"],
    "thymeleaf": ["thymeleaf", "templateprocessingexception"],
}


def run_scope_check(target: str, workspace: str | None) -> None:
    cmd = [SCOPE, target] + ([workspace] if workspace else [])
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode)


def send(url: str, param: str, value: str, method: str, as_json: bool,
         extra_headers: dict[str, str], timeout: float) -> tuple[int, str]:
    ctx = ssl.create_default_context()
    if method == "GET":
        parsed = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        q = [(k, v) for k, v in q if k != param] + [(param, value)]
        target = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(q)))
        req = urllib.request.Request(target, method="GET", headers=extra_headers)
    else:
        if as_json:
            body = json.dumps({param: value}).encode()
            ctype = "application/json"
        else:
            body = urllib.parse.urlencode({param: value}).encode()
            ctype = "application/x-www-form-urlencoded"
        headers = {"Content-Type": ctype, **extra_headers}
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read(200_000).decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="scope target name (scope.txt owner)")
    ap.add_argument("--workspace", help="workspace root that contains <target>/scope.txt")
    ap.add_argument("--url", required=True, help="endpoint that receives the parameter")
    ap.add_argument("--param", required=True, help="parameter name to test")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--json-body", action="store_true", help="send POST body as JSON")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (own session cookie allowed)")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out", help="write JSON result to this path")
    args = ap.parse_args()

    run_scope_check(args.target, args.workspace)

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    marker = "ssti" + secrets.token_hex(3)
    results = []
    sent = 0
    engine_votes: dict[str, int] = {}

    # Baseline first so reflected text is not confused with evaluated output.
    base_value = marker
    status, body = send(args.url, args.param, base_value, args.method, args.json_body, headers, args.timeout)
    sent += 1
    baseline_body = body
    baseline_has_marker = marker in body
    results.append({"probe": "baseline (marker)", "status": status, "length": len(body),
                    "reflected": baseline_has_marker, "evaluated": False, "note": ""})
    time.sleep(args.delay)

    for probe, expect, hint in PROBES:
        if sent >= MAX_REQUESTS:
            break
        value = probe.replace("{m}", marker)
        if expect == "{MU}":
            expect_val = marker.upper()
        elif expect is None:
            expect_val = None
        else:
            expect_val = expect
        status, body = send(args.url, args.param, value, args.method, args.json_body, headers, args.timeout)
        sent += 1
        low = body.lower()
        # Evaluated = expected result appears, and it was not already in the baseline response.
        evaluated = bool(expect_val) and expect_val in body and expect_val not in baseline_body
        note = ""
        if evaluated and hint:
            note = hint
            engine_votes[hint] = engine_votes.get(hint, 0) + 1
        # Error signatures count only when the probe text is not simply echoed back.
        for engine, sigs in ERROR_HINTS.items():
            if value not in body and any(sig in low for sig in sigs):
                engine_votes[engine] = engine_votes.get(engine, 0) + 1
                note = (note + "; " if note else "") + f"error signature: {engine}"
        results.append({"probe": value, "status": status, "length": len(body),
                        "reflected": value in body, "evaluated": evaluated, "note": note})
        time.sleep(args.delay)

    verdict = "possible-ssti" if any(r["evaluated"] for r in results) else "no-evaluation-seen"
    report = {
        "target": args.target, "url": args.url, "param": args.param, "method": args.method,
        "requests_sent": sent, "marker": marker, "verdict": verdict,
        "engine_hints": sorted(engine_votes, key=engine_votes.get, reverse=True),
        "results": results,
        "next_step": "Confirm the evaluated result with a second, different probe. Do not run command or file-read payloads without written approval for this check.",
    }
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
