#!/usr/bin/env python3
"""Passive deserialization format detector for captured values (read-only).

Reads captured cookies, parameters, headers, or response bodies (text files you
collected through your own proxy or tests) and reports values that look like
serialized objects for Java, PHP, Python pickle, YAML, .NET, Ruby Marshal, and
Node node-serialize. It never decodes-and-executes anything.

Usage: deser_detect.py <captured.txt> [--out artifacts/<target>/deser.json]
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys

SIGNATURES = [
    ("java-serialized", re.compile(r"(^|[^A-Za-z])(rO0AB|aced0005)")),
    ("php-serialized", re.compile(r"\b[OaCs]:\d+:\"[\w\\]+\"")),
    ("python-pickle", re.compile(r"^(gASV|\x80\x04|\x80\x03)")),
    ("yaml-python-object", re.compile(r"!!python/(object|name|module)")),
    ("dotnet-binaryformatter", re.compile(r"AAEAAAD/////")),
    ("dotnet-viewstate", re.compile(r"__VIEWSTATE")),
    ("ruby-marshal", re.compile(r"^(BAh|\x04\x08)")),
    ("node-serialize", re.compile(r"_\$\$ND_FUNC\$\$_")),
]


def classify(token: str) -> str | None:
    texts = [token]
    try:
        texts.append(base64.b64decode(token + "=" * (-len(token) % 4)).decode("latin-1"))
    except Exception:
        pass
    for t in texts:
        for name, rx in SIGNATURES:
            if rx.search(t):
                return name
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--out")
    args = ap.parse_args()
    findings = []
    with open(args.path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            for token in set(re.findall(r"[A-Za-z0-9+/=_%.\"-]{12,}", line)):
                fmt = classify(token)
                if fmt:
                    findings.append({"line": n, "format": fmt, "value_excerpt": token[:60],
                                     "risk": "review: confirm the format and whether the server deserializes it"})
    summary = {"file": args.path, "total": len(findings), "findings": findings}
    text = json.dumps(summary, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
