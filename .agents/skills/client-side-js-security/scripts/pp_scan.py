#!/usr/bin/env python3
"""Passive prototype pollution sink scanner for JavaScript and Node source (read-only).

Flags merge, extend, and property-assignment sinks, and marks a finding high when
the same statement reads from a request, URL, or JSON source. Use only on source
or bundles you are authorized to review.

Usage: pp_scan.py <dir-or-file> [--out artifacts/<target>/pp_sinks.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SKIP = {".git", "node_modules", "dist", "build", "vendor", "__pycache__"}
EXTS = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")
SINKS = [
    ("lodash merge/defaultsDeep", re.compile(r"_\.(merge|mergeWith|defaultsDeep|set|setWith)\s*\(")),
    ("jQuery deep extend", re.compile(r"\$\.extend\s*\(\s*true")),
    ("Object.assign", re.compile(r"Object\.assign\s*\(")),
    ("deep merge helper", re.compile(r"\b(deepmerge|merge|deepExtend|extend)\s*\(")),
    ("__proto__ or constructor.prototype access", re.compile(r"__proto__|constructor\s*\.\s*prototype|\[\s*['\"]__proto__['\"]\s*\]")),
    ("dynamic property assignment", re.compile(r"\[\s*[\w.]+\s*\]\s*=\s*")),
]
SOURCES = re.compile(r"(req\.(body|query|params)|request\.(json|args|form)|location\.(hash|search)|URLSearchParams|JSON\.parse|window\.name|localStorage|postMessage|event\.data)")


def scan_file(path: str, out: list[dict]) -> None:
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        for name, rx in SINKS:
            if rx.search(line):
                window = "\n".join(lines[max(0, i - 3): i + 2])
                risk = "high" if SOURCES.search(window) else "review"
                out.append({"file": path, "line": i, "sink": name, "risk": risk, "snippet": s[:180]})
                break


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out")
    args = ap.parse_args()
    findings: list[dict] = []
    if os.path.isfile(args.root):
        scan_file(args.root, findings)
    else:
        for dp, dn, fn in os.walk(args.root):
            dn[:] = [d for d in dn if d not in SKIP]
            for f in fn:
                if f.endswith(EXTS):
                    scan_file(os.path.join(dp, f), findings)
    findings.sort(key=lambda f: (f["risk"] != "high", f["file"], f["line"]))
    summary = {"root": args.root, "total": len(findings),
               "high": sum(1 for f in findings if f["risk"] == "high"), "findings": findings}
    text = json.dumps(summary, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
