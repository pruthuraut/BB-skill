#!/usr/bin/env python3
"""Offline analysis of collected anti-CSRF tokens (no network).

Input: a file with one token per line, collected from your own sessions
(log in and out, both accounts, several page loads).

Reports: count, duplicates, length spread, character set, estimated entropy,
static prefix and suffix shared by all tokens, hash-length hints, embedded
timestamps (decimal or hex), and base64-decoded structure.

Example:
  csrf_token_analyze.py tokens.txt --known user123 victim@example.test
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter

HASH_LENGTHS = {32: "MD5 (hex)", 40: "SHA-1 (hex)", 56: "SHA-224 (hex)", 64: "SHA-256 (hex)", 128: "SHA-512 (hex)"}


def common_prefix(items: list[str]) -> str:
    return os.path.commonprefix(items)


def common_suffix(items: list[str]) -> str:
    return os.path.commonprefix([s[::-1] for s in items])[::-1]


def charset(tokens: list[str]) -> tuple[str, int]:
    joined = "".join(tokens)
    if re.fullmatch(r"[0-9]*", joined):
        return "decimal", 10
    if re.fullmatch(r"[0-9a-f]*", joined):
        return "hex lowercase", 16
    if re.fullmatch(r"[0-9A-F]*", joined):
        return "hex uppercase", 16
    if re.fullmatch(r"[0-9A-Za-z]*", joined):
        return "alphanumeric", 62
    if re.fullmatch(r"[0-9A-Za-z+/=]*", joined):
        return "base64", 64
    if re.fullmatch(r"[0-9A-Za-z\-_=]*", joined):
        return "base64url", 64
    return "mixed", len(set(joined))


def find_timestamps(tok: str) -> list[str]:
    now = time.time()
    hits = []
    for m in re.finditer(r"\d{10,13}", tok):
        v = int(m.group())
        v = v / 1000 if len(m.group()) == 13 else v
        if 946684800 < v < now + 86400 * 365:
            hits.append(f"decimal {m.group()} = {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(v))} UTC")
    for m in re.finditer(r"[0-9a-f]{8}", tok.lower()):
        v = int(m.group(), 16)
        if now - 86400 * 365 * 3 < v < now + 86400:
            hits.append(f"hex {m.group()} = {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(v))} UTC")
    return hits


def try_b64(tok: str) -> str | None:
    s = tok.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    printable = sum(32 <= b < 127 for b in raw) / max(len(raw), 1)
    if printable > 0.85:
        return raw.decode("ascii", errors="replace")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--known", nargs="*", default=[], help="known values to hash and compare (user id, email, username)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    tokens = [l.strip() for l in open(args.file, encoding="utf-8") if l.strip()]
    if not tokens:
        sys.exit("no tokens in file")
    counts = Counter(tokens)
    lengths = Counter(len(t) for t in tokens)
    cs_name, cs_size = charset(tokens)
    pre, suf = common_prefix(tokens), common_suffix(tokens)
    if len(tokens) == 1:
        pre = suf = ""
    variable_len = max(min(lengths) - len(pre) - len(suf), 0)
    entropy_bits = round(variable_len * math.log2(cs_size), 1) if cs_size > 1 else 0.0

    per_pos_entropy = []
    if len(set(lengths)) == 1 and len(tokens) >= 5:
        L = len(tokens[0])
        for i in range(L):
            c = Counter(t[i] for t in tokens)
            h = -sum((n / len(tokens)) * math.log2(n / len(tokens)) for n in c.values())
            per_pos_entropy.append(round(h, 2))
    low_positions = [i for i, h in enumerate(per_pos_entropy) if h == 0]

    known_hits = []
    for val in args.known:
        for algo in ("md5", "sha1", "sha256"):
            d = hashlib.new(algo, val.encode()).hexdigest()
            for t in set(tokens):
                if d in t.lower():
                    known_hits.append(f"{algo}({val}) appears in token {t[:12]}...")

    findings = []
    if len(counts) < len(tokens):
        findings.append(f"duplicate tokens: {len(tokens) - len(counts)} repeats (token may be fixed per account or global)")
    if pre:
        findings.append(f"static prefix shared by all tokens: '{pre}' (try sending only the static part, XSRF-B-009)")
    if suf:
        findings.append(f"static suffix shared by all tokens: '{suf}'")
    if entropy_bits and entropy_bits < 128:
        findings.append(f"estimated variable entropy {entropy_bits} bits is below 128")
    if low_positions and not pre and not suf:
        findings.append(f"positions never changing across samples: {low_positions[:20]}")
    if cs_name == "decimal":
        findings.append("decimal-only token: check for counters or timestamps")
    hl = HASH_LENGTHS.get(min(lengths)) if cs_name.startswith("hex") and len(lengths) == 1 else None
    if hl:
        findings.append(f"length matches {hl}: try hashing known values with --known (XSRF-B-010)")
    ts = sorted({h for t in tokens[:50] for h in find_timestamps(t)})
    if ts:
        findings.append("possible embedded timestamps: " + "; ".join(ts[:5]))
    decoded = [d for d in (try_b64(t) for t in tokens[:5]) if d]
    if decoded:
        findings.append("base64 decodes to readable text, e.g. " + repr(decoded[0][:80]))
    findings += known_hits
    if len(tokens) < 20:
        findings.append(f"only {len(tokens)} samples; collect 20 or more for reliable results")

    report = {
        "samples": len(tokens), "unique": len(counts), "lengths": dict(lengths),
        "charset": cs_name, "static_prefix": pre, "static_suffix": suf,
        "estimated_variable_entropy_bits": entropy_bits, "findings": findings,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for k, v in report.items():
            if k != "findings":
                print(f"{k}: {v}")
        print("findings:")
        for f in findings or ["none (tokens look random at this sample size)"]:
            print(f"  - {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
