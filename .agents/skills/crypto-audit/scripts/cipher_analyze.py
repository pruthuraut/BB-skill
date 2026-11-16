#!/usr/bin/env python3
"""Offline analysis of captured ciphertexts or tokens (one per line, your own).

For each token: detect encoding (hex, base64, base64url, JWT), decoded length,
block-size guess (8 or 16 if length is a multiple), repeated blocks (ECB
signal, CRY-007), printable plaintext after decoding (CRY-V-004), and embedded
timestamps. Across tokens: identical tokens, shared first blocks (static IV or
deterministic encryption, CRY-005 / CRY-V-005), common prefix/suffix, and
hashes of known values (--known) found inside tokens (CRY-V-003).

Example:
  cipher_analyze.py tokens.txt --known own@example.test 1042
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

# Windows consoles (cp1252) cannot print every character in payloads; never crash on output.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

def decode(tok: str) -> tuple[str, bytes | None]:
    t = tok.strip()
    if t.count(".") == 2 and t.startswith("eyJ"):
        return "jwt", None
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        return "hex", bytes.fromhex(t)
    for name, alt in (("base64url", "-_"), ("base64", "+/")):
        if re.fullmatch(r"[A-Za-z0-9%s]+=*" % re.escape(alt), t):
            try:
                s = t + "=" * (-len(t) % 4)
                return name, base64.b64decode(s, altchars=alt.encode())
            except (binascii.Error, ValueError):
                continue
    return "raw", t.encode()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    return round(-sum(n / len(b) * math.log2(n / len(b)) for n in c.values()), 2)


def blocks(b: bytes, size: int) -> list[bytes]:
    return [b[i:i + size] for i in range(0, len(b) - len(b) % size, size)]


def jwt_info(tok: str) -> dict:
    try:
        h = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
        p = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
        return {"header": h, "claims": sorted(p.keys()),
                "notes": (["alg none"] if str(h.get("alg", "")).lower() == "none" else [])
                         + (["kid present: test kid injection (CRY-014)"] if "kid" in h else [])
                         + (["jku/x5u present: test URL injection (CRY-014)"] if {"jku", "x5u"} & set(h) else [])}
    except Exception as e:
        return {"error": str(e)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--known", nargs="*", default=[], help="known values to hash and look for (email, user id, username)")
    ap.add_argument("--out")
    args = ap.parse_args()
    toks = [l.strip() for l in open(args.file, encoding="utf-8") if l.strip()]
    if not toks:
        sys.exit("no tokens")
    per, findings = [], []
    decoded = []
    for t in toks:
        enc, raw = decode(t)
        rec: dict = {"token": t[:24] + ("..." if len(t) > 24 else ""), "encoding": enc}
        if enc == "jwt":
            rec["jwt"] = jwt_info(t)
            per.append(rec); continue
        rec["bytes"] = len(raw)
        rec["entropy_bits_per_byte"] = entropy(raw)
        sizes = [s for s in (16, 8) if len(raw) % s == 0 and len(raw) >= 2 * s]
        rec["block_size_guess"] = sizes[0] if sizes else None
        for s in sizes:
            reps = [k.hex() for k, v in Counter(blocks(raw, s)).items() if v > 1]
            if reps:
                rec.setdefault("repeated_blocks", {})[s] = reps[:3]
                findings.append(f"CRY-007: repeated {s}-byte blocks in {rec['token']} (ECB or deterministic block mode)")
                break
        printable = sum(32 <= b < 127 for b in raw) / max(len(raw), 1)
        if printable > 0.9 and enc != "raw":
            rec["decoded_text"] = raw[:80].decode(errors="replace")
            findings.append(f"CRY-V-004: {rec['token']} decodes to readable text: {rec['decoded_text'][:40]!r}")
        for m in re.finditer(rb"\d{10,13}", raw):
            v = int(m.group()); v = v / 1000 if len(m.group()) == 13 else v
            if 946684800 < v < time.time() + 31536000:
                findings.append(f"CRY-V-003: timestamp {m.group().decode()} inside {rec['token']}")
        decoded.append(raw)
        per.append(rec)

    c = Counter(toks)
    if len(c) < len(toks):
        findings.append(f"CRY-005/CRY-V-005: {len(toks) - len(c)} identical tokens (static IV, deterministic encryption, or reuse)")
    for s in (16, 8):
        firsts = Counter(r[:s] for r in decoded if len(r) >= 2 * s)
        same = [k for k, v in firsts.items() if v > 1]
        if same and len(decoded) > 1:
            findings.append(f"CRY-005: {sum(firsts[k] for k in same)} tokens share the same first {s}-byte block (static IV or fixed prefix)")
            break
    if len(decoded) > 1:
        pre = os.path.commonprefix(decoded)
        if len(pre) >= 4:
            findings.append(f"common decoded prefix of {len(pre)} bytes: {pre[:16].hex()}")
    for val in args.known:
        for algo in ("md5", "sha1", "sha256"):
            d = hashlib.new(algo, val.encode()).hexdigest()
            for t in set(toks):
                if d in t.lower():
                    findings.append(f"CRY-V-003: {algo}({val}) appears in token {t[:16]}...")
    lens = Counter(r.get("bytes") for r in per if "bytes" in r)
    report = {"tokens": len(toks), "length_distribution": dict(lens), "per_token": per[:50], "findings": findings}
    print(json.dumps({k: v for k, v in report.items() if k != "per_token"}, indent=2))
    for r in per[:10]:
        print(r)
    if args.out:
        json.dump(report, open(args.out, "w", encoding="utf-8"), indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
