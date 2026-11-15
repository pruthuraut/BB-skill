#!/usr/bin/env python3
"""Offline session-token analysis for SM-01, SM-02 and SM-39.

Usage:
  token_entropy.py TOKENS_FILE                 # one token per line
  token_entropy.py TOKENS_FILE --lengths-only
  token_entropy.py TOKENS_FILE --labelled      # lines are "<label> <token>", e.g. "A abc..." / "B def..."

Reports length, charset, theoretical bits, per-position Shannon entropy (an
estimate of effective entropy), constant positions, duplicates, and signs of
counters or timestamps. This is a triage aid; confirm with Burp Sequencer.
"""
import argparse
import math
import re
import string
import sys
import time
from collections import Counter, defaultdict

CHARSETS = [
    ("decimal", set(string.digits)),
    ("hex-lower", set("0123456789abcdef")),
    ("hex-upper", set("0123456789ABCDEF")),
    ("hex", set(string.hexdigits)),
    ("alphanumeric", set(string.ascii_letters + string.digits)),
    ("base64url", set(string.ascii_letters + string.digits + "-_=")),
    ("base64", set(string.ascii_letters + string.digits + "+/=")),
]
CHARSET_SIZE = {"decimal": 10, "hex-lower": 16, "hex-upper": 16, "hex": 16,
                "alphanumeric": 62, "base64url": 64, "base64": 64}


def load(path, labelled):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if labelled:
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                out.append((parts[0], parts[1]))
            else:
                out.append(("-", line))
    return out


def detect_charset(tokens):
    chars = set("".join(tokens))
    for name, cs in CHARSETS:
        if chars <= cs:
            return name, CHARSET_SIZE[name]
    return "mixed/other", max(len(chars), 2)


def shannon(counter, n):
    return -sum((c / n) * math.log2(c / n) for c in counter.values())


def positional(tokens):
    width = min(len(t) for t in tokens)
    n = len(tokens)
    ents, const = [], []
    for i in range(width):
        col = Counter(t[i] for t in tokens)
        e = shannon(col, n)
        ents.append(e)
        if len(col) == 1:
            const.append(i)
    return width, ents, const


def numeric_pattern(tokens):
    """Look for monotonic numeric runs (counters/timestamps) in the token stream."""
    findings = []
    # whole-token as int
    for base, rx in ((16, r"[0-9a-fA-F]+"), (10, r"[0-9]+")):
        if all(re.fullmatch(rx, t) for t in tokens) and len(tokens) > 3:
            vals = [int(t, base) for t in tokens]
            diffs = [b - a for a, b in zip(vals, vals[1:])]
            inc = sum(1 for d in diffs if d > 0) / len(diffs)
            if inc > 0.9 or inc < 0.1:
                findings.append(f"whole token parsed base{base} is {'increasing' if inc > 0.9 else 'decreasing'} "
                                f"in {max(inc, 1 - inc):.0%} of steps (counter-like)")
            break
    # embedded epoch timestamps
    now = int(time.time())
    ts_hits = 0
    for t in tokens:
        for m in re.findall(r"\d{10,13}", t):
            v = int(m[:10])
            if abs(v - now) < 10 * 365 * 86400:
                ts_hits += 1
                break
    if ts_hits >= max(3, len(tokens) // 2):
        findings.append(f"{ts_hits}/{len(tokens)} tokens contain a plausible Unix timestamp")
    # hex-encoded epoch at a fixed offset in (almost) every token
    width = min(len(t) for t in tokens)
    for off in range(0, max(width - 7, 0)):
        vals = []
        for t in tokens:
            seg = t[off:off + 8].lower()
            if not re.fullmatch(r"[0-9a-f]{8}", seg):
                break
            vals.append(int(seg, 16))
        else:
            plausible = sum(1 for v in vals if abs(v - now) < 10 * 365 * 86400)
            if plausible >= 0.9 * len(vals) and len(vals) >= 10:
                findings.append(f"offset {off}: 8 hex chars decode to plausible Unix timestamps in "
                                f"{plausible}/{len(vals)} tokens (e.g. {vals[0]})")
                break
    return findings


def common_affix(tokens):
    pre = tokens[0]
    suf = tokens[0]
    for t in tokens[1:]:
        while not t.startswith(pre):
            pre = pre[:-1]
        while not t.endswith(suf):
            suf = suf[1:]
    return pre, suf


def report(tokens, title, lengths_only=False):
    n = len(tokens)
    lens = Counter(len(t) for t in tokens)
    print(f"== {title}: {n} tokens")
    print(f"   lengths (chars): {dict(sorted(lens.items()))}")
    cs_name, cs_size = detect_charset(tokens)
    bits_per_char = math.log2(cs_size)
    min_len = min(lens)
    raw_bytes = min_len * bits_per_char / 8
    print(f"   charset: {cs_name} (~{bits_per_char:.2f} bits/char) -> max theoretical {min_len * bits_per_char:.0f} bits "
          f"(~{raw_bytes:.1f} bytes)")
    verdict_len = "OK" if min_len * bits_per_char >= 128 else "BELOW 128 bits (SM-02)"
    print(f"   length verdict: {verdict_len}")
    if lengths_only:
        return
    dups = [t for t, c in Counter(tokens).items() if c > 1]
    print(f"   duplicates: {len(dups)}" + (f"  e.g. {dups[0][:40]}" if dups else ""))
    pre, suf = common_affix(tokens)
    if pre or suf:
        print(f"   common prefix: {pre!r}  common suffix: {suf!r}")
    width, ents, const = positional(tokens)
    eff = sum(ents)
    cap = math.log2(n) if n > 1 else 0
    print(f"   per-position entropy sum (effective estimate): {eff:.1f} bits over {width} positions")
    print(f"   note: each position's estimate is capped at log2({n}) = {cap:.2f} bits; collect more samples if bits/char > cap")
    if const:
        print(f"   constant positions ({len(const)}): {const[:40]}{' ...' if len(const) > 40 else ''}")
    low = [i for i, e in enumerate(ents) if e < 0.5 * min(bits_per_char, cap) and i not in const]
    if low:
        print(f"   low-entropy positions ({len(low)}): {low[:40]}{' ...' if len(low) > 40 else ''}")
    for f in numeric_pattern(tokens):
        print(f"   PATTERN: {f}")
    if n < 100:
        print("   WARNING: fewer than 100 samples; results are indicative only")
    verdict = "LIKELY WEAK (<64 bits effective)" if eff < 64 else "no obvious weakness (confirm in Burp Sequencer)"
    print(f"   entropy verdict: {verdict}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--lengths-only", action="store_true")
    ap.add_argument("--labelled", action="store_true")
    a = ap.parse_args()

    rows = load(a.file, a.labelled)
    if not rows:
        sys.exit("no tokens loaded")
    all_tokens = [t for _, t in rows]
    report(all_tokens, "all tokens", a.lengths_only)

    if a.labelled:
        groups = defaultdict(list)
        for lab, t in rows:
            groups[lab].append(t)
        width = min(len(t) for t in all_tokens)
        per_label_const = {}
        for lab, toks in groups.items():
            print()
            report(toks, f"label {lab}", a.lengths_only)
            if len(toks) > 1:
                _, _, c = positional(toks)
                per_label_const[lab] = {i: toks[0][i] for i in c if i < width}
        # positions constant within each label but different between labels -> identity-derived
        if len(per_label_const) >= 2:
            labs = list(per_label_const)
            shared = set.intersection(*(set(v) for v in per_label_const.values()))
            identity = [i for i in sorted(shared) if len({per_label_const[l][i] for l in labs}) > 1]
            print()
            if identity:
                print(f"== SM-39 PATTERN: positions {identity} are constant per account but differ between accounts "
                      f"(identity-derived token material)")
            else:
                print("== SM-39: no identity-derived positions detected")


if __name__ == "__main__":
    main()
