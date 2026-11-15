#!/usr/bin/env python3
"""Generate identifier mutations for IDOR testing (offline).

Usage:
  id_mutator.py VALUE [--other OTHER_ID] [--encodings-only] [--between UUID_V1_B] [--limit 50]

  VALUE   your own (A) identifier or the target (B) identifier you own
  --other a second identifier you own; used for list/array/HPP combinations
  --between  for UUIDv1: second UUIDv1 created after VALUE -> prints the size of the
             "sandwich" search space and the first --limit candidates between them

Families: encodings, wrap (integer boundaries/overflow), juggle (type confusion),
list (arrays, comma lists, HPP strings, NoSQL operators), wildcard, uuid-format,
uuid-fixed, uuid-v1-neighbour, objectid-neighbour.
Output TSV: family  value
"""
import argparse
import base64
import json
import re
import sys
import uuid

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")


def encodings(v):
    s = str(v)
    out = [("encoding-base64", base64.b64encode(s.encode()).decode()),
           ("encoding-base64url", base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")),
           ("encoding-url", "".join(f"%{ord(c):02x}" for c in s)),
           ("encoding-double-url", "".join(f"%25{ord(c):02x}" for c in s)),
           ("encoding-hex-ascii", s.encode().hex())]
    if s.isdigit():
        n = int(s)
        out += [("encoding-hex", hex(n)), ("encoding-hex-bare", f"{n:x}"), ("encoding-octal-ish", "0" + s),
                ("encoding-graphql-global(User)", base64.b64encode(f"User:{s}".encode()).decode()),
                ("encoding-json-b64", base64.b64encode(json.dumps({"id": n}).encode()).decode())]
    return out


def int_mutations(n, other):
    out = []
    for d in (-2, -1, 1, 2):
        out.append(("neighbour", str(n + d)))
    out += [("wrap", x) for x in ("0", "-1", str(-n), "2147483647", "2147483648", str(2 ** 31 + n), str(2 ** 32 + n),
                                    "4294967295", "9223372036854775807", str(2 ** 63 + n), "18446744073709551615")]
    out += [("juggle", x) for x in (f"{n}.0", f"{n}e0", f"0{n}", f"+{n}", f" {n}", f"{n} ", f"{n}abc", f"{n}%00",
                                      f'"{n}"', "true", "null", "[]", "{}", f"{n}/", f"{n}#", f"{n}?")]
    return out


def list_mutations(v, other):
    o = other if other is not None else v
    jv = json.dumps(v) if not str(v).lstrip("-").isdigit() else str(v)
    jo = json.dumps(o) if not str(o).lstrip("-").isdigit() else str(o)
    return [("list-json-array", f"[{jv}]"), ("list-json-array-mixed", f"[{jo},{jv}]"),
            ("list-json-object", f'{{"id":{jv}}}'), ("list-nosql-in", f'{{"$in":[{jo},{jv}]}}'),
            ("list-nosql-ne", '{"$ne":null}'), ("list-nosql-gt", '{"$gt":""}'),
            ("list-comma", f"{o},{v}"), ("list-semicolon", f"{o};{v}"), ("list-pipe", f"{o}|{v}"),
            ("hpp-query", f"id={o}&id={v}"), ("hpp-array", f"id[]={o}&id[]={v}"),
            ("hpp-encoded", f"{o}%26id%3D{v}")]


def wildcards():
    return [("wildcard", x) for x in ("*", "%", "_", "%25", ".*", "all", "any", "me", "self", "current", "-", "~")]


def uuid_mutations(s, between=None, limit=50):
    u = uuid.UUID(s)
    out = [("uuid-format", str(u).upper()), ("uuid-format", u.hex), ("uuid-format", "{" + str(u) + "}"),
           ("uuid-format", "urn:uuid:" + str(u)), ("uuid-format", base64.b64encode(u.bytes).decode())]
    out += [("uuid-fixed", x) for x in ("00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111",
                                          "ffffffff-ffff-ffff-ffff-ffffffffffff", "00000000-0000-0000-0000-000000000001",
                                          "12345678-1234-1234-1234-123456789012")]
    if u.version == 1:
        node, clock = u.node, u.clock_seq
        def mk(t):
            return str(uuid.UUID(fields=(t & 0xffffffff, (t >> 32) & 0xffff, ((t >> 48) & 0x0fff) | 0x1000,
                                         (clock >> 8) | 0x80, clock & 0xff, node)))
        for d in (-10000, -1, 1, 10000):          # +/- 1 ms is 10000 ticks
            out.append((f"uuid-v1-neighbour({d:+d} ticks)", mk(u.time + d)))
        if between:
            v = uuid.UUID(between)
            if v.version != 1:
                print("# --between must also be a UUIDv1", file=sys.stderr)
            else:
                lo, hi = sorted((u.time, v.time))
                span = hi - lo - 1
                same = u.node == v.node and u.clock_seq == v.clock_seq
                print(f"# sandwich: {span:,} candidate timestamps between the two UUIDs "
                      f"({span / 1e7:.3f} s); node/clock_seq {'identical' if same else 'DIFFER - candidates less reliable'}",
                      file=sys.stderr)
                step = max(1, span // max(limit, 1))
                for t in range(lo + 1, hi, step)[:limit]:
                    out.append(("uuid-v1-sandwich", mk(t)))
    return out


def objectid_mutations(s, limit=10):
    ts, mid, ctr = s[:8], s[8:18], int(s[18:], 16)
    out = []
    for d in range(1, min(limit, 5) + 1):
        out.append((f"objectid-neighbour(counter-{d})", f"{ts}{mid}{(ctr - d) % (1 << 24):06x}"))
        out.append((f"objectid-neighbour(counter+{d})", f"{ts}{mid}{(ctr + d) % (1 << 24):06x}"))
    out.append(("objectid-neighbour(ts+1s)", f"{int(ts, 16) + 1:08x}{mid}{(ctr + 1) % (1 << 24):06x}"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("value")
    ap.add_argument("--other")
    ap.add_argument("--encodings-only", action="store_true")
    ap.add_argument("--between")
    ap.add_argument("--limit", type=int, default=50)
    a = ap.parse_args()
    v = a.value.strip()

    rows = []
    if a.encodings_only:
        rows = encodings(v)
    else:
        if re.fullmatch(r"-?\d{1,19}", v):
            rows += int_mutations(int(v), a.other)
        elif UUID_RE.match(v):
            rows += uuid_mutations(v, a.between, a.limit)
        elif re.fullmatch(r"[0-9a-fA-F]{24}", v):
            rows += objectid_mutations(v.lower(), a.limit)
        rows += encodings(v)
        rows += list_mutations(v, a.other)
        rows += wildcards()
    print("family\tvalue")
    seen = set()
    for fam, val in rows:
        if val in seen:
            continue
        seen.add(val)
        print(f"{fam}\t{val}")


if __name__ == "__main__":
    main()
