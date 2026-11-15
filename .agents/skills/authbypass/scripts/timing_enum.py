#!/usr/bin/env python3
"""Response-timing comparison for username enumeration (AB-01) and comparison
timing (AB-20). Scope-gated, interleaved, rate-limited.

Usage:
  timing_enum.py --target example.com --url https://app.example.com/login \
      --data 'username={user}&password=WrongPass!{n}' --users A,nouser_x1,nouser_x2 \
      [--samples 12] [--delay 1.0] [--content-type application/x-www-form-urlencoded] [--header 'K: V']

  {user} is replaced by each candidate, {n} by a unique counter (avoids caching).
  Include only YOUR OWN account(s) plus random non-existent names. Keep --samples low
  enough not to lock your own account (wrong-password attempts count toward lockout).

Prints per-user median/IQR and a Mann-Whitney U comparison of each user against the
pooled random-name baseline (rank-biserial effect size). Requires no third-party modules.
"""
import argparse
import math
import os
import random
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def scope_gate(host):
    here = os.path.dirname(os.path.abspath(__file__))
    gate = os.path.normpath(os.path.join(here, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", gate, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write(r.stdout + r.stderr)
    if r.returncode != 0:
        sys.exit(r.returncode)


def mann_whitney(x, y):
    """Return (U, z, rank-biserial r). Normal approximation with tie correction."""
    combined = sorted([(v, 0) for v in x] + [(v, 1) for v in y])
    ranks = [0.0] * len(combined)
    i = 0
    tie_term = 0.0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        t = j - i + 1
        tie_term += t ** 3 - t
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    n1, n2 = len(x), len(y)
    u1 = r1 - n1 * (n1 + 1) / 2
    mu = n1 * n2 / 2
    n = n1 + n2
    sigma = math.sqrt(n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))) if n > 1 else 0
    z = (u1 - mu) / sigma if sigma else 0.0
    rb = 2 * u1 / (n1 * n2) - 1
    return u1, z, rb


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--users", required=True, help="comma-separated; first ones = your accounts, names containing 'nouser'/'doesnotexist' = baseline")
    ap.add_argument("--samples", type=int, default=12)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--content-type", default="application/x-www-form-urlencoded")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    a = ap.parse_args()

    if a.samples > 100:
        sys.exit("--samples capped at 100 to protect your own account from lockout and the target from load")
    host = (urlsplit(a.url).hostname or "").lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"URL host {host} is outside target {a.target}")
    scope_gate(host)

    users = [u.strip() for u in a.users.split(",") if u.strip()]
    baseline_names = [u for u in users if any(k in u.lower() for k in ("nouser", "doesnotexist", "random", "invalid"))]
    if not baseline_names:
        sys.exit("include at least one random non-existent name containing 'nouser' or 'doesnotexist' as the baseline")

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {"Content-Type": a.content_type, "User-Agent": "bbtest-timing/1.0"}
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    times = {u: [] for u in users}
    statuses = {u: set() for u in users}
    sizes = {u: set() for u in users}
    n = 0
    order = []
    for _ in range(a.samples):
        rnd = users[:]
        random.shuffle(rnd)          # interleave to cancel drift
        order += rnd
    print(f"[*] {len(order)} requests, delay {a.delay}s", file=sys.stderr)
    for u in order:
        n += 1
        body = a.data.replace("{user}", u).replace("{n}", str(n)).encode()
        req = urllib.request.Request(a.url, data=body, headers=headers, method="POST")
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
                data = r.read()
                code = r.status
        except urllib.error.HTTPError as e:
            data = e.read()
            code = e.code
        except Exception as e:  # noqa: BLE001
            print(f"request error for {u}: {e}", file=sys.stderr)
            time.sleep(a.delay)
            continue
        dt = (time.perf_counter() - t0) * 1000
        times[u].append(dt)
        statuses[u].add(code)
        sizes[u].add(len(data))
        time.sleep(a.delay)

    base = [v for b in baseline_names for v in times[b]]
    print(f"{'user':<28}{'n':>4}{'median ms':>11}{'IQR ms':>9}  status  sizes   vs-baseline")
    for u in users:
        ts = sorted(times[u])
        if len(ts) < 3:
            print(f"{u:<28}{len(ts):>4}  insufficient samples")
            continue
        q = statistics.quantiles(ts, n=4)
        comp = ""
        if u not in baseline_names and len(base) >= 3:
            _, z, rb = mann_whitney(ts, base)
            verdict = "DIFFERENT" if abs(z) >= 3 and abs(rb) >= 0.5 else ("weak signal" if abs(z) >= 2 else "no difference")
            comp = f"z={z:+.2f} r={rb:+.2f} {verdict}"
        print(f"{u:<28}{len(ts):>4}{statistics.median(ts):>11.1f}{q[2] - q[0]:>9.1f}  {sorted(statuses[u])}  "
              f"{sorted(sizes[u])[:3]}  {comp}")
    print("\nNon-timing differences (status/size) are stronger evidence than timing. Report effect size and n.")


if __name__ == "__main__":
    main()
