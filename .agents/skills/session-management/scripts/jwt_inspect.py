#!/usr/bin/env python3
"""Offline JWT inspector for SM-21..SM-30 and SM-35.

Usage:
  jwt_inspect.py TOKEN
  jwt_inspect.py -            # read token from stdin

Decodes header and payload (no signature verification), and flags risky
algorithms, key-location headers (jku/x5u/jwk/kid), missing or long-lived
time claims, privilege-bearing claims worth tampering with, and sensitive data.
Exits 1 if the input is not a JWT/JWS/JWE.
"""
import base64
import json
import re
import sys
from datetime import datetime, timezone

PRIV_CLAIMS = re.compile(r"^(role|roles|admin|is_?admin|isadmin|scope|scopes|scp|groups?|permissions?|perms|"
                         r"authorities|tenant|tenant_?id|org|org_?id|acl|level|privilege|user_?type|plan)$", re.I)
SENSITIVE = re.compile(r"(password|passwd|pwd|secret|api_?key|private|ssn|credit|card|cvv|hash|salt|"
                       r"phone|dob|birth|address)", re.I)


def b64url(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def ts(v):
    try:
        return datetime.fromtimestamp(int(v), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return f"unparseable ({v!r})"


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    tok = sys.stdin.read().strip() if sys.argv[1] == "-" else sys.argv[1].strip()
    tok = re.sub(r"^(bearer\s+)", "", tok, flags=re.I)
    parts = tok.split(".")
    if len(parts) not in (3, 5):
        print("not a JWT (expected 3 parts for JWS or 5 for JWE)")
        sys.exit(1)
    try:
        header = json.loads(b64url(parts[0]))
    except Exception as e:  # noqa: BLE001
        print(f"header is not base64url JSON: {e}")
        sys.exit(1)

    flags = []
    print("# JWT analysis\n")
    print("## Header\n```json\n" + json.dumps(header, indent=2) + "\n```")
    alg = str(header.get("alg", ""))

    if len(parts) == 5:
        print("\nJWE (encrypted) token: payload not readable without the key.")
        flags.append(("SM-21", f"JWE with alg={alg} enc={header.get('enc')}; check for 'dir'/'RSA1_5' weak modes"))
        payload = None
    else:
        try:
            payload = json.loads(b64url(parts[1]))
        except Exception:  # noqa: BLE001
            payload = None
            print("\npayload is not JSON (may be compressed or opaque)")
        if payload is not None:
            print("\n## Payload\n```json\n" + json.dumps(payload, indent=2) + "\n```")
        if not parts[2]:
            flags.append(("SM-22", "EMPTY signature - token is unsigned as issued"))

    if alg.lower() == "none":
        flags.append(("SM-22", "alg=none issued by server"))
    elif alg.upper().startswith("HS"):
        flags.append(("SM-24", f"{alg} (HMAC): try offline cracking - hashcat -m 16500 / jwt_tool -C"))
    elif alg.upper()[:2] in ("RS", "PS", "ES"):
        flags.append(("SM-23", f"{alg} (asymmetric): test RS/ES->HS256 key confusion with the public key"))
    for h in ("jku", "x5u"):
        if h in header:
            flags.append(("SM-27", f"{h}={header[h]} - test pointing it at an attacker-hosted JWKS / allowlist bypass"))
    if "jwk" in header:
        flags.append(("SM-27", "embedded jwk header - test self-signed key injection"))
    if "kid" in header:
        flags.append(("SM-28", f"kid={header['kid']!r} - test path traversal (../../dev/null) and SQLi"))
    if "x5c" in header:
        flags.append(("SM-27", "x5c header present - test self-signed certificate chain injection"))

    if payload is not None and isinstance(payload, dict):
        now = datetime.now(timezone.utc).timestamp()
        print("\n## Time claims")
        for c in ("iat", "nbf", "exp"):
            if c in payload:
                print(f"- {c}: {payload[c]} ({ts(payload[c])})")
        if "exp" not in payload:
            flags.append(("SM-25", "no exp claim - token never expires unless revoked server-side"))
        else:
            try:
                exp = float(payload["exp"])
                if exp < now:
                    flags.append(("SM-25", "token already expired - replay it to test exp enforcement"))
                start = float(payload.get("iat", payload.get("nbf", now)))
                life = exp - start
                print(f"- lifetime: {life / 60:.0f} min ({life / 86400:.2f} days)")
                if life > 3600:
                    flags.append(("SM-30", f"long access-token lifetime ({life / 3600:.1f} h); "
                                           "verify revocation on logout/password change"))
            except (TypeError, ValueError):
                flags.append(("SM-25", "non-numeric exp"))
        for c in ("iss", "aud"):
            if c not in payload:
                flags.append(("SM-21", f"no {c} claim - test cross-service/cross-tenant token reuse"))
        if "jti" not in payload:
            flags.append(("SM-30", "no jti - server-side per-token revocation unlikely"))
        priv = [k for k in payload if PRIV_CLAIMS.match(k)]
        if priv:
            flags.append(("SM-29", f"privilege-bearing claims: {priv} - tamper after any signature bypass"))
        sens = []

        def walk(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    p = f"{path}.{k}" if path else k
                    if SENSITIVE.search(k):
                        sens.append(p)
                    walk(v, p)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, f"{path}[{i}]")
        walk(payload)
        emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", json.dumps(payload))
        if sens:
            flags.append(("SM-26", f"sensitive-looking fields: {sens}"))
        if emails:
            flags.append(("SM-26", f"email addresses in payload: {sorted(set(emails))}"))

    print("\n## Flags")
    if not flags:
        print("- none")
    for cid, msg in flags:
        print(f"- **{cid}** {msg}")


if __name__ == "__main__":
    main()
