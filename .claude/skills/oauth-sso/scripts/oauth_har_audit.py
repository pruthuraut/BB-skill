#!/usr/bin/env python3
"""Offline audit of a browser HAR containing OAuth 2.0 / OIDC / SAML flows.

Usage:
  oauth_har_audit.py FLOW.har [FLOW2.har ...]

Flags (with check IDs): missing/static/short state (OA-01/02), missing nonce on
implicit/hybrid (OA-17), PKCE absent or 'plain' (OA-09/29), implicit/hybrid
response types (OA-06/36), tokens or codes in query strings (OA-05/06), codes
leaking cross-origin in Referer (OA-05), client_secret sent from the browser
(OA-10), authorization code redeemed more than once (OA-08), redirect_uri
mismatch between authorize and token requests (OA-30), scope drift (OA-07),
SAML messages present (OA-E group), ROPC usage (OA-50).
"""
import json
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlsplit

TOKEN_PARAMS = ("access_token", "id_token", "refresh_token")


def hdr(headers, name):
    name = name.lower()
    for h in headers or []:
        if h.get("name", "").lower() == name:
            return h.get("value", "")
    return ""


def params_of(url):
    u = urlsplit(url)
    return dict(parse_qsl(u.query, keep_blank_values=True)), dict(parse_qsl(u.fragment, keep_blank_values=True))


def body_params(req):
    pd = req.get("postData") or {}
    if pd.get("params"):
        return {p.get("name", ""): p.get("value", "") for p in pd["params"]}
    text = pd.get("text") or ""
    mime = (pd.get("mimeType") or "").lower()
    if "json" in mime or text.strip().startswith("{"):
        try:
            obj = json.loads(text)
            return {k: str(v) for k, v in obj.items()} if isinstance(obj, dict) else {}
        except ValueError:
            return {}
    return dict(parse_qsl(text, keep_blank_values=True))


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    entries = []
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            har = json.load(fh)
        entries += har.get("log", {}).get("entries", [])
    print(f"# OAuth/SSO HAR audit ({len(entries)} entries)\n")

    findings = []
    flag = lambda cid, msg: findings.append((cid, msg))
    authz, tokreq = [], []
    states = Counter()
    codes_issued, codes_redeemed = set(), Counter()
    saml_seen = False

    for e in entries:
        req, res = e.get("request", {}), e.get("response", {})
        url = req.get("url", "")
        q, frag = params_of(url)
        bp = body_params(req) if req.get("method") == "POST" else {}
        allp = {**q, **bp}
        loc = hdr(res.get("headers"), "location")
        lq, lf = params_of(loc) if loc else ({}, {})
        host = urlsplit(url).hostname or ""

        if "SAMLResponse" in allp or "SAMLRequest" in allp:
            saml_seen = True

        # Authorization requests
        if "response_type" in q and "client_id" in q:
            authz.append((url, q))
            rt = q.get("response_type", "")
            st = q.get("state")
            if not st:
                flag("OA-01", f"authorization request without state: {url[:160]}")
            else:
                states[st] += 1
                if len(st) < 16:
                    flag("OA-02", f"short state value ({len(st)} chars): {st}")
            if ("token" in rt.split() or "id_token" in rt.split()) and not q.get("nonce"):
                flag("OA-17", f"implicit/hybrid response_type={rt} without nonce")
            if "token" in rt.split() or "id_token" in rt.split():
                flag("OA-06", f"implicit/hybrid response_type={rt} on {host}")
            if "code" in rt.split():
                m = q.get("code_challenge_method")
                if not q.get("code_challenge"):
                    flag("OA-09", f"code flow without PKCE code_challenge (client_id={q.get('client_id')})")
                elif (m or "plain") == "plain":
                    flag("OA-09", "PKCE code_challenge_method=plain")
            if q.get("response_mode") in ("query",) and rt != "code":
                flag("OA-36", f"response_mode=query with response_type={rt} (tokens in query string)")
            if q.get("prompt") == "none":
                flag("OA-38", "prompt=none silent authentication observed")
            if q.get("request_uri") or q.get("request"):
                flag("OA-49", "request object / request_uri used in authorization request")

        # Codes/tokens delivered in redirects
        for src, pq, pf in (("location", lq, lf), ("url", q, frag)):
            if "code" in pq and ("state" in pq or src == "location"):
                codes_issued.add(pq["code"])
            for t in TOKEN_PARAMS:
                if t in pq:
                    flag("OA-05/06", f"{t} in QUERY string ({src}): {(loc if src == 'location' else url)[:140]}")
                if t in pf and src == "location":
                    flag("OA-06", f"{t} delivered in URL fragment to {urlsplit(loc).hostname}")

        # Referer leakage of codes/tokens to another origin
        ref = hdr(req.get("headers"), "referer")
        if ref:
            rq, rf = params_of(ref)
            rhost = urlsplit(ref).hostname or ""
            leaked = [k for k in ("code",) + TOKEN_PARAMS if k in rq]
            if leaked and rhost != host:
                flag("OA-05", f"Referer carrying {leaked} from {rhost} sent to third party {host}")

        # Token endpoint requests (seen from the browser!)
        gt = allp.get("grant_type")
        if gt:
            tokreq.append((url, allp))
            auth = hdr(req.get("headers"), "authorization")
            if allp.get("client_secret") or auth.lower().startswith("basic "):
                flag("OA-10", f"client authentication (client_secret / Basic) sent from the browser to {url[:120]}")
            if gt == "authorization_code":
                c = allp.get("code", "")
                codes_redeemed[c] += 1
                if not allp.get("code_verifier"):
                    flag("OA-29", "authorization_code exchange without code_verifier (check PKCE downgrade)")
            if gt == "password":
                flag("OA-50", f"ROPC grant_type=password used at {url[:120]}")
            if gt == "refresh_token" and allp.get("scope"):
                flag("OA-07", f"refresh request specifies scope={allp.get('scope')} (test widening)")
            if "token-exchange" in gt:
                flag("OA-11", "token exchange grant used")

        # JWT-looking values in response bodies (for jwt_inspect)
        txt = ((res.get("content") or {}).get("text") or "")[:200000]
        for m in re.findall(r'"(id_token|access_token)"\s*:\s*"(eyJ[\w-]+\.[\w-]+\.[\w-]*)"', txt):
            flag("OA-16", f"{m[0]} JWT in response from {host} (inspect with jwt_inspect.py): {m[1][:40]}...")

    for st, c in states.items():
        if c > 1:
            flag("OA-02", f"state value reused across {c} authorization requests (static?): {st[:40]}")
    for c, n in codes_redeemed.items():
        if c and n > 1:
            flag("OA-08", f"authorization code redeemed {n} times in capture: {c[:20]}...")

    # redirect_uri consistency and scope drift
    ruris = {q.get("redirect_uri") for _, q in authz if q.get("redirect_uri")}
    for url, p in tokreq:
        if p.get("grant_type") == "authorization_code":
            r = p.get("redirect_uri")
            if not r:
                flag("OA-30", "token request without redirect_uri (test mismatch acceptance)")
            elif ruris and r not in ruris:
                flag("OA-30", f"token request redirect_uri {r} differs from authorize request(s) {sorted(ruris)}")
    scopes = defaultdict(set)
    for _, q in authz:
        scopes[q.get("client_id")].add(q.get("scope", ""))
    for cid, sc in scopes.items():
        if len(sc) > 1:
            flag("OA-07", f"client {cid} requested differing scopes {sorted(sc)}")
    if saml_seen:
        flag("OA-E", "SAMLRequest/SAMLResponse observed - run saml_inspect.py and the SAML checks")

    print("## Flows")
    for url, q in authz:
        print(f"- authorize {urlsplit(url).hostname}: client_id={q.get('client_id')} response_type={q.get('response_type')} "
              f"scope={q.get('scope')} redirect_uri={q.get('redirect_uri')} state={'yes' if q.get('state') else 'NO'} "
              f"nonce={'yes' if q.get('nonce') else 'no'} pkce={q.get('code_challenge_method') or ('plain?' if q.get('code_challenge') else 'no')}")
    for url, p in tokreq:
        print(f"- token {urlsplit(url).hostname}: grant_type={p.get('grant_type')} redirect_uri={p.get('redirect_uri')} "
              f"verifier={'yes' if p.get('code_verifier') else 'no'}")
    if not authz and not tokreq:
        print("- no OAuth authorize/token requests recognised")
    print("\n## Flags")
    seen = set()
    for cid, msg in findings:
        if (cid, msg) in seen:
            continue
        seen.add((cid, msg))
        print(f"- **{cid}** {msg}")
    if not findings:
        print("- none")


if __name__ == "__main__":
    main()
