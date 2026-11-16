#!/usr/bin/env python3
"""Replay one own-account state-changing request with CSRF defense variants.

Each variant changes one thing (token value, method, content type, Origin,
Referer, X-Requested-With) and the response is compared with the baseline.
"accepted" means the variant got the same status class as the baseline and no
CSRF error words. It is a lead: confirm by re-reading the state and by a PoC
page in your own victim browser profile.

Safety:
  - The scope gate (scripts/scope_check.sh) runs on the request's Host first.
  - Use a harmless own-account action (display name, bio). Max 20 requests,
    1 request per second by default.

Example:
  csrf_probe.py --target example.com --workspace ~/Documents/bugbounty \
     --request req.txt --other-token TOKEN_FROM_ACCOUNT_A \
     --out artifacts/example.com/csrf_probe.json

req.txt is a raw HTTP request saved from Burp ("Copy to file").
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import secrets
import ssl
import string
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
MAX_REQUESTS = 20
TOKEN_RE = re.compile(r"(csrf|xsrf|authenticity|_token$|^token$|anti.?forgery|requestverification|nonce)", re.I)
TOKEN_HEADERS = ("x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token", "x-csrf", "requestverificationtoken")
ERROR_WORDS = re.compile(r"csrf|xsrf|forgery|invalid token|token mismatch|token missing|expired token|origin|referer", re.I)


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


class Req:
    def __init__(self, method: str, path: str, headers: list[tuple[str, str]], body: str):
        self.method, self.path, self.headers, self.body = method, path, headers, body

    def copy(self) -> "Req":
        return Req(self.method, self.path, list(self.headers), self.body)

    def get(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def set(self, name: str, value: str | None) -> None:
        self.headers = [(k, v) for k, v in self.headers if k.lower() != name.lower()]
        if value is not None:
            self.headers.append((name, value))

    @property
    def ctype(self) -> str:
        return (self.get("Content-Type") or "").lower()


def load_request(path: str) -> Req:
    raw = open(path, "rb").read().decode("utf-8", errors="replace")
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, _, body = raw.partition(sep)
    lines = [l.rstrip("\r") for l in head.split("\n") if l.strip()]
    method, target, *_ = lines[0].split(" ")
    headers = []
    for l in lines[1:]:
        k, _, v = l.partition(":")
        if k.strip().lower() in ("content-length", "connection", "transfer-encoding", "accept-encoding"):
            continue
        headers.append((k.strip(), v.strip()))
    return Req(method.upper(), target, headers, body)


def find_token(req: Req, forced: str | None) -> tuple[str, str, str] | None:
    """Return (location, name, value). location: body-form, body-json, query, header."""
    names = [forced] if forced else None
    for k, v in req.headers:
        if (names and k.lower() == forced.lower()) or (not names and k.lower() in TOKEN_HEADERS):
            return ("header", k, v)
    if "json" in req.ctype:
        try:
            data = json.loads(req.body)
            for k, v in data.items():
                if (names and k == forced) or (not names and TOKEN_RE.search(k)):
                    return ("body-json", k, str(v))
        except (ValueError, AttributeError):
            pass
    elif "x-www-form-urlencoded" in req.ctype:
        for k, v in parse_qsl(req.body, keep_blank_values=True):
            if (names and k == forced) or (not names and TOKEN_RE.search(k)):
                return ("body-form", k, v)
    q = urlsplit(req.path).query
    for k, v in parse_qsl(q, keep_blank_values=True):
        if (names and k == forced) or (not names and TOKEN_RE.search(k)):
            return ("query", k, v)
    return None


def set_token(req: Req, tok: tuple[str, str, str], value, remove: bool = False) -> Req:
    r = req.copy()
    loc, name, _ = tok
    if loc == "header":
        r.set(name, None if remove else str(value))
    elif loc == "body-json":
        data = json.loads(r.body)
        if remove:
            data.pop(name, None)
        else:
            data[name] = value
        r.body = json.dumps(data)
    elif loc in ("body-form", "query"):
        src = r.body if loc == "body-form" else urlsplit(r.path).query
        pairs = [(k, v) for k, v in parse_qsl(src, keep_blank_values=True) if k != name]
        if not remove:
            if isinstance(value, list):
                pairs.append((name + "[]", ""))
            else:
                pairs.append((name, str(value)))
        enc = urlencode(pairs)
        if loc == "body-form":
            r.body = enc
        else:
            p = urlsplit(r.path)
            r.path = p.path + ("?" + enc if enc else "")
    return r


def same_shape_random(v: str) -> str:
    if re.fullmatch(r"[0-9a-f]+", v):
        alphabet = "0123456789abcdef"
    elif re.fullmatch(r"[0-9A-Za-z]+", v):
        alphabet = string.ascii_letters + string.digits
    else:
        alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in v) or "x"


def body_params(req: Req) -> list[tuple[str, str]]:
    if "json" in req.ctype:
        try:
            return [(k, v if isinstance(v, str) else json.dumps(v)) for k, v in json.loads(req.body).items()]
        except ValueError:
            return []
    return parse_qsl(req.body, keep_blank_values=True)


def build_variants(base: Req, tok, other_token: str | None) -> list[tuple[str, str, Req]]:
    v: list[tuple[str, str, Req]] = []
    if tok:
        val = tok[2]
        v += [
            ("token_removed", "XSRF-003 / B-001", set_token(base, tok, None, remove=True)),
            ("token_empty", "XSRF-B-002", set_token(base, tok, "")),
            ("token_undefined", "XSRF-B-003", set_token(base, tok, "undefined")),
            ("token_random_same_length", "XSRF-B-005", set_token(base, tok, same_shape_random(val))),
            ("token_last_char", "XSRF-B-006", set_token(base, tok, val[:-1] + ("a" if val[-1:] != "a" else "b"))),
        ]
        if tok[0] in ("body-form", "query"):
            v.append(("token_array", "XSRF-B-004", set_token(base, tok, [])))
        if other_token:
            v.append(("token_other_session", "XSRF-004 / B-007", set_token(base, tok, other_token)))
    stripped = set_token(base, tok, None, remove=True) if tok else base.copy()
    if base.method != "GET":
        g = stripped.copy()
        params = body_params(stripped)
        p = urlsplit(g.path)
        q = parse_qsl(p.query, keep_blank_values=True) + params
        g.method, g.body = "GET", ""
        g.path = p.path + ("?" + urlencode(q) if q else "")
        g.set("Content-Type", None)
        v.append(("post_to_get", "XSRF-B-016", g))
    if base.method in ("PUT", "PATCH", "DELETE"):
        m = stripped.copy()
        m.method = "POST"
        sep = "&" if "?" in m.path else "?"
        m.path += sep + "_method=" + base.method
        m.set("X-HTTP-Method-Override", base.method)
        v.append(("method_override", "XSRF-017 / B-017", m))
    if "json" in base.ctype:
        t = stripped.copy()
        t.set("Content-Type", "text/plain")
        v.append(("ct_text_plain", "XSRF-007 / B-018", t))
        f = stripped.copy()
        f.set("Content-Type", "application/x-www-form-urlencoded")
        f.body = urlencode(body_params(stripped))
        v.append(("ct_form", "XSRF-B-019", f))
    host = base.get("Host") or ""
    r = base.copy(); r.set("Referer", None)
    v.append(("no_referer", "XSRF-B-020", r))
    r = base.copy(); r.set("Referer", f"https://{host}.evil.example/{host}")
    v.append(("referer_evil", "XSRF-B-021", r))
    r = base.copy(); r.set("Origin", "null")
    v.append(("origin_null", "XSRF-B-024", r))
    r = base.copy(); r.set("Origin", "https://evil.example")
    v.append(("origin_evil", "XSRF-B-026", r))
    if base.get("X-Requested-With"):
        r = base.copy(); r.set("X-Requested-With", None)
        v.append(("no_x_requested_with", "XSRF-010", r))
    return v


def send(req: Req, host: str, port: int, use_tls: bool, insecure: bool, timeout: float) -> tuple[int, int, str]:
    if use_tls:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    body = req.body.encode() if req.body else None
    conn.putrequest(req.method, req.path, skip_host=True, skip_accept_encoding=True)
    for k, val in req.headers:
        conn.putheader(k, val)
    if body is not None or req.method in ("POST", "PUT", "PATCH"):
        conn.putheader("Content-Length", str(len(body or b"")))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, len(data), data[:300].decode(errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--request", required=True, help="raw HTTP request file (own account, harmless action)")
    ap.add_argument("--token-param", help="token parameter or header name if auto-detect fails")
    ap.add_argument("--other-token", help="valid token from your other own account (XSRF-004)")
    ap.add_argument("--http", action="store_true", help="plain HTTP")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (own lab only)")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    base = load_request(args.request)
    hosthdr = base.get("Host")
    if not hosthdr:
        sys.exit("request has no Host header")
    host, _, port_s = hosthdr.partition(":")
    host = host.lower()
    target = args.target.lower()
    if not (host == target or host.endswith("." + target)):
        sys.exit(f"request Host {host} is not {target} or a subdomain of it")
    run_scope_check(host, args.workspace, args.target.lower())
    port = int(port_s) if port_s else (80 if args.http else 443)

    tok = find_token(base, args.token_param)
    variants = [("baseline", "-", base)] + build_variants(base, tok, args.other_token)
    variants = variants[:MAX_REQUESTS]

    results = []
    base_status = None
    for i, (name, ref, req) in enumerate(variants):
        if i:
            time.sleep(args.delay)
        try:
            status, length, preview = send(req, host, port, not args.http, args.insecure, args.timeout)
        except Exception as e:  # network errors are recorded, not fatal
            results.append({"variant": name, "ref": ref, "error": str(e)})
            continue
        if name == "baseline":
            base_status = status
        accepted = (base_status is not None and status // 100 == base_status // 100
                    and not ERROR_WORDS.search(preview) and name != "baseline")
        results.append({"variant": name, "ref": ref, "method": req.method, "status": status,
                        "length": length, "accepted_lead": accepted, "preview": preview[:160]})

    report = {
        "target": target, "host": host,
        "token": {"location": tok[0], "name": tok[1]} if tok else None,
        "baseline_status": base_status,
        "results": results,
        "leads": [r["variant"] for r in results if r.get("accepted_lead")],
        "note": "Leads must be confirmed: re-read the state, then open a PoC in your own victim profile.",
    }
    text = json.dumps(report, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
