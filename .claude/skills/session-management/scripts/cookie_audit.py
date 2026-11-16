#!/usr/bin/env python3
"""Offline Set-Cookie auditor for SM-10/11/12/14/15/40 (and SM-06 lifetime).

Usage:
  cookie_audit.py RESPONSE_HEADERS_FILE [--session-names SESSIONID,sid] [--host app.example.com]

Input: raw response headers (curl -D, Burp "Copy response" or a HAR-exported header block).
Multiple responses in one file are fine. Cookies whose names look session-like are
flagged as session cookies automatically; add exact names with --session-names.
"""
import argparse
import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

SESSION_HINT = re.compile(
    r"(sess|sid|auth|token|jwt|login|remember|identity|connect\.sid|jsessionid|phpsessid|asp\.net_sessionid|"
    r"laravel_session|_session|csrftoken|xsrf)", re.I)


def parse_set_cookie(value):
    parts = [p.strip() for p in value.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), val.strip(), attrs


def lifetime(attrs):
    if "max-age" in attrs:
        try:
            return int(attrs["max-age"])
        except ValueError:
            return None
    if "expires" in attrs:
        try:
            exp = parsedate_to_datetime(attrs["expires"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return int((exp - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            return None
    return None  # session cookie (browser lifetime)


def audit(name, val, attrs, is_session, host):
    issues = []
    sev = "session" if is_session else "other"
    if "secure" not in attrs:
        issues.append(("SM-10", "missing Secure"))
    if "httponly" not in attrs:
        issues.append(("SM-11", "missing HttpOnly" + (" (expected if this is a double-submit CSRF cookie)"
                                                      if re.search(r"csrf|xsrf", name, re.I) else "")))
    ss = attrs.get("samesite", "").lower()
    if not ss:
        issues.append(("SM-12", "no SameSite (browser default; Chromium=Lax with 2-min POST window)"))
    elif ss == "none":
        issues.append(("SM-12", "SameSite=None (sent on cross-site requests)" +
                       ("" if "secure" in attrs else "; also invalid without Secure")))
    dom = attrs.get("domain", "")
    if dom:
        d = dom.lstrip(".").lower()
        note = f"Domain={dom} (sent to all *.{d})"
        if host and host.lower() != d:
            note += f"; broader than responding host {host}"
        issues.append(("SM-14", note))
    path = attrs.get("path", "")
    if path in ("", "/"):
        issues.append(("SM-15", f"Path={path or '(default)'} (whole host)"))
    if name.startswith("__Host-"):
        if "secure" not in attrs or dom or path != "/":
            issues.append(("SM-40", "__Host- prefix used but requirements not met (Secure, Path=/, no Domain)"))
    elif name.startswith("__Secure-"):
        if "secure" not in attrs:
            issues.append(("SM-40", "__Secure- prefix without Secure"))
    else:
        issues.append(("SM-40", "no __Host-/__Secure- prefix"))
    life = lifetime(attrs)
    if life is not None and life > 30 * 86400:
        issues.append(("SM-06", f"persistent lifetime ~{life // 86400} days"))
    if val and len(val) < 16:
        issues.append(("SM-02", f"short value ({len(val)} chars)"))
    return sev, life, issues


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--session-names", default="")
    ap.add_argument("--host", default="")
    a = ap.parse_args()
    explicit = {n.strip() for n in a.session_names.split(",") if n.strip()}

    with open(a.file, encoding="utf-8", errors="replace") as fh:
        lines = [l.rstrip("\r\n") for l in fh]
    cookies = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("set-cookie:")]
    if not cookies:
        sys.exit("no Set-Cookie headers found")

    seen = set()
    for raw in cookies:
        name, val, attrs = parse_set_cookie(raw)
        key = (name, tuple(sorted(attrs.items())))
        if key in seen:
            continue
        seen.add(key)
        is_session = name in explicit or (not explicit and bool(SESSION_HINT.search(name)))
        kind, life, issues = audit(name, val, attrs, is_session, a.host)
        lt = "browser-session" if life is None else f"{life}s"
        print(f"[{'SESSION' if is_session else 'cookie '}] {name}  lifetime={lt}  "
              f"attrs={','.join(k if not v else f'{k}={v}' for k, v in attrs.items()) or '-'}")
        for cid, msg in issues:
            print(f"    {cid}: {msg}")
        if not issues:
            print("    no attribute issues")
    print("\nOnly cookies that carry session authority matter for SM findings; verify by removing the cookie "
          "and re-requesting an authenticated page.")


if __name__ == "__main__":
    main()
