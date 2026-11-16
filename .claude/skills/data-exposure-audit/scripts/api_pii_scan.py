#!/usr/bin/env python3
"""Offline PII / excessive-data analyzer for saved API traffic (no network).

Input: HAR files (Burp/DevTools export) and/or JSON files or folders of saved
responses. For each response it walks the JSON and reports:
  - sensitive fields (password/hash/token/secret/api_key/mfa/reset...) -> DE-017
  - PII fields and values (email, phone, address, dob, ssn, card, ip...) -> DE-016
  - emails or IDs that are not yours (--own-email / --own-id)        -> DE-016 (other users' data)
  - field counts per endpoint (compare with what the UI shows)        -> DE-017
  - secrets by pattern inside any string value                         -> DE-003/DE-017
  - sensitive data in request URLs (query parameters)                  -> DE-018
Values are redacted in output.

Example:
  api_pii_scan.py history.har saved_json/ --own-email me@example.test --own-id 1042 \
     --out artifacts/example.com/api_pii.json
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit

SENSITIVE = re.compile(r"(?i)^(password|passwd|pwd|password_?hash|hash|salt|secret|client_?secret|api_?key|apikey|access_?token|"
                       r"refresh_?token|id_?token|token|session(_?id)?|otp|mfa_?secret|totp_?secret|reset_?token|"
                       r"verification_?code|private_?key|ssn|cvv|cvc|pin)$")
PII = re.compile(r"(?i)(^|_)(e?mail|phone|mobile|tel|address|street|city|zip|postcode|postal|dob|birth|birthday|"
                 r"ssn|national_?id|passport|tax_?id|iban|card|pan|ip|last_?login_?ip|lat|lng|latitude|longitude|"
                 r"location|gender|salary|first_?name|last_?name|full_?name)($|_)")
FLAGS = re.compile(r"(?i)^(is_?admin|admin|role|roles|permissions|is_?staff|is_?superuser|internal|debug|flags|feature_?flags|plan|tier)$")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET_VAL = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|\bsk_live_[0-9A-Za-z]{20,}|\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}|"
                        r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(id|i|d)\$|\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b")
SENS_PARAM = re.compile(r"(?i)^(token|access_token|id_token|refresh_token|session|sessionid|sid|password|pass|pwd|email|"
                        r"api_?key|key|secret|auth|code|reset|otp|ssn|phone)$")


def red(v) -> str:
    s = str(v)
    return s if len(s) <= 8 else f"{s[:3]}...{s[-3:]} ({len(s)})"


def walk(obj, path, visit):
    if isinstance(obj, dict):
        for k, v in obj.items():
            visit(f"{path}.{k}" if path else k, k, v)
            walk(v, f"{path}.{k}" if path else k, visit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            walk(v, f"{path}[]", visit)


def load_inputs(paths):
    """yield (method, url, json_body_or_None, text)"""
    for p in paths:
        files = []
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in names]
        else:
            files.append(p)
        for f in files:
            try:
                raw = open(f, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if f.lower().endswith(".har"):
                try:
                    har = json.loads(raw)
                except ValueError:
                    continue
                for e in har.get("log", {}).get("entries", []):
                    req, res = e.get("request", {}), e.get("response", {})
                    c = res.get("content", {})
                    text = c.get("text") or ""
                    if c.get("encoding") == "base64":
                        try:
                            text = base64.b64decode(text).decode("utf-8", errors="replace")
                        except Exception:
                            text = ""
                    body = None
                    if "json" in (c.get("mimeType") or "") or text.lstrip().startswith(("{", "[")):
                        try:
                            body = json.loads(text)
                        except ValueError:
                            body = None
                    yield req.get("method", "GET"), req.get("url", ""), body, text
            else:
                try:
                    yield "GET", f"file://{f}", json.loads(raw), raw
                except ValueError:
                    continue


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--own-email", action="append", default=[], help="your own email(s); others are flagged")
    ap.add_argument("--own-id", action="append", default=[], help="your own user/account ID(s)")
    ap.add_argument("--out")
    args = ap.parse_args()
    own_emails = {e.lower() for e in args.own_email}
    own_ids = {str(i) for i in args.own_id}

    endpoints = defaultdict(lambda: {"responses": 0, "fields": set(), "sensitive": set(), "pii": set(), "flags": set(),
                                     "other_emails": set(), "other_ids": set(), "secret_values": set()})
    url_issues = []
    for method, url, body, text in load_inputs(args.inputs):
        p = urlsplit(url)
        bad = [k for k, _ in parse_qsl(p.query) if SENS_PARAM.match(k)]
        if bad:
            url_issues.append(f"{method} {p.scheme}://{p.netloc}{p.path} params={bad}")
        if body is None:
            continue
        norm_path = re.sub(r"/[0-9a-f-]{6,}|/\d+", "/{id}", p.path)
        key = f"{method} {p.netloc}{norm_path}"
        ep = endpoints[key]
        ep["responses"] += 1

        def visit(path, k, v):
            ep["fields"].add(path)
            if isinstance(v, (dict, list)):
                return
            sv = "" if v is None else str(v)
            if SENSITIVE.match(str(k)) and sv:
                ep["sensitive"].add(f"{path}={red(sv)}")
            elif PII.search(str(k)) and sv:
                ep["pii"].add(path)
            if FLAGS.match(str(k)):
                ep["flags"].add(f"{path}={red(sv)}")
            for e in EMAIL.findall(sv):
                if own_emails and e.lower() not in own_emails:
                    ep["other_emails"].add(red(e))
            if re.match(r"(?i)^(id|user_?id|owner_?id|account_?id|author_?id|customer_?id)$", str(k)) and own_ids and sv and sv not in own_ids:
                ep["other_ids"].add(f"{path}={sv}")
            if SECRET_VAL.search(sv) and not re.match(r"(?i)^(id|uuid|etag|hash_?id|checksum|sha|md5|commit|version)$", str(k)):
                ep["secret_values"].add(f"{path}={red(sv)}")
        walk(body, "", visit)

    findings = []
    report = {}
    for key, ep in sorted(endpoints.items()):
        r = {k: (sorted(v)[:40] if isinstance(v, set) else v) for k, v in ep.items()}
        r["field_count"] = len(ep["fields"])
        report[key] = r
        if ep["sensitive"]:
            findings.append(f"DE-017: {key} returns sensitive fields {sorted(ep['sensitive'])[:4]}")
        if ep["secret_values"]:
            findings.append(f"DE-017/DE-003: {key} returns secret-looking values {sorted(ep['secret_values'])[:3]}")
        if ep["other_emails"]:
            findings.append(f"DE-016: {key} returns {len(ep['other_emails'])} emails that are not yours, e.g. {sorted(ep['other_emails'])[:2]}")
        if ep["other_ids"] and ep["pii"]:
            findings.append(f"DE-016: {key} returns PII fields {sorted(ep['pii'])[:4]} for objects not owned by you ({len(ep['other_ids'])} ids)")
        if ep["flags"]:
            findings.append(f"DE-017 info: {key} exposes internal/role fields {sorted(ep['flags'])[:3]}")
    for u in sorted(set(url_issues))[:50]:
        findings.append(f"DE-018: sensitive parameter in URL: {u}")
    for f in findings or ["none"]:
        print(f"- {f}")
    print("field counts per endpoint (compare with what the UI displays):")
    for key, r in report.items():
        print(f"  {r['field_count']:4} fields  {key}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump({"findings": findings, "endpoints": report}, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
