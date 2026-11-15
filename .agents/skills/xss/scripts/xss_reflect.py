#!/usr/bin/env python3
"""Scope-gated reflection & context analyser (class R: no script is executed, only inert canaries are sent).

Usage:
  xss_reflect.py --target example.com --url 'https://app.example.com/search?q=FUZZ'
  xss_reflect.py --target example.com --url 'https://app.example.com/page?a=1&b=2' --all-params
                 [--data 'x=FUZZ' | --json '{"x":"FUZZ"}'] [--header 'Referer: FUZZ'] [--method GET]
                 [--follow-url 'https://app.example.com/profile'] [--delay 0.5] [--out artifacts/xss/reflect.tsv]

For each injection point it sends (1) a plain alphanumeric canary to find every reflection and classify its
context (HTML text, quoted/unquoted attribute, URL attribute, event handler, JS string/template/block, comment,
RCDATA such as textarea/title, style, non-HTML response), then (2) the canary wrapped around the characters
< > " ' ` ( ) / \\ = ; : { } and reports which of them come back unencoded in each context.
--follow-url fetches a second page after submitting (stored/second-order reflections, e.g. a profile page).
It then prints the payload families from xss_payloads.py that fit the context and the surviving characters.
"""
import argparse
import importlib.util
import json
import os
import random
import re
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE_CHARS = "<>\"'`()/=;:{}\\"   # backslash last so it cannot escape another probe char
RANK = ["autofocus", "js-string", "js-template", "js-block", "js-break", "url", "basic", "events", "noparen",
        "nospace", "noquote", "svg", "mathml", "css", "waf", "polyglot"]
RCDATA = ("textarea", "title", "noscript", "xmp", "noembed", "iframe", "noframes", "plaintext")
URL_ATTRS = {"href", "src", "action", "formaction", "data", "xlink:href", "background", "poster", "srcset",
             "codebase", "cite", "longdesc", "ping", "lowsrc", "dynsrc", "content"}


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate(host):
    script = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


def js_quote_state(code):
    """Return the open quote char (' " `) at the end of code, or '' (ignores regex literals)."""
    q, i, n = "", 0, len(code)
    while i < n:
        c = code[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = ""
        else:
            if c in "'\"`":
                q = c
            elif code.startswith("//", i):
                j = code.find("\n", i)
                i = n if j == -1 else j
                continue
            elif code.startswith("/*", i):
                j = code.find("*/", i + 2)
                i = n if j == -1 else j + 2
                continue
        i += 1
    return q


def clean(seg, ctx):
    """Drop backslash escape sequences in JS contexts so escaped quotes are not counted as raw."""
    return re.sub(r"\\.", "", seg) if ctx.startswith("js-") or ctx == "json" else seg


def classify(body, idx, ctype):
    """Classify the context of the reflection at body[idx]."""
    if "html" not in ctype and "xml" not in ctype:
        return "json" if "json" in ctype else f"non-html({ctype or 'none'})", ""
    low = body.lower()
    before = low[:idx]
    # comment
    c_open = before.rfind("<!--")
    if c_open != -1 and before.find("-->", c_open) == -1:
        return "comment", ""
    # script / style / rcdata blocks
    for tag in ("script", "style") + RCDATA:
        o = before.rfind("<" + tag)
        if o != -1 and before.find("</" + tag, o) == -1:
            gt = before.find(">", o)
            if gt != -1:   # we are after the opening tag's '>'
                if tag == "script":
                    code = body[gt + 1: idx]
                    q = js_quote_state(code)
                    return {"'": "js-sq", '"': "js-dq", "`": "js-template"}.get(q, "js-block"), ""
                if tag == "style":
                    return "style", ""
                return "rcdata", tag
    # inside a tag?
    lt, gt = before.rfind("<"), before.rfind(">")
    if lt > gt:
        tagtext = body[lt:idx]
        m = re.search(r"([\w:-]+)\s*=\s*(\"[^\"]*|'[^']*|[^\s\"'>]*)$", tagtext)
        if m:
            name, val = m.group(1).lower(), m.group(2)
            q = val[:1] if val[:1] in "\"'" else ""
            if name.startswith("on"):
                return "event-attr", name
            if name in URL_ATTRS and val.lstrip("\"'") == "":
                return "url-attr", name
            if name == "style":
                return "style-attr", name
            if name == "srcdoc":
                return "srcdoc-attr", name
            return {"\"": "attr-dq", "'": "attr-sq"}.get(q, "attr-unquoted"), name
        tagname = re.match(r"<\s*([\w:-]*)", tagtext)
        return "tag-name-or-attr-name", tagname.group(1) if tagname else ""
    return "html", ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--all-params", action="store_true", help="test every query parameter of --url in turn")
    ap.add_argument("--data")
    ap.add_argument("--json")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--method")
    ap.add_argument("--follow-url", help="page to fetch after each submission (stored reflections)")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--out", default="artifacts/xss/reflect.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    host = (urlsplit(a.url).hostname or "").lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"URL host {host} outside target {a.target}")
    if a.follow_url:
        fh = (urlsplit(a.follow_url).hostname or "").lower()
        if fh != t and not fh.endswith("." + t):
            sys.exit(f"--follow-url host {fh} outside target {a.target}")
    points = []
    if a.all_params:
        parts = urlsplit(a.url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        if not qs:
            sys.exit("--all-params needs a URL with query parameters")
        for i, (k, _) in enumerate(qs):
            q2 = [(kk, "FUZZ" if j == i else vv) for j, (kk, vv) in enumerate(qs)]
            points.append((k, urlunsplit(parts._replace(query=urlencode(q2, safe="FUZZ")))))
    else:
        where = [x for x in ("url", "data", "json") if "FUZZ" in (getattr(a, x) or "")] + \
                [h for h in a.header if "FUZZ" in h]
        if len(where) != 1:
            sys.exit("exactly one of --url / --data / --json / --header must contain FUZZ (or use --all-params)")
        points.append((where[0], a.url))
    gate(host)

    gen = load("xss_payloads")
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    method = (a.method or ("POST" if (a.data or a.json) else "GET")).upper()

    def send(url, value):
        body = None
        hdrs = {"User-Agent": "bbtest-xss/1.0"}
        if a.data:
            body = a.data.replace("FUZZ", quote(value, safe="")).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif a.json:
            body = a.json.replace("FUZZ", json.dumps(value)[1:-1]).encode()
            hdrs["Content-Type"] = "application/json"
        for h in a.header:
            k, _, v = h.partition(":")
            hdrs[k.strip()] = v.strip().replace("FUZZ", value)
        req = urllib.request.Request(url.replace("FUZZ", quote(value, safe="")), data=body, headers=hdrs,
                                     method=method)
        out = []
        for r_ in [req] + ([urllib.request.Request(a.follow_url, headers={k: v for k, v in hdrs.items()
                                                                          if k.lower() != "content-type"})]
                           if a.follow_url else []):
            try:
                with opener.open(r_, timeout=20) as r:
                    out.append((r.status, r.headers.get("Content-Type", ""), r.read(3_000_000).decode("utf-8", "replace"),
                                dict(r.headers)))
            except urllib.error.HTTPError as e:
                out.append((e.code, e.headers.get("Content-Type", ""), e.read(3_000_000).decode("utf-8", "replace"),
                            dict(e.headers)))
            except Exception as e:  # noqa: BLE001
                out.append((0, "", str(e), {}))
            time.sleep(a.delay)
        return out

    rows, summary = [], []
    for pname, url in points:
        tok = "bbx" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
        res = send(url, tok)
        if res[0][0] == 0:
            sys.exit(f"target unreachable: {res[0][2][:120]}")
        found = []
        for page, (code, ctype, body, hdrs) in zip(["response", "follow"], res):
            for m in re.finditer(tok, body):
                c, detail = classify(body, m.start(), ctype.lower())
                found.append((page, m.start(), c, detail, code, ctype, hdrs))
        if not found:
            print(f"[-] {pname}: no reflection of canary")
            rows.append((pname, "-", "-", "-", "", "", "", "no reflection"))
            continue
        # character survival: one request with every char between canaries, then per-char if it fails
        e1, e2 = tok + "q", "q" + tok[::-1]
        res2 = send(url, e1 + PROBE_CHARS + e2)
        survive = {}
        for page, (code, ctype, body, _) in zip(["response", "follow"], res2):
            for m in re.finditer(re.escape(e1) + r"(.*?)" + re.escape(e2), body, re.S):
                c, _ = classify(body, m.start(), ctype.lower())
                seg = clean(m.group(1), c)
                survive.setdefault((page, c), set()).update(ch for ch in PROBE_CHARS if ch in seg)
        if not survive:
            for ch in PROBE_CHARS:
                for page, (code, ctype, body, _) in zip(["response", "follow"], send(url, e1 + ch + e2)):
                    for m in re.finditer(re.escape(e1) + r"(.*?)" + re.escape(e2), body, re.S):
                        c, _ = classify(body, m.start(), ctype.lower())
                        survive.setdefault((page, c), set())
                        if ch in clean(m.group(1), c):
                            survive[(page, c)].add(ch)
        for page, pos, c, detail, code, ctype, hdrs in found:
            s = survive.get((page, c))
            chars = "".join(ch for ch in PROBE_CHARS if s and ch in s) if s is not None else "?"
            allowed = set(chars) | {" "} if chars != "?" else None
            fams = gen.ALL_FAMILIES
            gctx = {"tag-name-or-attr-name": "attr-unquoted", "style-attr": "attr-dq", "srcdoc-attr": "attr-dq"}.get(c, c)
            sugg = []
            if gctx in gen.CONTEXTS:
                cand = [p for p in gen.build(gctx, families=fams)
                        if p["family"] in RANK and gen.fits(p["payload"], allowed)]
                cand.sort(key=lambda p: (p["interact"], RANK.index(p["family"])))
                sugg = [p["payload"] for p in cand][:3]
            nosniff = any(k.lower() == "x-content-type-options" for k in hdrs)
            note = ""
            if c.startswith("non-html") or c == "json":
                note = "non-HTML content type" + ("" if nosniff else " WITHOUT nosniff (check sniffing/old browsers)")
            print(f"[+] {pname:<14} {page:<8} {c:<20} {detail:<10} raw-chars: {chars:<16} {code} {ctype[:30]}")
            for p in sugg:
                print(f"      try: {p}")
            if not sugg and gctx in gen.CONTEXTS:
                print("      no payload fits the surviving characters (likely encoded) - try encoding/WAF families manually")
            rows.append((pname, page, c, detail, chars, code, ctype, note or (sugg[0] if sugg else "")))
            summary.append(dict(param=pname, page=page, context=c, detail=detail, raw_chars=chars, status=code,
                                content_type=ctype, suggestions=sugg, note=note))

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("param\tpage\tcontext\tdetail\traw_chars\tstatus\tcontent_type\tnote_or_first_suggestion\n")
        for r in rows:
            fh.write("\t".join(str(x).replace("\t", " ").replace("\n", " ") for x in r) + "\n")
    with open(os.path.splitext(a.out)[0] + ".json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"[+] {len(summary)} reflections -> {a.out}")
    print("    Verify every candidate manually in a browser (alert(document.domain)); reflection != execution.")


if __name__ == "__main__":
    main()
