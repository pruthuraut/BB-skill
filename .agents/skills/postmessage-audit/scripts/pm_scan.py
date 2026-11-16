#!/usr/bin/env python3
"""Offline postMessage scanner for saved JavaScript and HTML (no network).

Finds:
  - message listeners (addEventListener("message"), onmessage =, $(window).on("message"))
  - whether a handler body checks event.origin, how (exact vs weak), and event.source
  - sinks reached in the handler body (innerHTML, eval, location, jQuery html, ...)
  - postMessage(...) calls with "*" or a dynamic targetOrigin
Handler bodies are extracted by brace matching from the listener, so results on
minified bundles are leads; open the reported location to confirm.

Example:
  pm_scan.py saved_js/ --out artifacts/example.com/postmessage_scan.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

EXTS = (".js", ".mjs", ".html", ".htm", ".jsx", ".ts", ".tsx", ".vue")
LISTENER_RE = re.compile(
    r"""(addEventListener\s*\(\s*['"`]message['"`]|\bonmessage\s*=|\.on\(\s*['"`]message['"`]|attachEvent\(\s*['"`]onmessage['"`])""")
POST_RE = re.compile(r"""\.postMessage\s*\(""")
SINKS = [
    ("innerHTML", r"\.innerHTML\s*="), ("outerHTML", r"\.outerHTML\s*="),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("), ("document.write", r"document\.write(ln)?\s*\("),
    ("eval", r"(?<![\w.])eval\s*\("), ("Function", r"new\s+Function\s*\(|(?<![\w.])Function\s*\("),
    ("setTimeout-string", r"set(Timeout|Interval)\s*\(\s*[^,()]*data"),
    ("location", r"(window\.|document\.|top\.|self\.)?location(\.href)?\s*=|location\.(assign|replace)\s*\("),
    ("window.open", r"window\.open\s*\("), ("srcdoc", r"\.srcdoc\s*="),
    ("src/href/action", r"\.(src|href|action)\s*="), ("setAttribute", r"setAttribute\s*\(\s*['\"](src|href|action|on\w+|srcdoc)"),
    ("jquery-html", r"\.(html|append|prepend|after|before|replaceWith)\s*\("), ("jquery-$", r"\$\(\s*[\w.]*data"),
    ("createContextualFragment", r"createContextualFragment"), ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML"),
    ("localStorage", r"localStorage\.setItem"), ("fetch/xhr", r"fetch\s*\(|\.open\s*\(\s*['\"](GET|POST)"),
    ("JSON.parse", r"JSON\.parse\s*\("),
]
SINK_RES = [(n, re.compile(p)) for n, p in SINKS]
ORIGIN_RE = re.compile(r"\.origin\b")
EXACT_RE = re.compile(r"\.origin\s*(===|!==|==|!=)\s*['\"`]https?://|['\"`]https?://[^'\"`]+['\"`]\s*(===|!==|==|!=)\s*\w+\.origin|"
                      r"(includes|has|indexOf)\s*\(\s*\w+\.origin\s*\)")
WEAK = [
    ("indexOf-substring", re.compile(r"\.origin\s*\.\s*indexOf\s*\(")),
    ("includes-substring", re.compile(r"\.origin\s*\.\s*includes\s*\(")),
    ("search/match", re.compile(r"\.origin\s*\.\s*(search|match)\s*\(")),
    ("startsWith", re.compile(r"\.origin\s*\.\s*startsWith\s*\(")),
    ("endsWith", re.compile(r"\.origin\s*\.\s*endsWith\s*\(")),
    ("regex-test", re.compile(r"/[^/\n]{3,}/[gimsuy]*\s*\.\s*test\s*\(\s*\w+\.origin")),
    ("null-allowed", re.compile(r"['\"]null['\"]")),
    ("data.origin-used", re.compile(r"\.data\s*\.\s*origin")),
]
SOURCE_RE = re.compile(r"\.source\s*(===|!==|==|!=)|(===|!==|==|!=)\s*\w+\.source\b")


def handler_body(text: str, start: int, limit: int = 6000) -> str:
    """Return text of the first {...} block after start (brace matched, string-unaware)."""
    i = text.find("{", start, start + 400)
    if i < 0:
        # function reference: addEventListener("message", handlerName)
        m = re.match(r"[^,]*,\s*([\w$.]+)", text[start:start + 200])
        if m:
            name = m.group(1).split(".")[-1]
            d = re.search(r"(function\s+%s\s*\(|%s\s*[:=]\s*(async\s*)?(function\b|\([^)]*\)\s*=>|\w+\s*=>))" % (re.escape(name), re.escape(name)), text)
            if d:
                return handler_body(text, d.start(), limit)
        return text[start:start + 300]
    depth = 0
    for j in range(i, min(len(text), i + limit)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return text[i:i + limit]


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def target_origin_arg(text: str, pos: int) -> str:
    """Extract the second argument of postMessage( ... ) roughly."""
    depth, args, cur = 0, [], []
    j = text.find("(", pos) + 1
    end = min(len(text), j + 2000)
    while j < end:
        c = text[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append("".join(cur).strip())
                break
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        j += 1
    return args[1] if len(args) > 1 else ""


def scan_file(path: str) -> list[dict]:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out = []
    for m in LISTENER_RE.finditer(text):
        body = handler_body(text, m.end())
        has_origin = bool(ORIGIN_RE.search(body))
        weak = [n for n, r in WEAK if r.search(body)]
        exact = bool(EXACT_RE.search(body))
        sinks = sorted({n for n, r in SINK_RES if r.search(body)})
        issues = []
        if not has_origin:
            issues.append("no-origin-check (PMX-001)")
        elif weak and not (exact and weak == ["null-allowed"]):
            issues.append("weak-origin-check: " + ", ".join(weak) + " (PMX-002)")
        elif not exact:
            issues.append("origin referenced but no exact comparison found (PMX-002, review)")
        if not SOURCE_RE.search(body):
            issues.append("no-source-check (PMX-007)")
        dangerous = [s for s in sinks if s not in ("JSON.parse", "fetch/xhr", "localStorage")]
        if dangerous:
            issues.append("sinks: " + ", ".join(dangerous) + " (PMX-006)")
        if "JSON.parse" in sinks:
            issues.append("JSON.parse of message data: check for deep merge (PMX-V-003)")
        sev = "high" if (dangerous and (not has_origin or weak)) else ("medium" if (not has_origin or weak) else "info")
        out.append({"file": path, "line": line_of(text, m.start()), "kind": "listener", "severity": sev,
                    "issues": issues, "snippet": body[:300].replace("\n", " ")})
    for m in POST_RE.finditer(text):
        tgt = target_origin_arg(text, m.start())
        issues = []
        if re.fullmatch(r"""['"`]\*['"`]""", tgt):
            issues.append("wildcard-target (PMX-004)")
        elif not tgt:
            issues.append("no targetOrigin argument found (review)")
        elif not re.match(r"""['"`]https?://""", tgt):
            issues.append(f"dynamic-target '{tgt[:60]}' (PMX-004, check where it comes from)")
        if not issues:
            continue
        ctx = text[max(0, m.start() - 120): m.start() + 200]
        sensitive = bool(re.search(r"token|auth|session|code|secret|password|jwt|key|email|user", ctx, re.I))
        out.append({"file": path, "line": line_of(text, m.start()), "kind": "sender",
                    "severity": "high" if sensitive and "wildcard" in issues[0] else "medium" if sensitive else "low",
                    "issues": issues + (["context mentions sensitive data (PMX-003)"] if sensitive else []),
                    "snippet": ctx.replace("\n", " ")[:300]})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="files or folders of saved JS/HTML")
    ap.add_argument("--out")
    args = ap.parse_args()
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in names if n.lower().endswith(EXTS)]
        else:
            files.append(p)
    findings = []
    for f in files:
        findings += scan_file(f)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: (order[x["severity"]], x["file"], x["line"]))
    for x in findings:
        print(f"[{x['severity']}] {x['kind']} {x['file']}:{x['line']}")
        for i in x["issues"]:
            print(f"    - {i}")
    print(f"files {len(files)}, listeners {sum(x['kind']=='listener' for x in findings)}, "
          f"risky senders {sum(x['kind']=='sender' for x in findings)}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump({"files": len(files), "findings": findings}, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
