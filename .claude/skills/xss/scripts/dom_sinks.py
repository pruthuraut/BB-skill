#!/usr/bin/env python3
"""Offline DOM-XSS triage: find attacker-controllable sources, dangerous sinks, framework escape hatches,
postMessage listeners without origin checks, prototype-pollution and DOM-clobbering patterns in JS/HTML.

Usage:
  dom_sinks.py FILE_OR_DIR [...] [--min-score 2] [--out artifacts/xss/dom_sinks.tsv]

Pair with jsrecon (downloaded / de-minified bundles) and DOM Invader in Burp's browser. Each hit gets a score:
3 = source and sink on the same line, 2 = dangerous sink, 1 = source / informational. Review in context;
a sink is only exploitable if attacker data reaches it.
"""
import argparse
import os
import re
import sys

SOURCES = [
    r"location\.(hash|search|href|pathname)", r"document\.(URL|documentURI|baseURI|referrer|cookie)",
    r"window\.name", r"URLSearchParams", r"\.searchParams\.get\(", r"event\.data|e\.data|msg\.data|message\.data",
    r"localStorage\.getItem|sessionStorage\.getItem", r"history\.state", r"\$route\.(query|params)",
    r"useSearchParams|router\.query|this\.route\.snapshot\.(queryParams|params)", r"location\b(?!\.)",
]
SINKS = {
    "innerHTML/outerHTML": r"\.(inner|outer)HTML\s*\+?=",
    "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
    "document.write": r"document\.write(ln)?\s*\(",
    "eval-like": r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(",
    "setTimeout/Interval string": r"set(Timeout|Interval)\s*\(\s*['\"`]|set(Timeout|Interval)\s*\(\s*[a-zA-Z_$][\w$.]*\s*[,)]",
    "location assignment": r"(location(\.href)?|window\.open)\s*(=|\()\s*(?!['\"]https?:)",
    "src/href/action attribute": r"\.(src|href|action|formAction|data)\s*=\s*(?!['\"])|setAttribute\(\s*['\"](href|src|action|formaction|on\w+|srcdoc)['\"]",
    "srcdoc": r"\.srcdoc\s*=",
    "jQuery html sinks": r"\$\([^)]*\)\.(html|append|prepend|after|before|replaceWith|wrap\w*)\s*\(|\$\(\s*(location|decodeURI|[a-zA-Z_$][\w$]*)\s*\)|\.attr\(\s*['\"](href|src|on\w+)",
    "jQuery parse": r"\$\.parseHTML|jQuery\.parseHTML|\$\.globalEval",
    "createContextualFragment": r"createContextualFragment\s*\(",
    "DOMParser/Range": r"parseFromString\s*\(",
    "React dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "Vue v-html / compile": r"v-html|\$compile|Vue\.compile|template\s*:\s*[a-zA-Z_$]",
    "Angular bypassSecurityTrust": r"bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)",
    "AngularJS ng-bind-html / trustAs": r"ng-bind-html|\$sce\.trustAs|\$sceProvider\.enabled\(\s*false",
    "Svelte @html / Lit unsafeHTML": r"\{@html|unsafeHTML\s*\(",
    "Handlebars triple-stash / SafeString": r"\{\{\{[^}]+\}\}\}|new\s+Handlebars\.SafeString|SafeString\(",
    "markdown render to HTML": r"(marked|markdownIt|showdown|remarkable)\s*[\.(]",
    "sanitizer config": r"DOMPurify\.sanitize\([^)]*(ADD_TAGS|ADD_ATTR|ALLOWED_TAGS|SAFE_FOR_TEMPLATES|RETURN_DOM)|sanitizeHtml\(|xss\(\s*[^)]*whiteList",
    "Trusted Types policy": r"trustedTypes\.createPolicy",
}
INFO = {
    "postMessage listener": r"addEventListener\(\s*['\"]message['\"]|onmessage\s*=",
    "postMessage origin check": r"\.origin\s*(===?|!==?)|origin\.(indexOf|includes|startsWith|endsWith|match)\(",
    "postMessage send *": r"postMessage\([^)]*,\s*['\"]\*['\"]",
    "prototype pollution": r"__proto__|constructor\s*\[\s*['\"]prototype|\[\s*['\"]__proto__['\"]\s*\]|(merge|extend|deepMerge|defaultsDeep|set)\s*\([^)]*(JSON\.parse|location|search|hash)",
    "DOM clobbering candidate": r"window\.[a-zA-Z_$][\w$]*\s*\|\|\s*\{|document\.getElementById\([^)]*\)\s*\|\||(\bwindow|\bdocument)\.(?!body\b|head\b|documentElement\b|location\b|forms\b|images\b|links\b|scripts\b|activeElement\b)([a-zA-Z_$][\w$]*)\.(src|href|innerHTML)",
    "JSONP callback": r"[?&](callback|jsonp|cb|jsonpCallback)=",
    "library version": r"(jquery|angular|vue|react|dompurify|bootstrap|handlebars|lodash)[@/ -]v?(\d+\.\d+(\.\d+)?)",
}
EXT = (".js", ".mjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".php", ".erb", ".ejs", ".hbs",
       ".jsp", ".aspx", ".cshtml", ".twig", ".map")


def scan(path, text, rows):
    src_rx = re.compile("|".join(SOURCES))
    has_listener = re.search(INFO["postMessage listener"], text)
    has_origin = re.search(INFO["postMessage origin check"], text)
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:    # minified bundle: split on ; to keep hits readable
            chunks = [c for c in re.split(r"(?<=;)", line) if c.strip()]
        else:
            chunks = [line]
        for ch in chunks:
            src = src_rx.search(ch)
            for name, rx in SINKS.items():
                if re.search(rx, ch):
                    rows.append((3 if src else 2, path, ln, name, src.group(0) if src else "", ch.strip()[:220]))
            for name, rx in INFO.items():
                if name == "postMessage origin check":
                    continue
                m = re.search(rx, ch, re.I if name == "library version" else 0)
                if m:
                    score = 1
                    if name == "postMessage listener" and has_listener and not has_origin:
                        name, score = "postMessage listener WITHOUT origin check in file", 2
                    rows.append((score, path, ln, name, m.group(0)[:60], ch.strip()[:220]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--min-score", type=int, default=1)
    ap.add_argument("--out", default="artifacts/xss/dom_sinks.tsv")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                files += [os.path.join(root, f) for f in fs if f.lower().endswith(EXT)]
        else:
            files.append(p)
    rows = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                scan(f, fh.read(20_000_000), rows)
        except OSError as e:
            print(f"[!] {f}: {e}", file=sys.stderr)
    rows = [r for r in rows if r[0] >= a.min_score]
    rows.sort(key=lambda r: (-r[0], r[1], r[2]))
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("score\tfile\tline\tkind\tsource_or_match\tcode\n")
        for r in rows:
            fh.write("\t".join(str(x).replace("\t", " ") for x in r) + "\n")
    for r in rows[:40]:
        print(f"{r[0]}  {os.path.basename(r[1])}:{r[2]:<6} {r[3]:<34} {r[4][:30]:<30} {r[5][:90]}")
    print(f"[+] {len(files)} files, {len(rows)} hits (score>={a.min_score}) -> {a.out}")


if __name__ == "__main__":
    main()
