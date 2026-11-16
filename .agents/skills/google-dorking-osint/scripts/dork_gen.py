#!/usr/bin/env python3
"""Generate the GD-001..GD-049 dorks (plus extras) for a domain as clickable links.

No queries are sent: the output is a Markdown file of search links per engine and
a plain text list, for running by hand in a browser at a normal pace.

Example:
  dork_gen.py --domain example.com --engines google,bing,duckduckgo --out artifacts/example.com/dorks.md
  dork_gen.py --domain example.com --wildcard --org-name "Example Corp" --out dorks.md
"""
from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import quote_plus

ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
    "yandex": "https://yandex.com/search/?text={q}",
}
CORE = [
    ("GD-001", "site:{T} filetype:pdf"), ("GD-002", "site:{T} filetype:xlsx"), ("GD-003", "site:{T} filetype:docx"),
    ("GD-004", "site:{T} filetype:txt"), ("GD-005", "site:{T} filetype:log"), ("GD-006", "site:{T} filetype:sql"),
    ("GD-007", "site:{T} filetype:env"), ("GD-008", "site:{T} filetype:yml"), ("GD-009", "site:{T} filetype:json"),
    ("GD-010", "site:{T} filetype:xml"), ("GD-011", "site:{T} filetype:conf"), ("GD-012", "site:{T} filetype:cfg"),
    ("GD-013", "site:{T} filetype:bak"), ("GD-014", 'site:{T} intitle:"index of"'), ("GD-015", 'site:{T} intitle:"dashboard"'),
    ("GD-016", 'site:{T} intitle:"admin"'), ("GD-017", 'site:{T} intitle:"login"'), ("GD-018", "site:{T} inurl:admin"),
    ("GD-019", "site:{T} inurl:login"), ("GD-020", "site:{T} inurl:dashboard"), ("GD-021", "site:{T} inurl:config"),
    ("GD-022", "site:{T} inurl:api"), ("GD-023", "site:{T} inurl:upload"), ("GD-024", "site:{T} inurl:debug"),
    ("GD-025", "site:{T} inurl:test"), ("GD-026", "site:{T} inurl:staging"), ("GD-027", "site:{T} inurl:dev"),
    ("GD-028", "site:{T} inurl:.git"), ("GD-029", "site:{T} inurl:.env"), ("GD-030", "site:{T} inurl:wp-admin"),
    ("GD-031", "site:{T} inurl:phpmyadmin"), ("GD-032", "site:{T} inurl:swagger"), ("GD-033", "site:{T} inurl:graphql"),
    ("GD-034", 'site:{T} intext:"password"'), ("GD-035", 'site:{T} intext:"api key"'), ("GD-036", 'site:{T} intext:"secret"'),
    ("GD-037", 'site:{T} intext:"token"'), ("GD-038", "site:{T} cache:"), ("GD-039", 'site:{T} "error" "sql"'),
    ("GD-040", "site:pastebin.com {T}"), ("GD-041", "site:github.com {T} password"), ("GD-042", "site:github.com {T} api_key"),
    ("GD-043", "site:github.com {T} secret"), ("GD-044", "site:github.com {T} token"), ("GD-045", "site:gist.github.com {T}"),
    ("GD-046", "site:stackoverflow.com {T}"), ("GD-047", "site:trello.com {T}"), ("GD-048", "site:slack.com {T}"),
    ("GD-049", "site:notion.so {T}"),
]
EXTRA = [
    ("subdomains", "site:*.{T} -site:www.{T}"),
    ("params", "site:{T} inurl:? ext:php"),
    ("db files", "site:{T} (ext:sql | ext:db | ext:dbf | ext:mdb)"),
    ("secrets in env-like", 'site:{T} (ext:env | ext:ini | ext:yml) intext:"DB_PASSWORD"'),
    ("panels", 'site:{T} (intitle:"Grafana" | intitle:"Kibana" | intitle:"Jenkins" | intitle:"phpMyAdmin")'),
    ("diagnostics", 'site:{T} (inurl:"/actuator" | inurl:"/server-status" | inurl:"phpinfo")'),
    ("redirect params", "site:{T} (inurl:redirect= | inurl:url= | inurl:next= | inurl:return=)"),
    ("buckets", "(site:s3.amazonaws.com | site:blob.core.windows.net | site:storage.googleapis.com) {T}"),
    ("atlassian", 'site:atlassian.net "{T}"'),
    ("google docs", '(site:docs.google.com | site:drive.google.com) "{T}"'),
    ("postman", "(site:postman.com | site:documenter.getpostman.com) {T}"),
    ("code playgrounds", "(site:jsfiddle.net | site:codepen.io | site:replit.com) {T}"),
    ("notion.site", "site:notion.site {T}"),
    ("other pastes", "(site:paste.ee | site:hastebin.com | site:justpaste.it | site:rentry.co) {T}"),
]
GITHUB = ['"{T}" password', '"{T}" (api_key OR apikey OR secret OR token)', '"{T}" filename:.env', '"{T}" filename:config extension:yml']


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", required=True, action="append", help="in-scope root domain (repeatable)")
    ap.add_argument("--engines", default="google,bing,duckduckgo")
    ap.add_argument("--wildcard", action="store_true", help="also emit site:*.T -site:www.T variants of the site: dorks")
    ap.add_argument("--org-name", help="organization name for quoted-name variants on third-party sites")
    ap.add_argument("--no-extras", action="store_true")
    ap.add_argument("--out", required=True, help="Markdown output path (a .txt list is written next to it)")
    a = ap.parse_args()
    engines = [e for e in a.engines.split(",") if e in ENGINES]
    if not engines:
        sys.exit(f"engines must be among {list(ENGINES)}")
    md = ["# Dorks", "", "Run by hand at a normal pace. Mark results in `references/dork_tracker.md`.", ""]
    plain = []
    for T in [d.lower().strip() for d in a.domain]:
        md += [f"## {T}", "", "| ID | Dork | " + " | ".join(e.title() for e in engines) + " |", "|---|---|" + "---|" * len(engines)]
        rows = list(CORE)
        if a.wildcard:
            rows += [(f"{i}w", d.replace("site:{T}", "site:*.{T} -site:www.{T}")) for i, d in CORE if d.startswith("site:{T}")]
        if a.org_name:
            rows += [(f"{i}o", d.replace("{T}", f'"{a.org_name}"')) for i, d in CORE[39:]]
        if not a.no_extras:
            rows += [(f"X:{n}", d) for n, d in EXTRA]
        for rid, tpl in rows:
            q = tpl.replace("{T}", T)
            if rid == "GD-038":
                links = [f"[wayback](https://web.archive.org/web/*/{T}/*)"] * len(engines)
                plain.append(f"{rid}\thttps://web.archive.org/cdx/search/cdx?url=*.{T}/*&output=txt&fl=original&collapse=urlkey")
            else:
                links = [f"[{e}]({ENGINES[e].format(q=quote_plus(q))})" for e in engines]
                plain.append(f"{rid}\t{q}")
            md.append(f"| {rid} | `{q.replace('|', '&#124;')}` | " + " | ".join(links) + " |")
        md += ["", f"### GitHub code search for {T}", ""]
        for g in GITHUB:
            q = g.replace("{T}", T)
            md.append(f"- [`{q}`](https://github.com/search?type=code&q={quote_plus(q)})")
        md += [f"- Wayback: https://web.archive.org/web/*/{T}/*", f"- crt.sh: https://crt.sh/?q=%25.{T}", ""]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, "w", encoding="utf-8").write("\n".join(md) + "\n")
    txt = os.path.splitext(a.out)[0] + ".txt"
    open(txt, "w", encoding="utf-8").write("\n".join(plain) + "\n")
    print(f"wrote {len(plain)} dorks to {a.out} and {txt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
