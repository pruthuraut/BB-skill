---
name: google-dorking-osint
description: Passive search-engine and OSINT reconnaissance for authorized targets across 49 Google dorks — exposed documents (pdf, xlsx, docx, txt), logs, SQL dumps, .env/yml/json/xml/conf/cfg/bak files, directory listings (intitle:"index of"), dashboards/admin/login pages, sensitive URL paths (admin, login, dashboard, config, api, upload, debug, test, staging, dev, .git, .env, wp-admin, phpmyadmin, swagger, graphql), secrets in page text (password, api key, secret, token), cached copies, SQL errors, and third-party leaks on pastebin, GitHub, Gist, Stack Overflow, Trello, Slack, and Notion — plus Bing/DuckDuckGo equivalents, GitHub code search, Wayback, and extra dorks. Includes a generator that writes clickable dork links for a target (no automated scraping) and a triage tool that ranks collected result URLs by risk and optionally verifies in-scope ones with scope-gated HEAD/GET status checks. Triggers on "Google dork", "dorking", "GHDB", "OSINT", "site:", "filetype:", "inurl:", "intitle:", "intext:", "exposed documents", "pastebin leak", "GitHub leak", "Trello leak", "search engine recon", or at the start of recon for a new target.
---

# Google Dorking and OSINT (49 checks)

Search engines and public collaboration sites often index what the target never meant to publish: documents with internal data, config and log files, admin panels, staging hosts, and secrets pasted into code, tickets, or boards. Dorking itself is passive (you query the search engine, not the target); opening or verifying results touches the target and follows the normal scope rules.

- Checklist: `references/dork_checklist.md` (GD-001 to GD-049, the exact dork per row, what a hit means, safe verification).
- Extras: `references/dork_extras.md` (Bing/DuckDuckGo/Yandex operator differences, GitHub code search, Wayback/CommonCrawl, Shodan/Censys, more dorks by goal, GHDB categories).
- Tracker: `references/dork_tracker.md`.
- `scripts/dork_gen.py`: writes all 49 dorks (and extras) for a target as a Markdown file of clickable search links per engine, plus a plain list. No queries are sent.
- `scripts/dork_triage.py`: reads URLs you collected from result pages, ranks them (secrets, dumps, configs, VCS, logs, backups, admin/login, docs, third-party leaks), and with `--verify` sends scope-gated HEAD/GET status checks to in-scope hosts only (status, type, size; no downloads).
- Related: `recon-hunter` (OSINT-001 and the pipeline), `subdomainenum` (hosts found by dorks), `contentdiscovery` (paths found by dorks), `data-exposure-audit` (DE-008 to DE-011 verification), `cloud-supplychain` (GitHub org secret hunting), `jsrecon`, `api-security` (swagger/graphql hits).

## Procedure

1. Confirm the program and its scope with `scripts/scope_check.sh TARGET`. Note which domains are in scope; third-party sites (GitHub, Pastebin, Trello, Notion) are searched passively but are not the target.
2. Generate the dorks:

   ```bash
   python3 .agents/skills/google-dorking-osint/scripts/dork_gen.py --domain example.com \
     --engines google,bing,duckduckgo --out artifacts/example.com/dorks.md
   ```

   Repeat with `--domain` for each in-scope root (and `--wildcard` to use `site:*.example.com -site:www.example.com` variants).
3. Run the dorks by hand in a browser at a human pace (no scrapers, which violate search engine terms and get blocked). Copy interesting result URLs into a file, one per line.
4. Triage:

   ```bash
   python3 .agents/skills/google-dorking-osint/scripts/dork_triage.py --target example.com --urls found.txt --verify \
     --out artifacts/example.com/dork_triage.json
   ```

   `--verify` checks only hosts that pass the scope gate, with a HEAD (or a GET limited to the first 2 KB) to report status, content type, and size.
5. Review high-ranked hits manually. For files: confirm exposure with status/size/type and a redacted first line (data-exposure-audit rules). For panels: note the product and version (tech-stack-audit), never try credentials.
6. Third-party leaks (pastebin, GitHub, Gist, Trello, Notion, Slack, Stack Overflow): record the URL, what it exposes, and whether it belongs to the target (author, org, internal hostnames). Do not use any leaked credential; report it for rotation.
7. Feed new hosts to subdomainenum, new paths to contentdiscovery, API docs to api-security/graphql-audit.
8. Save results to `artifacts/<target>/dorking.json` and the tracker to `artifacts/<target>/dork_tracker.md`.

## Classes

- `passive`: running dorks in a search engine, reading result snippets and third-party pages (GitHub, Pastebin, Trello, Notion).
- `bounded`: opening or status-checking result URLs on in-scope hosts (single HEAD/limited GET per URL).
- `authorized-only`: downloading full dumps, backups, or documents with personal data beyond proof; logging in with any found credential; accessing third-party workspaces (Trello/Notion/Slack) that require joining or accepting invites.

## Rules

- No automated scraping of search engines; use the browser at a normal pace (or an official API you are licensed for).
- Never use leaked credentials, tokens, or keys; report them.
- Treat documents with personal data carefully: confirm exposure with metadata (title, size, date), do not redistribute; redact in reports.
- Out-of-scope domains found through dorks are leads for the program only if the program says so; do not test them.
- Google's `cache:` operator was retired in 2024; use the Wayback Machine (`web.archive.org/web/*/target.com/*`) instead (see extras).

## Mitigation guidance for reports

- Remove sensitive files from public web roots and storage; block indexing of non-public paths (`X-Robots-Tag: noindex`, authentication — robots.txt alone is not a control).
- Request removal from search indexes (Google Search Console "Removals", Bing Webmaster Tools) after fixing.
- Rotate any credential or key found in public code, pastes, or boards; enable secret scanning (GitHub push protection) and monitor public paste sites.
- Restrict admin, staging, and debug interfaces by network or SSO; avoid exposing them on public DNS.
- Review public collaboration boards (Trello, Notion) and repositories for internal data; set workspaces to private by default.

## Sources

Exploit-DB Google Hacking Database (GHDB), Google Search operators documentation, OWASP WSTG-INFO-01 (search engine discovery), OSINT Framework, GitHub code search syntax, Internet Archive Wayback CDX API documentation.
