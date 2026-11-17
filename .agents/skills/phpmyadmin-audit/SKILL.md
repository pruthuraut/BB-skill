---
name: phpmyadmin-audit
description: "Deep recon and audit of authorized phpMyAdmin installations across 143 checklist rows: install-path and subdomain discovery, port and banner checks, version fingerprinting with CVE version matching (no exploits), config, backup, VCS and directory exposure, login token and cookie analysis, bounded XSS, SQL error and traversal probes, approval-gated file reads, and authorized-only login, injection and database steps. Uses Kali tools (ffuf, gobuster, dirsearch, nuclei, nikto, nmap NSE, whatweb, searchsploit, sqlmap, hydra) and a scope-gated probe. Triggers on \"phpMyAdmin\", \"phpmyadmin\", \"pma\", \"/phpmyadmin\", \"pma_username\", \"pma_password\", \"config.inc.php\", \"setup/\", \"libraries/\", \"db_sql.php\", \"MySQL web admin\", \"database admin panel\"."
---

# phpMyAdmin Audit

Full phpMyAdmin assessment, from discovery through version and configuration review, to bounded injection checks and authorized-only database steps. Every check is tied to a row in `references/phpmyadmin_checklist.md` (IDs `PMA-001` to `PMA-143`).

Probe: `scripts/pma_probe.py`. Kali commands: `pma_probe.py --print-kali` prints the set and sends nothing.

## Hard rules

1. **Scope first.** The probe runs `scripts/scope_check.sh` and stops if the host is not listed in its scope file. Nothing is assumed authorized.
2. **Default run is passive and bounded.** GET, HEAD, OPTIONS, TRACE, one marker or quote per parameter, and one nonexistent-file traversal. Nothing else.
3. **Never** submit credentials, brute-force, or try default passwords from this skill. The probe never logs in. Default-credential, lockout and brute-force rows (`PMA-045`, `PMA-050`, `PMA-051`) are `authorized-only`: written approval for each check, capped attempts, and a stop at the first lockout signal.
4. **CVE rows are version checks.** The probe matches the version string against the affected range from the checklist. It never runs exploit code. `--searchsploit` lists titles from the offline exploit-db copy and runs nothing.
5. **File reads are gated.** `/etc/passwd` and `win.ini` are read only with `--lfi-approved`, and the probe stores only a yes/no result, never file content.
6. **No writes.** Never create databases, tables, users, or files, and never run `INTO OUTFILE`, `LOAD_FILE` on a live system, or `GRANT`. Report feasibility only (`PMA-067`, `PMA-119`, `PMA-120`).
7. **Redact.** Passwords, secrets, tokens, hashes, and table rows are redacted in every artifact. Store counts, names, and signatures.

## Procedure

1. Confirm scope. The host (or the program's scope file) must list the target.
2. Print the Kali command set, then choose from it:

   ```
   python3 .agents/skills/phpmyadmin-audit/scripts/pma_probe.py --target https://app.example.com --print-kali
   ```

3. Run the probe. Add `--install-path` if the install sits under a path the defaults miss:

   ```
   python3 .agents/skills/phpmyadmin-audit/scripts/pma_probe.py \
     --target https://app.example.com --workspace ~/Documents/bugbounty --program example \
     --nmap --searchsploit --out artifacts/app.example.com/phpmyadmin.json
   ```

   Options: `--delay 0.5` (default), `--max-requests 200` (default), `--no-injection-probes` to skip the marker, quote and traversal probes, `--insecure` only for lab hosts with self-signed certificates.
4. Discovery, when the default paths miss. Run these on in-scope hosts only:
   - Kali: `ffuf -u https://app.example.com/FUZZ/ -w wordlists/phpmyadmin.txt -mc 200,301,302,401,403 -rate 10` (`PMA-004`, `PMA-042`).
   - Subdomains: `subfinder -d example.com` and `subdomainenum` for `db.`, `admin.`, `phpmyadmin.`, `mysql.` (`PMA-005`). Scope-check each hit.
5. Review the output against the checklist. The probe lists every finding in severity order. For each finding, confirm by hand with a single request (`curl -sI`, or a browser for XSS candidates).
6. Work the `manual` rows that the probe does not cover: source review of `libraries/` on your own copy (`PMA-043`), `postMessage` and DOM sinks (`PMA-095`, `PMA-096`, run `.agents/skills/jsrecon/scripts/js_sink_audit.py` on the downloaded JS), and server config review you are authorized to read (`PMA-035`).
7. Authorized-only steps (`PMA-045` to `PMA-068`, `PMA-071` to `PMA-078`, `PMA-089` to `PMA-094`, `PMA-099` to `PMA-122`, `PMA-136`): only after written approval for that exact check, on accounts or instances you are permitted to use. Record approval in the report.
8. Write the report using `references/report_template.md`. Keep the JSON artifact in `artifacts/<host>/phpmyadmin.json`.

## Coverage map

| Section of the checklist | Rows | Probe coverage |
|---|---|---|
| Initial reconnaissance: dorks, paths, subdomains, ports, DNS | `PMA-001` to `PMA-012` | paths, redirects, `--nmap` ports and banner |
| Detection and fingerprinting: headers, cookies, version, form, token | `PMA-013` to `PMA-024` | full |
| Configuration and directory exposure | `PMA-025` to `PMA-044` | config, backup, `.htaccess`, `.htpasswd`, phpinfo, VCS, archives, dumps, listings, setup |
| Authentication | `PMA-045` to `PMA-058` | token analysis, reCAPTCHA version check; login steps are authorized-only |
| SQL injection | `PMA-059` to `PMA-068` | version check, single-quote errors, Kali sqlmap (authorized-only) |
| Local file inclusion | `PMA-069` to `PMA-078` | version check, nonexistent-file traversal, approval-gated reads |
| Directory traversal | `PMA-079` to `PMA-085` | version check, depth via nonexistent file, nmap NSE |
| Cross-site scripting | `PMA-086` to `PMA-096` | CVE version checks, marker reflection; stored and check-tables tests are authorized-only |
| CSRF and session | `PMA-097` to `PMA-110` | token presence, entropy, cookie flags; state tests are authorized-only |
| Database access and exploitation | `PMA-111` to `PMA-122` | authorized-only |
| Known CVEs and legacy | `PMA-123` to `PMA-127` | version table, `searchsploit` titles |
| Advanced reconnaissance | `PMA-128` to `PMA-136` | nmap banner, manual review |
| Process and reporting | `PMA-137` to `PMA-143` | scope gate, budget and delay, artifacts, report template |

## Kali toolkit

| Use | Tool and command | Class |
|---|---|---|
| Fingerprint | `whatweb -a 3 BASE`, `wafw00f BASE` | bounded |
| Ports and banner | `nmap -Pn -sT -sV --open -p 80,443,8080,8888,8008,3306 HOST` (or `--nmap`) | bounded |
| NSE checks | `nmap -Pn -p 80,443 --script http-phpmyadmin-dir-traversal,http-phpself-xss HOST` | bounded |
| Path fuzzing | `ffuf`, `gobuster dir`, `dirsearch` with `wordlists/phpmyadmin.txt` and `wordlists/config.txt` | bounded (rate-limited) |
| Detection templates | `nuclei -tags phpmyadmin,exposure,misconfig -severity info,low,medium -rl 5` | bounded |
| Web baseline | `nikto -h BASE` | bounded |
| Version lookup | `searchsploit --json phpmyadmin VERSION` (titles only, never run) | passive |
| TLS | `openssl s_client` and `x509` for certificate names and dates | passive |
| SQL injection | `sqlmap -u 'BASE/...?server=1' --batch --level 1 --risk 1 --technique=E` | authorized-only |
| Login brute force | `hydra ... https-post-form` (static token only) | authorized-only |

Use the wordlists that already live in the repo: `wordlists/phpmyadmin.txt`, `wordlists/PhpMyAdmin_PHPmyadmin.txt`, `wordlists/config.txt`, `wordlists/sql.txt`, `wordlists/dotfiles.txt`.

## Probe outputs

`artifacts/<host>/phpmyadmin.json` contains: installs, primary install, server headers, version and source, CVE version matches, login fields, token shape (length, charset, entropy estimate, and whether the token is the same across fresh sessions), cookie flags, method results, exposure table, XSS and SQL-error probe results, traversal result, approval-gated read results, nmap ports, searchsploit titles, request count, and findings. The token value, file contents and table data are never written.

## Reporting notes

- A version match is a lead, not a finding. Confirm it against the vendor advisory (phpmyadmin.net/security) before reporting a CVE.
- A reflected marker is a candidate until you confirm it in a browser on the in-scope host.
- Report `config.inc.php` source exposure, `.git`, dumps and archives as high-impact only after confirming the content signature by hand, and show the redacted lines in the report.
- Do not keep dumped data. Delete any sample after reporting.
