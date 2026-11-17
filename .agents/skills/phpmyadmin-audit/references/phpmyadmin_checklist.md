# phpMyAdmin Deep Recon and Audit Checklist

Source: the Deep Reconnaissance Checklist for phpMyAdmin (Nov 2025), restructured into rows with a class and a safe verification.

Class key:
- `passive`: read from responses already fetched, configuration you own, or offline data. No extra requests.
- `bounded`: a few read-only GET, HEAD, OPTIONS, or TRACE requests, or one marker or single-quote request per parameter. The probe runs these by default.
- `authorized-only`: login with an account you are permitted to use, injection payloads with time or boolean delays, file reads, writes, or any step that changes data. Needs written approval for that exact check.

Never run an exploit from a CVE row. CVE rows are version checks only: the probe matches the version string against the affected range. Confirm each match by reading the advisory before you report it.

Probe column: `probe` means `scripts/pma_probe.py` runs the check. `kali` means a Kali tool command is printed by `--print-kali`. `manual` means it is a review you do yourself.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| PMA-001 | phpMyAdmin | phpMyAdmin discovery: Search-engine dorks: `inurl:phpmyadmin`, `intitle:"phpMyAdmin"`, `site:target.com phpmyadmin` (manual; probe: kali) | passive | `dork_gen.py` from google-dorking-osint; read result URLs only |
| PMA-002 | phpMyAdmin | phpMyAdmin discovery: Default install paths: `/phpmyadmin`, `/pma`, `/admin/phpmyadmin`, `/db/phpmyadmin`, `/mysql/phpmyadmin`, `/tools/phpmyadmin` (probe) | bounded | GET `path/` once; record status and markers |
| PMA-003 | phpMyAdmin | phpMyAdmin discovery: Alternative paths: `/PMA`, `/myadmin`, `/phpmyadmin_old`, `/phpmyadmin_backup`, `/phpmyadmin-old`, `/sql/phpmyadmin`, `/database/phpmyadmin`, `/dbadmin` (probe) | bounded | GET `path/` once; record status and markers |
| PMA-004 | phpMyAdmin | phpMyAdmin discovery: Versioned folder names such as `/phpMyAdmin-X.X.X` (kali: ffuf with `wordlists/phpmyadmin.txt`) | bounded | Rate-limited fuzz; filter by status and size |
| PMA-005 | phpMyAdmin | phpMyAdmin discovery: Subdomains `db.`, `admin.`, `phpmyadmin.`, `mysql.` (kali: subfinder, subdomainenum) | passive | Passive sources first; scope-check each name before any request |
| PMA-006 | phpMyAdmin | phpMyAdmin discovery: Certificate transparency for pma hostnames (crt.sh) | passive | Read CT logs; no requests to the target |
| PMA-007 | phpMyAdmin | Network: Web ports 80, 443, 8080, 8888, 8008 (probe with `--nmap`; kali: nmap) | bounded | `nmap -Pn -sT -sV --open -p ...` on the in-scope host |
| PMA-008 | phpMyAdmin | Network: MySQL port 3306 reachable from the internet (probe with `--nmap`) | bounded | Banner only (`-sV`); do not attempt a login |
| PMA-009 | phpMyAdmin | Stack: Server, X-Powered-By, and PHP version headers (probe) | passive | Read headers from the GET responses |
| PMA-010 | phpMyAdmin | DNS: MX, TXT, NS records for the apex (kali: dig; see dns-security-audit) | passive | `dig +short MX/TXT/NS` |
| PMA-011 | phpMyAdmin | Redirects: Redirect chain from the install path (probe) | bounded | Follow `Location` by hand, up to 5 hops |
| PMA-012 | phpMyAdmin | Discovery: Restricted (401/403) install path that still returns phpMyAdmin markers (probe) | bounded | Note the status; do not bypass the restriction |
| PMA-013 | phpMyAdmin | Fingerprint: Status codes: 200 loaded, 301/302 redirect, 403 restricted, 404 absent (probe) | passive | Read from responses |
| PMA-014 | phpMyAdmin | Fingerprint: Cookies `phpMyAdmin` and `pma_*` present on the login page (probe) | passive | Parse `Set-Cookie` |
| PMA-015 | phpMyAdmin | Fingerprint: Version in HTML comment `<!-- phpMyAdmin X.X.X -->` (probe) | passive | Regex on the login page |
| PMA-016 | phpMyAdmin | Fingerprint: Version in JS or CSS query strings, or `pma_version` (probe) | passive | Regex on the login page |
| PMA-017 | phpMyAdmin | Fingerprint: Version in error messages (probe with `--sql-error`) | passive | Read the error response |
| PMA-018 | phpMyAdmin | Fingerprint: Login form fields `pma_username`, `pma_password`, `server`, `token`, `go` (probe) | passive | Parse the form |
| PMA-019 | phpMyAdmin | Fingerprint: Hidden `token` field: presence, length, character set, entropy (probe) | passive | Compare token shape only; redact the value |
| PMA-020 | phpMyAdmin | Fingerprint: Language selector and UI markers (probe) | passive | Presence of `name="lang"` and the logo markup |
| PMA-021 | phpMyAdmin | Fingerprint: Meta tags, generator tag, and `<link>`/`<script>` paths (manual) | passive | Read the page source |
| PMA-022 | phpMyAdmin | Fingerprint: HTML comments that leak internal paths or versions (manual) | passive | Read the page source |
| PMA-023 | phpMyAdmin | Fingerprint: OPTIONS, HEAD, and TRACE responses and the `Allow` header (probe) | bounded | One request each; TRACE returning 200 is a finding |
| PMA-024 | phpMyAdmin | Fingerprint: Redirect targets reveal version or path (probe) | bounded | Read the `Location` header |
| PMA-025 | phpMyAdmin | Config and directories: Directory listing of `/`, `libraries/`, `js/`, `themes/`, `locale/`, `setup/`, `sql/`, `examples/` (probe) | bounded | GET the directory; look for "Index of" |
| PMA-026 | phpMyAdmin | Config and directories: `setup/` reachable without authentication (probe) | bounded | GET `setup/`; record status |
| PMA-027 | phpMyAdmin | Config and directories: `config.inc.php` served as source, not executed (probe) | bounded | Signature `<?php` or `$cfg[`; an empty 200 is normal |
| PMA-028 | phpMyAdmin | Config and directories: `config.sample.inc.php` exposed (probe) | bounded | Signature `$cfg[` |
| PMA-029 | phpMyAdmin | Config and directories: `libraries/config.default.php` exposed (probe) | bounded | Signature `$cfg[` |
| PMA-030 | phpMyAdmin | Config and directories: `setup/frames/config.inc.php` exposed (probe) | bounded | Signature `$cfg[` |
| PMA-031 | phpMyAdmin | Config and directories: `.htaccess` readable (probe) | bounded | Signatures `RewriteEngine`, `AuthType`, `Require` |
| PMA-032 | phpMyAdmin | Config and directories: Backup variants: `.config.inc.php`, `config.inc.php.bak`, `~`, `.old`, `.sample`, `.save`, `.orig` (probe) | bounded | Signature check on each |
| PMA-033 | phpMyAdmin | Config and directories: `.htpasswd` readable (probe) | bounded | Signature `user:$hash`; redact the hash |
| PMA-034 | phpMyAdmin | Config and directories: `phpinfo.php` and `info.php` at install path and site root (probe) | bounded | Signatures `phpinfo()`, `PHP Version` |
| PMA-035 | phpMyAdmin | Config and directories: nginx.conf, httpd.conf, default location blocks (manual) | passive | Review only config you own or are authorized to read |
| PMA-036 | phpMyAdmin | Config and directories: `.git` exposed (probe) | bounded | `.git/HEAD` with `ref: refs/` and `.git/config` with `[core]` |
| PMA-037 | phpMyAdmin | Config and directories: `.svn` exposed (probe) | bounded | `.svn/wc.db` SQLite header or `.svn/entries` |
| PMA-038 | phpMyAdmin | Config and directories: `.hg` exposed (probe) | bounded | `.hg/requires` signature |
| PMA-039 | phpMyAdmin | Config and directories: Archives `phpmyadmin.tar.gz`, `.zip`, `.tar` (probe) | bounded | Magic bytes only; do not download the full file |
| PMA-040 | phpMyAdmin | Config and directories: SQL dumps in web root: `dump.sql`, `db.sql`, `backup.sql`, `phpmyadmin.sql` (probe) | bounded | Signature `CREATE TABLE` or `-- MySQL dump`; store no rows |
| PMA-041 | phpMyAdmin | Config and directories: Debug or verbose errors in production (probe with `--sql-error`) | passive | Read the error page |
| PMA-042 | phpMyAdmin | Config and directories: Path fuzzing with ffuf, gobuster, or dirsearch (kali) | bounded | Rate-limited; `wordlists/phpmyadmin.txt` |
| PMA-043 | phpMyAdmin | Config and directories: Source review of `libraries/` on your own copy (manual) | passive | Review code; no requests |
| PMA-044 | phpMyAdmin | Config and directories: Custom patches, auth plugins, and modified files (manual) | passive | Compare with the release tarball of the same version |
| PMA-045 | phpMyAdmin | Authentication: Default credentials: `root/(empty)`, `root/password`, `root/mysql`, `admin/admin`, `pma/(empty)` | authorized-only | Manual, only with written approval; at most one attempt per pair |
| PMA-046 | phpMyAdmin | Authentication: Login POST accepted without a token (authorized-only) | authorized-only | One POST on an account you own, with approval |
| PMA-047 | phpMyAdmin | Authentication: Token static across fresh sessions (probe) | bounded | Two fresh sessions with no cookie; compare the token |
| PMA-048 | phpMyAdmin | Authentication: Token expiry timing | authorized-only | Own session only |
| PMA-049 | phpMyAdmin | Authentication: Token reuse across requests | authorized-only | Own session only |
| PMA-050 | phpMyAdmin | Authentication: Brute-force lockout and rate limit | authorized-only | Approved, capped attempts; stop on first lockout signal |
| PMA-051 | phpMyAdmin | Authentication: Hydra `http-post-form` with token handling (kali: hydra) | authorized-only | Hydra cannot refresh a token; use only with approval |
| PMA-052 | phpMyAdmin | Authentication: reCAPTCHA bypass CVE-2015-6830 (version check) (probe) | passive | Version in 4.3 < 4.3.13.2 or 4.4 < 4.4.14.1 |
| PMA-053 | phpMyAdmin | Authentication: SQL injection in the login form (`' OR '1'='1`) | authorized-only | Own instance only; never a live login |
| PMA-054 | phpMyAdmin | Authentication: Null byte in username (`admin%00`) | authorized-only | Own instance only |
| PMA-055 | phpMyAdmin | Authentication: Case-sensitivity and encoding variants of the username | authorized-only | Own instance only |
| PMA-056 | phpMyAdmin | Authentication: Remove, modify, or replay the session token | authorized-only | Own account; verify the server rejects it |
| PMA-057 | phpMyAdmin | Authentication: Authenticated pages reachable without login (manual) | bounded | GET the pages without a cookie; record the status |
| PMA-058 | phpMyAdmin | Authentication: `AllowArbitraryServer` and `ServerDefault = 0` behaviour (manual) | passive | Observe the server selector; do not change settings |
| PMA-059 | phpMyAdmin | SQL injection: CVE-2020-26935 and CVE-2020-10802: search controller version (probe) | passive | 4.9 < 4.9.5/4.9.6 or 5.0 < 5.0.2/5.0.3 |
| PMA-060 | phpMyAdmin | SQL injection: Single quote in `db`, `table`, `server`, `pos`, `sql_query` shows an SQL error (probe with `--sql-error`) | bounded | One request per parameter; signature check |
| PMA-061 | phpMyAdmin | SQL injection: Time-based `SLEEP()` on the search fields | authorized-only | Approved; short delay; own instance |
| PMA-062 | phpMyAdmin | SQL injection: Boolean-based differential on the search fields | authorized-only | Approved; own instance |
| PMA-063 | phpMyAdmin | SQL injection: Quote, semicolon, and comment characters in general parameters (probe: quote only) | bounded | Single quote only; no SQL-shaped values |
| PMA-064 | phpMyAdmin | SQL injection: sqlmap enumeration (kali: sqlmap) | authorized-only | `--batch --level 1 --risk 1` on own instance with approval |
| PMA-065 | phpMyAdmin | SQL injection: Table or database names that carry SQL, triggered through search | authorized-only | Create only on an instance you own |
| PMA-066 | phpMyAdmin | SQL injection: Extract database list, table names, and user credentials | authorized-only | Report counts and names; redact values |
| PMA-067 | phpMyAdmin | SQL injection: Privilege escalation through GRANT or creating an admin user | authorized-only | Report feasibility only; never create users on a live system |
| PMA-068 | phpMyAdmin | SQL injection: UNION-based extraction | authorized-only | Approved; own instance |
| PMA-069 | phpMyAdmin | Local file inclusion: CVE-2018-12613: version 4.8.0 or 4.8.1 (probe) | passive | Version string match |
| PMA-070 | phpMyAdmin | Local file inclusion: `target=db_sql.php%253f/../` traversal to a nonexistent file: error text reveals paths (probe) | bounded | Random nonexistent name; read the error only |
| PMA-071 | phpMyAdmin | Local file inclusion: Read `/etc/passwd` through the `target` parameter (probe with `--lfi-approved`) | authorized-only | Signature `root:x:0:0`; store no content |
| PMA-072 | phpMyAdmin | Local file inclusion: Read `win.ini` through the `target` parameter (probe with `--lfi-approved`) | authorized-only | Signature `[fonts]`; store no content |
| PMA-073 | phpMyAdmin | Local file inclusion: Read `config.inc.php` through traversal | authorized-only | Own instance; redact secrets |
| PMA-074 | phpMyAdmin | Local file inclusion: Read `/proc/self/environ` | authorized-only | Approved; redact environment values |
| PMA-075 | phpMyAdmin | Local file inclusion: Read `.htaccess` through traversal | authorized-only | Approved |
| PMA-076 | phpMyAdmin | Local file inclusion: `open_basedir` restriction in effect (manual) | passive | Read the PHP configuration you can see |
| PMA-077 | phpMyAdmin | Local file inclusion: Unauthenticated LFI when `ServerDefault = 0` | authorized-only | Approved; own instance |
| PMA-078 | phpMyAdmin | Local file inclusion: LFI to RCE by including a DB table file (report feasibility only) | authorized-only | Never write payloads to a live database |
| PMA-079 | phpMyAdmin | Directory traversal: CVE-2005-3299: version 2.6.4 series (probe) | passive | Version string match |
| PMA-080 | phpMyAdmin | Directory traversal: Traversal encodings `..%2f`, `..;/`, `....//` (manual) | bounded | Nonexistent target only |
| PMA-081 | phpMyAdmin | Directory traversal: Traversal depth discovery with increasing `../` (probe, same as PMA-070) | bounded | Nonexistent target only |
| PMA-082 | phpMyAdmin | Directory traversal: nmap `http-phpmyadmin-dir-traversal` NSE (kali: nmap) | bounded | NSE check only |
| PMA-083 | phpMyAdmin | Directory traversal: Read web server files (authorized-only) | authorized-only | Approved |
| PMA-084 | phpMyAdmin | Directory traversal: Enumerate application files (authorized-only) | authorized-only | Approved |
| PMA-085 | phpMyAdmin | Directory traversal: Read database configuration files (authorized-only) | authorized-only | Approved; redact secrets |
| PMA-086 | phpMyAdmin | Cross-site scripting: CVE-2025-24530: Check Tables XSS, version 5.x below 5.2.2 (probe) | passive | Version string match |
| PMA-087 | phpMyAdmin | Cross-site scripting: CVE-2025-24529: database and table name XSS, version 5.x below 5.2.2 (probe) | passive | Version string match |
| PMA-088 | phpMyAdmin | Cross-site scripting: Reflected XSS: unique marker plus `"'<>` in `db`, `table`, `server`, `lang`, `target` (probe with `--xss`) | bounded | Unique marker; check for unencoded reflection |
| PMA-089 | phpMyAdmin | Cross-site scripting: Stored XSS through database or table names | authorized-only | Own instance; create a marker-named test object only |
| PMA-090 | phpMyAdmin | Cross-site scripting: Check Tables operation with a marker name | authorized-only | Own instance only |
| PMA-091 | phpMyAdmin | Cross-site scripting: Error message reflects input (probe with `--xss`, error page) | bounded | Same marker test; read the error page |
| PMA-092 | phpMyAdmin | Cross-site scripting: Search functionality reflects input | bounded | Marker only |
| PMA-093 | phpMyAdmin | Cross-site scripting: Payload set (`<img onerror>`, `<svg onload>`, `<details ontoggle>`) | authorized-only | Marker first; execute only on your own instance |
| PMA-094 | phpMyAdmin | Cross-site scripting: Cookie or CSRF-token capture proof of concept | authorized-only | Never use a real third-party session |
| PMA-095 | phpMyAdmin | Cross-site scripting: DOM sinks in phpMyAdmin JavaScript (manual; kali: jsrecon `js_sink_audit.py`) | passive | Run the sink scanner on downloaded JS of the in-scope host |
| PMA-096 | phpMyAdmin | Cross-site scripting: Client-side message handlers and `postMessage` (manual) | passive | Review JS; no requests |
| PMA-097 | phpMyAdmin | CSRF and session: Anti-CSRF token on state-changing forms (probe) | bounded | Parse forms on the login page; record token presence |
| PMA-098 | phpMyAdmin | CSRF and session: Token length and entropy (probe) | passive | Shape and entropy only |
| PMA-099 | phpMyAdmin | CSRF and session: Submit a state change without the token | authorized-only | Own account; approval |
| PMA-100 | phpMyAdmin | CSRF and session: Submit with an invalid token | authorized-only | Own account; approval |
| PMA-101 | phpMyAdmin | CSRF and session: Submit with an expired token | authorized-only | Own account; approval |
| PMA-102 | phpMyAdmin | CSRF and session: Token reuse across requests | authorized-only | Own account; approval |
| PMA-103 | phpMyAdmin | CSRF and session: Cookie flags: `HttpOnly`, `Secure`, `SameSite` on `phpMyAdmin` and `pma_*` (probe) | passive | Parse `Set-Cookie` |
| PMA-104 | phpMyAdmin | CSRF and session: Cookie domain and path scope (probe) | passive | Parse `Set-Cookie` |
| PMA-105 | phpMyAdmin | CSRF and session: Session fixation: session ID before and after login | authorized-only | Own account; approval |
| PMA-106 | phpMyAdmin | CSRF and session: Logout invalidates the session | authorized-only | Own account |
| PMA-107 | phpMyAdmin | CSRF and session: Old session reused after logout or timeout | authorized-only | Own account |
| PMA-108 | phpMyAdmin | CSRF and session: Parallel sessions allowed | authorized-only | Own account |
| PMA-109 | phpMyAdmin | CSRF and session: Referer or Origin validation on state changes | authorized-only | Own account; approval |
| PMA-110 | phpMyAdmin | CSRF and session: Missing or spoofed Referer accepted | authorized-only | Own account; approval |
| PMA-111 | phpMyAdmin | Database access: Enumerate databases after login (own account) | authorized-only | List names and counts only |
| PMA-112 | phpMyAdmin | Database access: Access to `mysql`, `information_schema`, `performance_schema` | authorized-only | Record access; do not dump |
| PMA-113 | phpMyAdmin | Database access: Table list, engine, and size | authorized-only | Metadata only |
| PMA-114 | phpMyAdmin | Database access: Column list; sensitive column names (`password`, `token`, `email`) | authorized-only | Names only |
| PMA-115 | phpMyAdmin | Database access: Data extraction | authorized-only | Minimal rows; redact in the report |
| PMA-116 | phpMyAdmin | Database access: Privileges in `mysql.user`: FILE, SUPER, GRANT | authorized-only | Read privilege flags only |
| PMA-117 | phpMyAdmin | Database access: Privilege escalation attempts | authorized-only | Report feasibility only |
| PMA-118 | phpMyAdmin | Database access: `LOAD_FILE()` | authorized-only | Own instance; approval |
| PMA-119 | phpMyAdmin | Database access: `SELECT ... INTO OUTFILE` | authorized-only | Report feasibility only; never write to a web root |
| PMA-120 | phpMyAdmin | Database access: Create configuration files through SQL | authorized-only | Never on a live system |
| PMA-121 | phpMyAdmin | Database access: Cross-database access to other application databases | authorized-only | Metadata only |
| PMA-122 | phpMyAdmin | Database access: Privilege levels: unauthenticated, limited, admin | authorized-only | Use accounts you own |
| PMA-123 | phpMyAdmin | Known CVE: CVE-2024-2961 iconv: `RecodingEngine = iconv`, glibc, `ISO-2022-CN-EXT` (manual) | passive | Configuration review only |
| PMA-124 | phpMyAdmin | Known CVE: Legacy version list: versions with published advisories (probe: version table) | passive | Version match; read the advisory before reporting |
| PMA-125 | phpMyAdmin | Known CVE: Remote code execution through proxy integration (version and config only) | passive | Version and config review; no exploit |
| PMA-126 | phpMyAdmin | Known CVE: Legacy file upload vulnerability (version only) | passive | Version match |
| PMA-127 | phpMyAdmin | Known CVE: Searchsploit lookup for the detected version (probe with `--searchsploit`; kali) | passive | Offline DB; titles only, never run exploit code |
| PMA-128 | phpMyAdmin | Environment: Hosting: shared, dedicated, or cloud (manual) | passive | Infer from headers and DNS; do not scan beyond scope |
| PMA-129 | phpMyAdmin | Environment: Apache modules and nginx layout (manual) | passive | Headers and error pages only |
| PMA-130 | phpMyAdmin | Environment: PHP extensions, `iconv`, `open_basedir` (manual) | passive | Read from phpinfo only if exposed (PMA-034) |
| PMA-131 | phpMyAdmin | Environment: MySQL or MariaDB version from banner (probe with `--nmap`) | bounded | Banner only; no login |
| PMA-132 | phpMyAdmin | Environment: Integration APIs, webhooks, and backup or monitoring plugins (manual) | passive | Review the UI and JS |
| PMA-133 | phpMyAdmin | Environment: Error log review on your own copy (manual) | passive | Logs you are authorized to read |
| PMA-134 | phpMyAdmin | Environment: Verbose errors and stack traces (probe, same as PMA-041) | bounded | Error response only |
| PMA-135 | phpMyAdmin | Environment: Response timing variance (manual) | bounded | Few requests; do not load-test |
| PMA-136 | phpMyAdmin | Environment: Cross-database and privilege tests (authorized-only) | authorized-only | Approved |
| PMA-137 | phpMyAdmin | Process: Scope verification before each run (probe: `scope_check.sh`) | passive | The probe refuses to run without a scope match |
| PMA-138 | phpMyAdmin | Process: Rate limiting and request budget (probe: `--delay`, `--max-requests`) | passive | Defaults: 0.5 s delay, 200 requests |
| PMA-139 | phpMyAdmin | Process: Evidence capture to `artifacts/` (probe: `--out`) | passive | JSON with redacted snippets only |
| PMA-140 | phpMyAdmin | Process: False-positive check: rerun and confirm by hand (manual) | passive | Two independent runs or a manual request |
| PMA-141 | phpMyAdmin | Process: Report structure: summary, findings by severity, detail, remediation (manual) | passive | Use `references/report_template.md` |
| PMA-142 | phpMyAdmin | Process: Responsible disclosure and no data retention beyond the report | passive | Delete extracted samples after reporting |
| PMA-143 | phpMyAdmin | Process: Version and advisory cross-check before reporting a CVE | passive | Read the vendor advisory (phpmyadmin.net/security) |
