# Dorking Extras

## Operator differences by engine

| Need | Google | Bing | DuckDuckGo |
|---|---|---|---|
| Domain | `site:T` | `site:T` | `site:T` |
| File type | `filetype:pdf` / `ext:pdf` | `filetype:pdf` | `filetype:pdf` |
| In URL | `inurl:admin` | `inurl:admin` (also `instreamset:url:`) | `inurl:admin` |
| In title | `intitle:"x"` | `intitle:"x"` | `intitle:x` |
| In body | `intext:"x"` | `inbody:"x"` | (quoted phrase) |
| Exclude | `-site:www.T` | `-site:www.T` | `-site:www.T` |
| OR | `OR` / `\|` | `OR` | `OR` |

Yandex supports `site:`, `mime:pdf`, `inurl:`, `title:` and often indexes different pages; worth a pass for large targets.

## Useful combinations

```
site:*.T -site:www.T                                   # subdomains Google knows
site:T ext:php inurl:?                                 # parameterised pages
site:T (ext:sql | ext:db | ext:dbf | ext:mdb)
site:T (ext:log | ext:txt) intext:"password"
site:T (ext:env | ext:ini | ext:yml) intext:"DB_PASSWORD"
site:T inurl:"/wp-content/uploads/" ext:(sql|zip|bak)
site:T intitle:"Grafana" | intitle:"Kibana" | intitle:"Jenkins" | intitle:"phpMyAdmin"
site:T inurl:"/actuator" | inurl:"/server-status" | inurl:"/phpinfo"
site:T "Index of /" (backup | .git | .svn)
site:T inurl:redirect= | inurl:url= | inurl:next= | inurl:return=      # open redirect candidates
site:T inurl:id= | inurl:uid= | inurl:user=                            # IDOR candidates
site:s3.amazonaws.com T | site:blob.core.windows.net T | site:storage.googleapis.com T
site:atlassian.net T | site:*.atlassian.net "T"                        # public Jira/Confluence
site:docs.google.com "T" | site:drive.google.com "T"                   # shared Google docs
site:postman.com T | site:documenter.getpostman.com T                  # public API collections
site:jsfiddle.net T | site:codepen.io T | site:replit.com T
```

## GitHub code search (better than `site:github.com`)

Web UI (`github.com/search?type=code&q=...`) or `gh search code`:

```
"T" password
"T" (api_key OR apikey OR secret OR token) NOT test
"T" filename:.env
"T" filename:config extension:yml
org:TARGET_ORG (password OR secret OR token)
"internal.T" OR "corp.T" OR "staging.T"
```

Tools: trufflehog (`trufflehog github --org TARGET_ORG`), gitleaks, GitHub "secret scanning" alerts (owner side). See cloud-supplychain.

## Archives (replacement for `cache:`)

```
https://web.archive.org/web/*/T/*
https://web.archive.org/cdx/search/cdx?url=*.T/*&output=txt&fl=original&collapse=urlkey
https://index.commoncrawl.org/  (CDX index per crawl)
```

Tools: waybackurls, gau, waymore (installed by setup.sh). Filter for `\.(sql|bak|env|log|zip|json|xml|conf|cfg)$`.

## Other OSINT sources

| Source | Use |
|---|---|
| Shodan / Censys / FOFA / ZoomEye | `ssl:"T"`, `hostname:T`, `org:"Target"` for exposed services and panels |
| crt.sh / Certificate Transparency | Subdomains (subdomainenum) |
| Wayback / CommonCrawl | Removed pages and old endpoints |
| Public Postman workspaces | API collections with tokens |
| LinkedIn / job posts | Technologies in use (techfingerprint context) |
| DNSDumpster / SecurityTrails | DNS history |

## GHDB categories (Exploit-DB)

Footholds, Files Containing Usernames, Sensitive Directories, Web Server Detection, Vulnerable Files, Vulnerable Servers, Error Messages, Files Containing Juicy Info, Files Containing Passwords, Sensitive Online Shopping Info, Network or Vulnerability Data, Pages Containing Login Portals, Various Online Devices, Advisories and Vulnerabilities. Browse https://www.exploit-db.com/google-hacking-database and adapt dorks with `site:T`.
