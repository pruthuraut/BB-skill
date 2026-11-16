# Status-Code Triage, Enumeration Methodology, and DNS Checks (extension)

Class key: `passive` = OSINT, DNS, or certificate data only. `bounded` = one or two GET requests per host. Bypass attempts on 403 are `bounded` only for headers that are already documented behaviour; anything that changes server state is out of scope.

## Methodology: enumeration sources

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SUB-M-001 | Passive sources | Certificate transparency (crt.sh) | passive | `curl -s 'https://crt.sh/?q=%25.<target>&output=json' \| jq` |
| SUB-M-002 | Passive sources | subfinder, assetfinder, chaos | passive | `subfinder -d <t> -all -silent`; `chaos -d <t> -silent` if key present |
| SUB-M-003 | Passive sources | Historical URL and host sources (gau, waybackurls) | passive | `gau --subs <t>` |
| SUB-M-004 | Org-level | Acquisitions and subsidiaries (amass intel -org, whois org search) | passive | `amass intel -org '<Org>' -max 100` |
| SUB-M-005 | Org-level | Reverse WHOIS for related domains | passive | `amass intel -whois -d <t>` |
| SUB-M-006 | Search | Search-engine dorks for subdomains | passive | `site:<t> -www` review |
| SUB-M-007 | Brute force | DNS brute force with resolver pool | bounded | `puredns bruteforce <wordlist> <t> -r resolvers.txt` (rate limited) |
| SUB-M-008 | Permutation | alterx and gotator permutations of discovered names | bounded | `alterx -d <t> -list found.txt \| dnsx -silent` |
| SUB-M-009 | Resolution | Resolve and keep live hosts | bounded | `dnsx -a -resp -silent` then `httpx -silent` |
| SUB-M-010 | Probing | Title, tech, status for each live host | bounded | `httpx -title -tech-detect -status-code -silent` |
| SUB-M-011 | Wildcard | Detect wildcard DNS before brute force | passive | Resolve random 20-char label; skip brute-force results that match wildcard IP |

## Status-code triage

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SUB-403-001 | 403 host | Method variation (POST, PUT, OPTIONS) reveals different behaviour | bounded | Status and Allow header per method |
| SUB-403-002 | 403 host | Forwarding headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL) changes result | bounded | One request per header, compare status and body length |
| SUB-403-003 | 403 host | Path normalization (`/..;/`, `/./`, `//`, case change, `%2f`) changes result | bounded | Compare status and body length per variant |
| SUB-404-001 | 404 host | Directory fuzzing behind 404 for hidden endpoints | bounded | `ffuf -u https://<h>/FUZZ -w common.txt -fc 404` with rate limit |
| SUB-404-002 | 404 host | Custom 404 leaks framework, stack, or version | passive | Read body of a random missing path; grep for version and trace text |
| SUB-301-001 | 301 host | Redirect chain reveals staging or internal origin | passive | `curl -sIL` record Location chain |
| SUB-301-002 | 301 host | Open redirect via header injection | bounded | See open-redirect-and-header-injection OR-001 |
| SUB-302-001 | 302 host | Redirect parameter (redirect, next, returnUrl) takes external host | bounded | See open-redirect-and-header-injection OR-001 |
| SUB-302-002 | 302 host | OAuth callback redirect_uri bypass | bounded | See oauth-sso |
| SUB-200-001 | 200 host | Full directory and API enumeration | bounded | `ffuf` or `gobuster` with rate limit on owned scope only |
| SUB-200-002 | 200 host | Technology fingerprint | passive | Headers, cookies, page content (`whatweb`) |
| SUB-200-003 | 200 host | Sensitive files: .git, .env, sitemap, robots, backups, admin panels | bounded | GET each path; record status and size only |

## DNS

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| DNS-001 | Zone | AXFR allowed from nameserver | bounded | `dig axfr <t> @ns1.<t>`; only if the program allows zone checks |
| DNS-002 | Zone | Records enumeration via dnsrecon and dnsenum | bounded | `dnsrecon -d <t> -t std` |
| DNS-003 | DNSSEC | Signing missing or broken | passive | `dig +dnssec <t>` |
| DNS-004 | Email DNS | SPF, DKIM, DMARC records | passive | See email-security-audit |
| DNS-005 | Dangling | CNAME to unclaimed service | passive | See subdomain-takeover |
