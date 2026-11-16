# Scope Playbooks: Large, Medium, Small (extension)

The router (`scripts/route_target.py`) picks a playbook from the scope file:
- **large**: scope says any asset of the organization is in scope.
- **medium**: wildcard scope such as `*.target.com`.
- **small**: one host or endpoint, or a narrow list.

Every playbook still requires `scripts/scope_check.sh TARGET` before active steps.

## Large scope (whole organization)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SCOPE-L-001 | OSINT | Organization-wide asset discovery (amass intel, chaos) | passive | `amass intel -org '<Org>' -max 100`; `chaos -d <t> -silent` |
| SCOPE-L-002 | OSINT | Acquired and related companies (WHOIS, certificate issuers) | passive | `amass intel -whois -d <t>`; crt.sh issuer review |
| SCOPE-L-003 | OSINT | Subsidiary search queries | passive | Search `<t> subsidiary` (manual) |
| SCOPE-L-004 | Network | Mass port scan of all discovered ranges (rate-limited) | bounded | `mapcidr -l ranges.txt -silent \| naabu -rate 1000 -silent \| httpx -silent` |
| SCOPE-L-005 | Network | Service identification on open ports | bounded | `nmap -sV -sC -iL live-hosts.txt -oA nmap` on approved ranges |
| SCOPE-L-006 | Triage | Group findings by provider and product, then route to tech-stack-audit | passive | `route_target.py --fingerprint <httpx output>` |

## Medium scope (wildcard)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SCOPE-M-001 | Subdomains | Aggressive enumeration (subfinder -all, puredns with resolvers) | bounded | Commands in subdomainenum SKILL.md |
| SCOPE-M-002 | Takeover | Dangling DNS and provider fingerprints | passive | See subdomain-takeover provider_fingerprints.md |
| SCOPE-M-003 | Live hosts | Probe and fingerprint every live host | bounded | `httpx -tech-detect -status-code -cdn` |
| SCOPE-M-004 | Triage | Status-code triage per subdomainenum status_triage_and_dns.md | bounded | Per status family |

## Small scope (single host or endpoint)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SCOPE-S-001 | Content | Exhaustive directory and file fuzzing with limits | bounded | `ffuf -u https://<h>/FUZZ -w raft-large-directories.txt -t 20 -rate 50` |
| SCOPE-S-002 | Crawl | Deep crawl of the host | bounded | `katana -u https://<h> -d 5 -silent \| sort -u` |
| SCOPE-S-003 | Params | Hidden parameter discovery | bounded | `arjun -u https://<h>/<path> -t 10 -oJ params.json` |
| SCOPE-S-004 | Params | Route discovered parameters with `route_target.py --params` | passive | Feed params into skills per routing table |
| SCOPE-S-005 | Auth | Authentication and session tests with two self-owned accounts | authorized-only | See authbypass, session-management, idor |

## Methodology and OSINT extension

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| OSINT-001 | Search engines | Filetype and inurl dorks for env, log, sql, admin, login | passive | `site:<t> filetype:env OR filetype:log OR filetype:sql` |
| OSINT-002 | Search engines | Secrets in dorks (password, api_key, secret) | passive | `site:<t> "password" OR "api_key"`; report, do not use secrets |
| OSINT-003 | Code hosting | GitHub search for org secrets | passive | `site:github.com "<t>" password OR apikey OR secret` |
| OSINT-004 | Paste sites | Paste mentions | passive | `site:pastebin.com "<t>"` |
| OSINT-005 | Shodan | Exposed services for org | passive | `shodan search org:"<Org>" http.title:"admin"` |
| OSINT-006 | Historical | Wayback and CommonCrawl URLs for sensitive paths | passive | `gau --subs <t> \| sort -u` |
| OSINT-007 | Historical | Old JS files with embedded keys | passive | Feed js URLs to jsrecon |
