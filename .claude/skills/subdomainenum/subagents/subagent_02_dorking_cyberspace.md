# Subagent 02: Search Engine Dorking & Cyberspace Engines

## Role & Mission
Responsible for harvesting subdomains leaked through public search engines, global cyberspace scanners (FOFA, ZoomEye), code repositories (GitHub/GitLab), and developer forums using automated queries and negative filtering loops.

## Assigned Checklist Tasks (9 Checks)
- **Check 14:** Google dorking with recursive exclusion (`site:target.com -www`)
- **Check 15:** Bing dorking for supplemental index discovery
- **Check 16:** Yahoo & DuckDuckGo search engine diversity
- **Check 30:** Sublist3r multi-engine scraping
- **Check 32:** GitHub and GitLab code repository subdomain search
- **Check 33:** Stack Overflow & developer forum search
- **Check 48:** FOFA search engine queries
- **Check 49:** ZoomEye cyberspace search queries
- **Check 50:** DorkAssistant / automated dorking loop

---

## Standardized Execution Playbook

### Step 1: Recursive Search Engine Dorking (TBHM v4 Haddix Slide 35)
*Methodology:* Never stop at the first Google page. Extract subdomains, then recursively subtract them using `-subdomain` until zero results are returned.

```bash
# Manual or Automated Recursive Exclusion Pattern:
# Iteration 1: site:<target> -www.<target>
# Iteration 2: site:<target> -www.<target> -mail.<target>
# Iteration 3: site:<target> -www.<target> -mail.<target> -dev.<target>
# Continue until Google returns no results.

# Automated Dorking using DorkAssistant or degoogle:
python3 -m pip install degoogle
degoogle -j "site:<target>" | jq -r '.[].url' | sed -e 's_https*://__' -e 's[/?:].*__' | grep -E "\.<target>$" | sort -u > google_dork_subs.txt
```

### Step 2: Multi-Engine Scraping with Sublist3r
```bash
# Check 30: Run sublist3r across Google, Yahoo, Bing, Baidu, Ask
python3 sublist3r.py -d <target> -t 15 -v -o sublist3r.txt
```

### Step 3: Cyberspace Search Engines (FOFA & ZoomEye)
Cyberspace search engines index SSL certificates, HTTP headers, and raw HTML across the entire IPv4/IPv6 internet.

```bash
# Check 48: FOFA (API / CLI)
# Query syntax: domain="<target>"
fofa search 'domain="<target>"' --fields host | sed -e 's_https*://__' -e 's[/?:].*__' | grep -E "\.<target>$" | sort -u > fofa_subs.txt

# Or via FOFA API directly:
FOFA_QUERY=$(echo -n 'domain="<target>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$FOFA_QUERY" | \
  jq -r '.results[][0]' | sed -e 's_https*://__' -e 's[/?:].*__' | sort -u > fofa_api.txt

# Check 49: ZoomEye Search
zoomeye search "site:<target>" -num 500 | grep -oE "([a-zA-Z0-9._-]+\.<target>)" | sort -u > zoomeye.txt
```

### Step 4: Code Repository Mining (TBHM v4 Haddix Slide 39 Rule)
*Methodology:* Developers regularly leak staging, dev, and internal subdomains in code, documentation, CI/CD pipelines, and `.env.example` files.
*Critical TBHM Rule:* The GitHub API returns randomized subsets and has strict secondary rate limits. Always iterate 5 times with a 6-second sleep between queries, rotating Personal Access Tokens (PATs).

```bash
# Check 32: GitHub Subdomain Scraping
python3 github-subdomains.py -d <target> -t $GITHUB_TOKEN -o github_subs.txt

# GitLab API Scraping
curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects?search=<target>&per_page=100" | \
  grep -oE "([a-zA-Z0-9._-]+\.<target>)" | sort -u > gitlab_subs.txt
```

### Step 5: Developer Forum & Stack Overflow Intelligence
```bash
# Check 33: Dorking Developer Forums
# Search StackOverflow, Pastebin, and Gist for target subdomain mentions
curl -s "https://api.stackexchange.com/2.3/search/excerpts?order=desc&sort=relevance&q=<target>&site=stackoverflow" | \
  grep -oE "([a-zA-Z0-9._-]+\.<target>)" | sort -u > stackoverflow_subs.txt

# Google Dork for Pastebin / GitHub Gists:
# site:pastebin.com "<target>"
# site:gist.github.com "<target>"
```

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_02_dorking_results.txt`
```bash
cat google_dork_subs.txt sublist3r.txt fofa_subs.txt fofa_api.txt zoomeye.txt github_subs.txt gitlab_subs.txt stackoverflow_subs.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:upper:]' '[:lower:]' | grep -E "\.<target>$" | sort -u > artifacts/subagent_02_dorking_results.txt
```
