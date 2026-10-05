# Subagent 02: Historical Crawling, JS Extraction & Public OSINT Leaks

## Role & Mission
Responsible for mining historical URL archives (Wayback Machine, Common Crawl, AlienVault OTX), deeply analyzing JavaScript files for hidden API endpoints/secrets, mapping staging/dev environments on subdomains, and dorking public cloud document leaks (Google Docs/Sheets).

## Assigned Checklist Tasks (5 Checks)
- **Check 22:** Check for staging/dev environments on subdomains (`dev.`, `staging.`, `test.`, `uat.`)
- **Check 23:** Search for publicly accessible Google Docs and Google Sheets with sensitive target data
- **Check 24:** `waybackurls` historical endpoint discovery
- **Check 25:** `gau` multi-source URL harvesting (Wayback, Common Crawl, AlienVault OTX)
- **Check 26:** Systematic extraction of URLs and endpoints from all JavaScript files

---

## Standardized Execution Playbook

### Step 1: Historical Archive URL Scraping (Checks 24, 25 & AUTOMATION2.0.txt)
```bash
# 1. Fetch historical endpoints via waybackurls (Check 24)
echo "<target>" | waybackurls > artifacts/wayback_urls.txt

# 2. Comprehensive archive gathering via gau (Check 25)
gau <target> --providers wayback,commoncrawl,otx --subs > artifacts/gau_urls.txt

# 3. Deep Waymore archive extraction (Wayback Machine, Common Crawl, AlienVault)
waymore -i "<target>" -mode U -oU artifacts/waymore_urls.txt 2>/dev/null

# 4. Deduplicate and clean URLs
cat artifacts/wayback_urls.txt artifacts/gau_urls.txt artifacts/waymore_urls.txt 2>/dev/null | sort -u > artifacts/historical_urls.txt

# Filter out static media extensions to highlight actionable endpoints
grep -Ev "\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|eot|ico)$" artifacts/historical_urls.txt > artifacts/historical_endpoints.txt

# 5. High-Impact Juicy Extension Filter
grep -iE '\.(bak|backup|sql|db|sqlite|json|xml|yaml|yml|env|config|conf|log|old|gz|zip|tar|7z|rar|pdf|xls|xlsx|doc|docx|csv|pem|key|crt|p12|pfx|jks)(\?|$)' \
  artifacts/historical_urls.txt | sort -u > artifacts/juicy_extensions.txt

# 6. Immediate Live Verification of Discovered Juicy Files (Check if still accessible)
httpx -l artifacts/juicy_extensions.txt -mc 200,206,301,302 -follow-redirects \
  -o artifacts/juicy_live_confirmed.txt -silent
```

### Step 2: Systematic JavaScript Scraping & Endpoint Extraction (Check 26)
*Methodology from AUTOMATION2.0.txt & TBHM Module 09:*

```bash
# 1. Deduplicate master URL collection from archives (gau, waybackurls) and active spiders (katana)
cat artifacts/historical_urls.txt | sort -u > artifacts/all_discovered_urls.txt

# 2. Automated Category Sorting (API, DB, Admin, Debug, PHP, JS, Auth, Sensitive, IDOR, Params)
mkdir -p artifacts/sorted_categories/

# Execute high-speed category sorting script:
python3 .agents/skills/contentdiscovery/scripts/endpoint_sorter.py \
  -i artifacts/all_discovered_urls.txt \
  -o artifacts/sorted_categories/

# Dedicated Category Extraction Commands (Bash / Grep):
# • API Endpoints (REST, GraphQL, Swagger, OpenAPI)
grep -iE "/(api|v[0-9]+|graphql|gql|rest|jsonrpc|swagger|openapi)/|\.(json|wsdl)(\?.*)?$" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/api_urls.txt

# • Admin & Management Consoles (Staff, Dashboard, Portal)
grep -iE "/(admin|administrator|adm|backend|dashboard|staff|moderator|manager|portal|cpanel)/" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/admin_urls.txt

# • Debug, Test & Metrics (Actuator, Profiler, Health, Status, Dev, Stage)
grep -iE "/(debug|trace|status|metrics|health|actuator|info|test|demo|dev|stage|profiler|phpinfo)/" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/debug_urls.txt

# • Database Files & Management (phpMyAdmin, Adminer, .sql, .db, .sqlite dumps)
grep -iE "/(phpmyadmin|adminer|pma|dbadmin)/|\.(sql|db|sqlite|dump)(\?.*)?$" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/db_urls.txt

# • PHP Endpoints (.php, .phtml, legacy handlers)
grep -iE "\.php[0-9]?(\?.*)?$" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/php_urls.txt

# • Authentication & Session Routes (Login, Signup, Reset, 2FA, OAuth, SAML)
grep -iE "/(login|signin|auth|oauth|sso|saml|register|signup|password|reset|2fa|otp|verify)/" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/auth_urls.txt

# • Sensitive Files, Configs & Backups (.env, .git, .yml, .bak, .zip)
grep -iE "(\.env|\.git|\.htaccess|\.aws|\.npmrc|web\.config|\.bak|\.zip|\.tar|\.conf|\.ya?ml)(\?.*)?$" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/sensitive_urls.txt

# • File Upload & Attachment Handlers
grep -iE "/(upload|uploader|uploads|file-upload|attachment|media|avatar|import)/" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/upload_urls.txt

# • IDOR / BOLA Parameterized Routes (Numeric IDs or UUIDs)
grep -iE "/[a-zA-Z0-9_\-]+/([0-9]{1,10}|[0-9a-fA-F-]{36})(/|$|\?)" \
  artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/idor_urls.txt

# • Parameterized Query URLs (for SSRF, XSS, SQLi parameter mining)
grep "=" artifacts/all_discovered_urls.txt | sort -u > artifacts/sorted_categories/params_urls.txt

# • JavaScript Files (.js, .mjs)
grep -iE "\.(js|mjs)(\?.*)?$" artifacts/all_discovered_urls.txt | sort -u > artifacts/js_files.txt

# 2. Probe JS files with httpx to filter live 200 OK responses
httpx -l artifacts/js_files.txt -mc 200 -silent > artifacts/live_js_files.txt

# 3. Store JS files locally in dedicated folder for offline AST and secret inspection
mkdir -p artifacts/js_bundles/
cat artifacts/live_js_files.txt | head -n 100 | while read js_url; do
  fname=$(echo "$js_url" | awk -F'/' '{print $NF}' | cut -d'?' -f1)
  [ -z "$fname" ] && fname="bundle_$(date +%s%N).js"
  curl -sL "$js_url" -o "artifacts/js_bundles/${fname}"
done

# 4. Extract API endpoints, paths, and secrets from live JS bundles
python3 -c "
import requests, re

with open('artifacts/live_js_files.txt') as f:
    urls = [line.strip() for line in f if line.strip()]

endpoint_pattern = re.compile(r'\"(\/[a-zA-Z0-9_\-\/]{2,100})\"|\'(\/[a-zA-Z0-9_\-\/]{2,100})\'')
discovered_endpoints = set()

for u in urls[:200]:
    try:
        res = requests.get(u, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        matches = endpoint_pattern.findall(res.text)
        for m1, m2 in matches:
            ep = m1 or m2
            if not ep.endswith(('.png', '.jpg', '.css', '.svg', '.woff')):
                discovered_endpoints.add(ep)
    except:
        pass

with open('artifacts/js_extracted_endpoints.txt', 'w') as out:
    for ep in sorted(discovered_endpoints):
        out.write(ep + '\n')
"
```

### Step 3: Staging & Dev Subdomain Identification (Check 22)
Identify non-production environments that often feature disabled authentication, verbose errors, or outdated code:

```bash
# Filter live subdomains for staging identifiers
grep -Ei "(dev|stage|staging|test|qa|uat|preprod|demo|sandbox|internal|corp)" artifacts/live_subdomains.txt > artifacts/staging_environments.txt

if [ -s "artifacts/staging_environments.txt" ]; then
  echo "[!] High Value Targets: Staging/Dev Environments Discovered:"
  cat artifacts/staging_environments.txt
fi
```

### Step 4: Public Google Docs & Sheets Dorking (Check 23)
Search for inadvertently shared spreadsheets or documents containing employee credentials, API tokens, or internal architecture:

```bash
# Dork queries for Google Docs / Sheets
# 1. site:docs.google.com/spreadsheets/ "<target>"
# 2. site:docs.google.com/document/ "<target>" password OR credential OR token OR internal
# 3. site:drive.google.com "<target>"

python3 -m pip install degoogle 2>/dev/null
degoogle -j "site:docs.google.com/spreadsheets/ \"<target>\"" > artifacts/google_sheets_leaks.json
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_02_osint_endpoints.txt`
