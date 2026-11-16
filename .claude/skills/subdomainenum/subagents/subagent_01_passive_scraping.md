# Subagent 01: Passive OSINT & Certificate Transparency

## Role & Mission
Responsible for executing non-intrusive, zero-packet-to-target reconnaissance across Certificate Transparency (CT) logs, passive DNS aggregators, threat intelligence platforms, and historical archives.

## Assigned Checklist Tasks (18 Checks)
- **Check 01:** Subfinder with full provider integrations
- **Check 02:** OWASP Amass passive mode with data sources
- **Check 03:** Assetfinder data mining
- **Check 04:** Findomain certificate transparency search
- **Check 06:** DNSdumpster API and scraping
- **Check 07:** `crt.sh` Certificate Transparency query (PostgreSQL & JSON)
- **Check 08:** SecurityTrails API historical and current DNS
- **Check 09:** Wayback Machine CDX API historical subdomains
- **Check 10:** VirusTotal passive DNS domain report
- **Check 11:** Shodan subdomain search & `shosubgo`
- **Check 12:** Censys certificate search API
- **Check 13:** Facebook Certificate Transparency logs
- **Check 24:** Google Transparency Report certificate search
- **Check 34:** ProjectDiscovery Chaos dataset
- **Check 39:** Recon.dev API aggregation
- **Check 43:** BufferOver.run Rapid7 Sonar dataset
- **Check 44:** Common Crawl index search
- **Check 47:** CertSpotter API log stream

---

## Standardized Execution Playbook

### Step 1: Automated Aggregation Tools
```bash
# 1. Subfinder with all active providers
subfinder -d <target> -all -cs -provider-config ~/.config/subfinder/provider-config.yaml -o subfinder.txt

# 2. Amass Passive Enumeration
amass enum -passive -d <target> -config ~/.config/amass/datasources.yaml -o amass.txt

# 3. Assetfinder
assetfinder --subs-only <target> | sort -u > assetfinder.txt

# 4. Findomain
findomain -t <target> -u findomain.txt

# 5. Cero (TLS Subject Alternative Name Scraping)
cero <target> 2>/dev/null | sort -u > cero.txt

# 6. GitHub Subdomains (requires GITHUB_TOKEN)
github-subdomains -d <target> -t "$GITHUB_TOKEN" -o github_subs.txt 2>/dev/null
```

### Step 2: Direct Certificate Transparency (CT) Queries
```bash
# 7. crt.sh JSON parsing
curl -s "https://crt.sh/?q=%25.<target>&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt

# 13. Facebook CT API (requires FB App Token)
curl -s -G "https://graph.facebook.com/certificates" \
  -d "query=<target>" \
  -d "fields=certificates" \
  -d "access_token=$FB_APP_TOKEN" | \
  jq -r '.data[].domains[]' | sort -u > fb_ct.txt

# 24. Google Transparency Report CT Search
curl -s "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain=<target>" | \
  grep -oE "[a-zA-Z0-9._-]+\.<target>" | sort -u > google_ct.txt

# 47. CertSpotter API
curl -s "https://api.certspotter.com/v1/issuances?domain=<target>&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u > certspotter.txt
```

### Step 3: Threat Intelligence & Passive DNS
```bash
# 8. SecurityTrails API
curl -s --request GET \
  --url "https://api.securitytrails.com/v1/domain/<target>/subdomains?children_only=false&include_inactive=true" \
  --header "APIKEY: $SECURITYTRAILS_API_KEY" | \
  jq -r '.subdomains[]' | sed "s/$/.<target>/" > securitytrails.txt

# 10. VirusTotal Passive DNS
curl -s --request GET \
  --url "https://www.virustotal.com/api/v3/domains/<target>/subdomains?limit=40" \
  --header "x-apikey: $VIRUSTOTAL_API_KEY" | \
  jq -r '.data[].id' > virustotal.txt

# 11. Shodan Subdomain Mining (TBHM v4 Haddix Slide 40: shosubgo)
shosubgo -d <target> -s $SHODAN_API_KEY | sort -u > shodan_subs.txt

# 12. Censys Search API
censys subdomains <target> | sort -u > censys.txt

# 34. ProjectDiscovery Chaos
chaos -d <target> -key $CHAOS_KEY -silent > chaos.txt

# 39. Recon.dev
curl -s -H "Authorization: Bearer $RECON_DEV_KEY" \
  "https://recon.dev/api/search?key=<target>" | \
  jq -r '.[].rawDomains[]' | sort -u > recondev.txt
```

### Step 4: Web Archives & Historical Datasets
```bash
# 9 & 41. Wayback Machine CDX API
curl -s "http://web.archive.org/cdx/search/cdx?url=*.<target>/*&output=text&fl=original&collapse=urlkey" | \
  sed -e 's_https*://__' -e 's[/?:].*__' | grep -E "\.<target>$" | sort -u > wayback.txt

# 43. BufferOver.run Rapid7 Sonar
curl -s "https://dns.bufferover.run/dns?q=.<target>" | \
  jq -r '.FDNS_A[], .RDNS[]' 2>/dev/null | cut -d',' -f2 | grep -E "\.<target>$" | sort -u > bufferover.txt

# 44. Common Crawl Index
curl -s "http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.<target>&output=json" | \
  jq -r .url 2>/dev/null | sed -e 's_https*://__' -e 's[/?:].*__' | grep -E "\.<target>$" | sort -u > commoncrawl.txt

# 06. DNSdumpster
# Using Python scraper or DNSdumpster API:
python3 -c "
import requests, re
r = requests.get('https://dnsdumpster.com/')
csrf = re.findall(r'name=\"csrfmiddlewaretoken\" value=\"(.*?)\"', r.text)[0]
cookies = {'csrftoken': csrf}
headers = {'Referer': 'https://dnsdumpster.com/'}
data = {'csrfmiddlewaretoken': csrf, 'targetip': '<target>', 'user': 'free'}
res = requests.post('https://dnsdumpster.com/', cookies=cookies, data=data, headers=headers)
for sub in set(re.findall(r'([a-zA-Z0-9_\-\.]+\.<target>)', res.text)):
    print(sub)
" > dnsdumpster.txt
```

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_01_passive_results.txt`
```bash
cat subfinder.txt amass.txt assetfinder.txt findomain.txt crtsh.txt fb_ct.txt google_ct.txt certspotter.txt securitytrails.txt virustotal.txt shodan_subs.txt censys.txt chaos.txt recondev.txt wayback.txt bufferover.txt commoncrawl.txt dnsdumpster.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:upper:]' '[:lower:]' | grep -E "\.<target>$" | sort -u > artifacts/subagent_01_passive_results.txt
```
