# Subagent 04: JavaScript Crawling, Content Discovery & Mobile Artifacts

## Role & Mission
Responsible for extracting subdomains embedded inside dynamic application assets: crawled JavaScript files, source maps, robots.txt, sitemaps, historical archive crawls, mobile application packages (Android APK / iOS IPA), and ad/analytics trackers.

## Assigned Checklist Tasks (5 Checks)
- **Check 21:** Subdomain enumeration from JavaScript files on the main domain
- **Check 31:** Subdomain extraction from `robots.txt` and `sitemap.xml`
- **Check 35:** Subdomain extraction from Android APK and iOS IPA application packages
- **Check 41:** Subdomain extraction via Internet Archive Wayback Machine CDX API (`gau` / `waybackurls`)
- **Check 42:** Ad, analytics, and technology relationship correlation (BuiltWith / Wappalyzer)

---

## Standardized Execution Playbook

### Step 1: Web Walking & JavaScript Scraping (TBHM v4 Slides 25-32 & Check 21)
Modern SPAs (Single Page Applications) bundle API gateways, staging backends, and microservice subdomains directly in client-side JavaScript bundles.

```bash
# 1. Spider and extract all JavaScript files from main seeds
katana -u https://<target> -d 3 -jc -silent | grep -E "\.js(\?.*)?$" | sort -u > js_endpoints.txt

# Also fetch historical JS files from Wayback (Check 41 & AUTOMATION2.0.txt)
echo "<target>" | waybackurls | grep -E "\.js(\?.*)?$" >> js_endpoints.txt
sort -u js_endpoints.txt -o js_endpoints.txt

# 2. Extract subdomains from JS files using SubDomainizer (TBHM Slide 32)
SubDomainizer -u https://<target> -l 3 -o js_subdomains.txt

# 3. Direct Regex extraction across downloaded JS files
python3 -c "
import requests, re, os
with open('js_endpoints.txt') as f:
    urls = [line.strip() for line in f if line.strip()]

pattern = re.compile(r'([a-zA-Z0-9_\-\.]+\.<target>)')
found = set()

for u in urls[:150]: # Scan first 150 JS files
    try:
        r = requests.get(u, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        matches = pattern.findall(r.text)
        for m in matches:
            found.add(m.lower())
    except:
        pass

with open('extracted_from_js.txt', 'w') as out:
    for s in sorted(found):
        out.write(s + '\n')
"
```

### Step 2: Robots.txt & Sitemap.xml Parsing (Check 31)
Developers often restrict crawlers on staging, internal, or dev endpoints in `robots.txt` or expose alternate language/regional subdomains in `sitemap.xml`.

```bash
# Fetch and parse robots.txt
curl -sL "https://<target>/robots.txt" "http://<target>/robots.txt" | \
  grep -oE "([a-zA-Z0-9_\-\.]+\.<target>)" | sort -u > robots_subs.txt

# Fetch and parse sitemap.xml
curl -sL "https://<target>/sitemap.xml" "http://<target>/sitemap.xml" | \
  grep -oE "([a-zA-Z0-9_\-\.]+\.<target>)" | sort -u > sitemap_subs.txt
```

### Step 3: Mobile Application Extraction (Android APK / iOS IPA - Check 35)
Mobile applications frequently hardcode unreleased, legacy, or API-only subdomains that are never referenced on public web pages.

```bash
# When an APK is available:
# 1. Decompile APK
apktool d app.apk -o decompiled_apk/

# 2. Regex search for target subdomains in smali, xml, and strings
grep -Eroh "([a-zA-Z0-9_\-\.]+\.<target>)" decompiled_apk/ | tr '[:upper:]' '[:lower:]' | sort -u > mobile_apk_subs.txt

# When an IPA is available:
# Unzip IPA and grep binary and plist files
unzip -q app.ipa -d decompiled_ipa/
strings decompiled_ipa/Payload/*.app/* | grep -oE "([a-zA-Z0-9_\-\.]+\.<target>)" | sort -u > mobile_ipa_subs.txt
```

### Step 4: URL Archive Indexing (Check 41)
```bash
# Extract all subdomains ever seen by AlienVault, Wayback, and CommonCrawl
gau --subs <target> --providers wayback,commoncrawl,otx | \
  unfurl -u domains | grep -E "\.<target>$" | sort -u > gau_subs.txt
```

### Step 5: Ad & Analytics Tracker Correlation (TBHM v4 Slide 18 & Check 42)
*Methodology:* Many organizations use the same Google Analytics (UA-XXXXX / G-XXXXX), Tag Manager (GTM-XXXXX), New Relic, or Segment IDs across all their web properties and subdomains.

```bash
# Correlate via BuiltWith API or public scraping
curl -s "https://api.builtwith.com/v20/api.json?KEY=$BUILTWITH_KEY&LOOKUP=<target>" | \
  jq -r '.Results[].Result.Paths[].SubDomain' | sed "s/$/.<target>/" > builtwith_subs.txt
```

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_04_js_content_results.txt`
```bash
cat js_subdomains.txt extracted_from_js.txt robots_subs.txt sitemap_subs.txt mobile_apk_subs.txt mobile_ipa_subs.txt gau_subs.txt builtwith_subs.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:upper:]' '[:lower:]' | grep -E "\.<target>$" | sort -u > artifacts/subagent_04_js_content_results.txt
```
