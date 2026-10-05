# Subagent 01: Automated Crawlers & Linked Discovery

## Role & Mission
Responsible for comprehensive active crawling, link traversal, DOM parsing, client-side hash routing extraction, and cross-origin frame harvesting using headless browsers and command-line spiders (`katana`, `hakrawler`, `gospider`).

## Assigned Checklist Tasks (5 Checks)
- **Check 01:** Comprehensive web crawling and URL discovery via `katana`
- **Check 02:** Fast CLI web crawling with depth control via `hakrawler`
- **Check 03:** Site mapping and link spidering via `gospider` / Burp Suite spider
- **Check 10:** Discover client-side URL fragments and hash-based routing (`#/path`)
- **Check 25:** Harvest `iframe` and `embed` source URLs for cross-origin assets

---

## Standardized Execution Playbook

### Step 1: Katana Headless & Standard Crawling (Check 01)
`katana` is a next-generation crawling engine supporting headless Chrome rendering, JavaScript parsing, and form field extraction:

```bash
# High-concurrency headless crawling with automatic form fill and JavaScript scraping
katana -u "https://<target>" \
  -depth 5 \
  -jc \
  -jsl \
  -kf all \
  -aff \
  -concurrency 25 \
  -silent \
  -o artifacts/katana_discovered_urls.txt

# Multi-host automated crawling loop
head -n 25 artifacts/live_subdomains.txt | while read -r HOST; do
  SAFE_NAME=$(echo "$HOST" | tr '/:' '_')
  katana -u "$HOST" -jc -jsl -d 5 -kf all -aff -silent -o "artifacts/katana_${SAFE_NAME}.txt" 2>/dev/null
  gospider -s "$HOST" -d 3 --js -q 2>/dev/null | grep -oP 'https?://[^\s"'"'"']+' >> artifacts/all_discovered_urls.txt
  echo "$HOST" | hakrawler -d 3 -subs 2>/dev/null >> artifacts/all_discovered_urls.txt
done
```

### Step 2: Hakrawler Fast Link Traversal (Check 02 & TBHM Slide 31)
```bash
# Fast link traversal with controlled depth
echo "https://<target>" | hakrawler -depth 3 -plain -subs > artifacts/hakrawler_urls.txt
```

### Step 3: Historical URL Ingestion (waybackurls & gau)
```bash
# Query Wayback Machine archive endpoints
echo "<target>" | waybackurls > artifacts/wayback_discovered_urls.txt

# Multi-provider historical archive harvesting (Common Crawl, OTX, Wayback)
gau "<target>" --subs --providers wayback,commoncrawl,otx > artifacts/gau_discovered_urls.txt
```

### Step 4: GoSpider / Recursive Spidering (Check 03)
```bash
# Multi-source recursive spidering (mines robots, sitemaps, JS links)
gospider -s "https://<target>" \
  -d 3 \
  -c 15 \
  --other-source \
  --include-subs \
  -o artifacts/gospider_out/
```

### Step 5: Client-Side Hash Routing & Fragment Extraction (Check 10)
Single Page Applications utilizing React Router `HashRouter` or Vue Router often route through hash fragments (`/#/admin`, `/#/settings`):

```bash
# Extract hash routes from crawled URLs and HTML sources
grep -oE "https?://[^\"' ]+#[a-zA-Z0-9_\-\/]+" artifacts/katana_discovered_urls.txt > artifacts/hash_routes.txt

# Extract hash route definitions directly from client-side bundles
grep -oE "path: *['\"]#?\/[a-zA-Z0-9_\-\/]+['\"]" artifacts/katana_discovered_urls.txt >> artifacts/hash_routes.txt
sort -u artifacts/hash_routes.txt -o artifacts/hash_routes.txt
```

### Step 6: Iframe & Embedded Cross-Origin Asset Harvesting (Check 25)
```bash
# Extract iframe and embed tags to uncover embedded third-party panels or sandbox domains
python3 -c "
import requests, re
try:
    r = requests.get('https://<target>', timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
    iframes = re.findall(r'<iframe[^>]+src=[\"\\\']([^\"\\\']+)[\"\\\']', r.text, re.IGNORECASE)
    embeds = re.findall(r'<embed[^>]+src=[\"\\\']([^\"\\\']+)[\"\\\']', r.text, re.IGNORECASE)
    with open('artifacts/embedded_frames.txt', 'w') as f:
        for item in set(iframes + embeds):
            f.write(item + '\n')
            print(f'Embedded frame: {item}')
except:
    pass
"
```

### Step 7: Extension Sorting & Dedicated Separation (.js, .json, .xml, parameters)
*Automated sorting pattern from TBHM Lecture Recon & AUTOMATION2.0:*
Once all crawled and historical URLs are aggregated from `katana`, `hakrawler`, `gau`, and `waybackurls`, separate them into dedicated files for targeted analysis:

```bash
# Combine and deduplicate all discovered URLs
cat artifacts/katana_discovered_urls.txt artifacts/hakrawler_urls.txt artifacts/wayback_discovered_urls.txt artifacts/gau_discovered_urls.txt 2>/dev/null | sort -u > artifacts/all_discovered_urls.txt

# 1. Separate JavaScript URLs into their own dedicated file
grep -E "\.js(\?.*)?$" artifacts/all_discovered_urls.txt | sort -u > artifacts/js_files.txt

# Probe live JavaScript files and save to live list
httpx -l artifacts/js_files.txt -mc 200 -silent > artifacts/live_js_files.txt

# 2. Download and store .js files locally in a dedicated directory for AST / LinkFinder analysis
mkdir -p artifacts/js_bundles/
cat artifacts/live_js_files.txt | head -n 100 | while read js_url; do
  fname=$(echo "$js_url" | awk -F'/' '{print $NF}' | cut -d'?' -f1)
  [ -z "$fname" ] && fname="bundle_$(date +%s%N).js"
  curl -sL "$js_url" -o "artifacts/js_bundles/${fname}"
done

# 3. Separate JSON & XML endpoints
grep -E "\.(json|xml)(\?.*)?$" artifacts/all_discovered_urls.txt | sort -u > artifacts/data_endpoints.txt

# 4. Separate parameterized URLs for fuzzing (Check 06, 08)
grep "=" artifacts/all_discovered_urls.txt | sort -u > artifacts/parameter_urls.txt
```

---

## Output Artifacts
Aggregate findings into:
- `artifacts/subagent_01_crawler_links.txt` — All verified links.
- `artifacts/js_files.txt` & `artifacts/live_js_files.txt` — Separated JavaScript URL inventory.
- `artifacts/js_bundles/` — Dedicated directory containing downloaded `.js` scripts.
- `artifacts/parameter_urls.txt` — URLs containing query parameters ready for parameter mining.
