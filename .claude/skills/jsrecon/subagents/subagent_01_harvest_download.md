# Subagent 01: Multi-Source JavaScript Harvesting, Extension Sorting & Parallel Downloads

## Role & Mission
Execute exhaustive, multi-source JavaScript asset discovery across both historical internet archives (Wayback Machine CDX API, AlienVault OTX, Common Crawl via `gau`) and active headless web crawlers (`katana`, `hakrawler`, `gospider`). Deduplicate assets, deterministically isolate `.js`, `.json`, and `.xml` files, verify live status via `httpx`, and download bundles locally for static code review.

---

## 1. Artifact Inheritance & Prior Agent Output Ingestion (Zero-Redundancy Mode)

**Core Principle:** *Never repeat reconnaissance work that previous agents have already completed.* 

Before running any network queries or crawling tools, Subagent 01 checks for artifacts produced by prior agents:

```bash
mkdir -p artifacts/js_recon/

# Check 1: Ingest live subdomains from subdomainenum agent
if [ -s "artifacts/live_subdomains.txt" ]; then
  echo "[+] Reusing existing subdomains from subdomainenum agent..."
  cp artifacts/live_subdomains.txt artifacts/js_recon/live_hosts.txt
elif [ -s "live_hosts.txt" ]; then
  cp live_hosts.txt artifacts/js_recon/live_hosts.txt
else
  # Fallback: Only run subdomain enumeration if no prior artifacts exist
  echo "[*] No prior subdomains artifact found. Running initial subdomain resolution..."
  cat wildcards.txt 2>/dev/null | assetfinder --subs-only | sort -u > artifacts/js_recon/subdomains_raw.txt
  subfinder -dL wildcards.txt -t 100 -silent >> artifacts/js_recon/subdomains_raw.txt 2>/dev/null
  sort -u artifacts/js_recon/subdomains_raw.txt | httpx -silent -mc 200,301,302 > artifacts/js_recon/live_hosts.txt
fi

# Check 2: Ingest already-harvested URLs from contentdiscovery & linkparamdiscovery
PREV_URLS=""
[ -s "artifacts/all_discovered_urls.txt" ] && PREV_URLS="$PREV_URLS artifacts/all_discovered_urls.txt"
[ -s "artifacts/discovered_endpoints.txt" ] && PREV_URLS="$PREV_URLS artifacts/discovered_endpoints.txt"
[ -s "artifacts/js_files.txt" ] && PREV_URLS="$PREV_URLS artifacts/js_files.txt"
[ -s "artifacts/subagent_01_crawler_links.txt" ] && PREV_URLS="$PREV_URLS artifacts/subagent_01_crawler_links.txt"

if [ -n "$PREV_URLS" ]; then
  echo "[+] Ingesting URLs previously gathered by contentdiscovery and linkparamdiscovery..."
  cat $PREV_URLS | grep -E "\.(js|mjs)(\?.*)?$" | sed -E 's/[?#].*$//' | sort -u > artifacts/js_recon/js_urls_inherited.txt
  echo "    -> Ingested $(wc -l < artifacts/js_recon/js_urls_inherited.txt) JS URLs from earlier steps!"
fi
```

---

## 2. Gap-Filling Discovery (Only for New/Uncrawled Assets)
If running in standalone mode or augmenting existing crawl depth:

# 1. Historical Wayback Machine CDX API query
cat live_hosts.txt | while read host; do
  curl -sS --max-time 30 -A "Mozilla/5.0" \
    "http://web.archive.org/cdx/search/cdx?url=*.${host}/*&output=text&fl=original&collapse=urlkey" >> artifacts/js_recon/urls_wayback.txt
done

# 2. Multi-provider historical harvesting via GAU
gau --subs --threads 10 < live_hosts.txt > artifacts/js_recon/urls_gau.txt
```

### Step 2: Active Headless & Recursive Crawling
```bash
# 3. Active crawling with JavaScript parsing and form extraction
katana -list live_hosts.txt -d 3 -jc -kf -fx -automatic-form-fill -concurrency 25 -silent > artifacts/js_recon/urls_katana.txt

# 4. Fast link traversal
cat live_hosts.txt | hakrawler -depth 2 -plain -subs > artifacts/js_recon/urls_hakrawler.txt
```

---

## 3. Deterministic Extension Sorting & Separation
*Rule: Never analyze raw URLs in bulk. Systematically partition extensions into dedicated artifacts:*

```bash
# Combine and deduplicate all discovered URLs
cat artifacts/js_recon/urls_*.txt | sort -u > artifacts/js_recon/all_discovered_urls.txt

# 1. Isolate JavaScript bundles (.js, .mjs)
grep -E "\.(js|mjs)(\?.*)?$" artifacts/js_recon/all_discovered_urls.txt | \
  sed -E 's/[?#].*$//' | sort -u > artifacts/js_recon/js_urls_all.txt

# 2. Isolate JSON & XML data endpoints
grep -E "\.(json|xml)(\?.*)?$" artifacts/js_recon/all_discovered_urls.txt | sort -u > artifacts/js_recon/data_endpoints.txt

# 3. Isolate parameterized URLs for parameter mining & fuzzing
grep "=" artifacts/js_recon/all_discovered_urls.txt | sort -u > artifacts/js_recon/parameter_urls.txt
```

---

## 4. Live Verification & High-Concurrency Downloading

```bash
# 1. Probe JS URLs with httpx to filter live 200 OK responses
httpx -l artifacts/js_recon/js_urls_all.txt -mc 200 -silent > artifacts/js_recon/live_js_urls.txt

# 2. High-speed parallel download worker
mkdir -p artifacts/js_recon/js_raw/

cat artifacts/js_recon/live_js_urls.txt | head -n 500 | while read url; do
  # Hash naming prevents filename collisions and long URL errors
  h=$(printf '%s' "$url" | sha1sum | cut -c1-10)
  b=$(basename "$url" | cut -d'?' -f1 | tr -c 'A-Za-z0-9._-' '_')
  [ -z "$b" ] && b="index.js"
  
  curl -sSL --max-time 15 --compressed -A "Mozilla/5.0" \
    -o "artifacts/js_recon/js_raw/${h}_${b}" "$url"
done
```

---

## Output Artifacts
- `artifacts/js_recon/all_discovered_urls.txt` — Deduplicated master URL catalog.
- `artifacts/js_recon/live_js_urls.txt` — Verified HTTP 200 JavaScript URLs.
- `artifacts/js_recon/data_endpoints.txt` — Harvested `.json` and `.xml` API endpoints.
- `artifacts/js_recon/parameter_urls.txt` — Parameterized query URLs.
- `artifacts/js_recon/js_raw/` — Directory containing downloaded `.js` files.
