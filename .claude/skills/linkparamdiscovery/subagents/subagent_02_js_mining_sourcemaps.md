# Subagent 02: JavaScript Mining, AST Analysis & Source Maps

## Role & Mission
Responsible for static and dynamic analysis of JavaScript files: extracting buried API paths (`LinkFinder`, `JSParser`), recovering original source code via unmapped Source Maps (`.map`), parsing SPA router tables (React, Angular, Vue), and harvesting hardcoded secrets, constants, and administrative route definitions.

## Assigned Checklist Tasks (8 Checks)
- **Check 04:** Extract all links and paths from JavaScript files using LinkFinder
- **Check 05:** Extract API endpoints from JavaScript bundles via JSParser / AST analysis
- **Check 09:** Analyze JavaScript for internal API routes and hidden parameter names
- **Check 15:** Discover internal API documentation embedded in JS source maps
- **Check 16:** Extract global variables, API tokens, and constants from minified JS
- **Check 17:** Check for exposed JavaScript source map files (`.js.map`) for original code access
- **Check 18:** Analyze Angular/React/Vue compiled templates for route definitions
- **Check 39:** Uncover admin and debug endpoints directly from JavaScript router definitions

---

## Standardized Execution Playbook

### Step 1: LinkFinder & JSParser Endpoint Extraction (Checks 04, 05)
```bash
# 1. Download unique JS files identified by crawlers
mkdir -p artifacts/js_bundles/
cat artifacts/live_js_files.txt | head -n 50 | while read js_url; do
  fname=$(echo "$js_url" | awk -F'/' '{print $NF}' | cut -d'?' -f1)
  [ -z "$fname" ] && fname="bundle_$(date +%s%N).js"
  curl -sL "$js_url" -o "artifacts/js_bundles/${fname}"
done

# 2. Run LinkFinder across all downloaded JS files (Check 04)
for js in artifacts/js_bundles/*.js; do
  python3 linkfinder.py -i "$js" -o cli >> artifacts/linkfinder_endpoints.txt
done
sort -u artifacts/linkfinder_endpoints.txt -o artifacts/linkfinder_endpoints.txt
```

### Step 2: Source Map Discovery & Decompilation (Checks 15, 17)
*High-Impact Audit:* If developers deploy `.js.map` files, the complete unminified, commented TypeScript/React/Vue source code can be fully recovered.

```bash
# 1. Check for .map files in HTTP headers or via appending .map
cat artifacts/live_js_files.txt | head -n 30 | while read js_url; do
  map_url="${js_url}.map"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$STATUS" = "200" ]; then
    echo "[!] CRITICAL: Source Map Exposed: $map_url" >> artifacts/exposed_sourcemaps.txt
    # Download map
    curl -sL "$map_url" -o "artifacts/js_bundles/$(basename $js_url).map"
  fi
done

# 2. Unpack source tree using sourcemapper or unwebpack-sourcemap
mkdir -p artifacts/unpacked_source_code/
for sm in artifacts/js_bundles/*.map; do
  [ -f "$sm" ] && python3 -m unwebpack_sourcemap "$sm" artifacts/unpacked_source_code/
done

# 3. Search unpacked source tree for JSDoc and Swagger API documentation (Check 15)
grep -rnE "(swagger|@api|@param|internal-api|endpoints)" artifacts/unpacked_source_code/ > artifacts/internal_api_docs_found.txt
```

### Step 3: SPA Router Tables & Administrative Routes (Checks 18, 39)
Frontend SPAs register routes in compiled client-side router configurations:

```bash
# Extract React Router, Vue Router, Angular Route tables
python3 -c "
import glob, re, json

route_regex = re.compile(r'path:\s*[\"\\\'](\/[a-zA-Z0-9_\-\/:]+)[\"\\\']')
admin_keywords = ['admin', 'debug', 'manage', 'super', 'dashboard', 'internal', 'portal', 'god', 'root', 'config']

found_routes = set()
admin_routes = set()

for fpath in glob.glob('artifacts/js_bundles/*.js'):
    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        routes = route_regex.findall(content)
        for r in routes:
            found_routes.add(r)
            if any(k in r.lower() for k in admin_keywords):
                admin_routes.add(r)

with open('artifacts/extracted_spa_routes.txt', 'w') as out:
    for r in sorted(found_routes):
        out.write(r + '\n')

with open('artifacts/hidden_admin_routes.txt', 'w') as out:
    for r in sorted(admin_routes):
        out.write(r + '\n')
        print(f'[!] Hidden Admin/Debug SPA Route: {r}')
"
```

### Step 4: Secrets, Variables & Constants Extraction (Check 16)
```bash
# Extract API Keys, Bearer tokens, and configuration objects
for js in artifacts/js_bundles/*.js; do
  grep -oE "(api[_-]?key|secret|token|auth|password|bearer)[\"':= ]+[\"'][a-zA-Z0-9_\-\.]{10,80}[\"']" "$js" >> artifacts/leaked_js_secrets.txt
  # Extract environment configuration constants
  grep -oE "(baseURL|apiHost|endpoint)[\"':= ]+[\"']https?://[^\"']+[\"']" "$js" >> artifacts/client_api_hosts.txt
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_02_js_endpoints.txt`
