# Subagent 04: Deep Endpoint Extraction, Parameter Mining & Architectural Analysis

## Role & Mission
Responsible for extracting hidden routes, unlinked API endpoints, client-side SPA routing tables (React Router, Vue Router, Angular), object body keys, and query parameters from JavaScript. Deduplicates routes, cleans CDN false positives, and classifies endpoints by sensitivity and privilege tier.

---

## 1. The 6-Way Endpoint Extraction Suite

*Methodology: Never rely on a single regex. Combine 6 complementary extraction approaches:*

```bash
mkdir -p artifacts/js_recon/endpoints/

# WAY 1: Absolute Paths starting with /
grep -roE "['\"](\/[a-zA-Z0-9\-_\.\/]{2,100})['\"]" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  sed "s/['\"]//g" | awk -F: '{print $NF}' | sort -u > artifacts/js_recon/endpoints/endpoints_abs.txt

# WAY 2: High-Value Keywords (api, v1, v2, internal, admin, staff, graphql, debug)
grep -roE "['\"](\/(api|v1|v2|v3|internal|admin|staff|graphql|console|debug)\/[^'\"]+)['\"]" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  sed "s/['\"]//g" | awk -F: '{print $NF}' | sort -u > artifacts/js_recon/endpoints/endpoints_high.txt

# WAY 3: Dynamic Paths with Template Variables (${id}, ${userId})
grep -roE "['\"`](\/[a-zA-Z0-9\-_\.\/]*\$\{[a-zA-Z0-9_-]+\}[a-zA-Z0-9\-_\.\/]*)['\"`]" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  sed "s/['\"`]//g" | awk -F: '{print $NF}' | sort -u > artifacts/js_recon/endpoints/endpoints_dynamic.txt

# WAY 4: Raw URLs without quotes (embedded base URLs)
grep -roE "(https?://)?[a-zA-Z0-9.-]+/(api|v1|internal)/[^\"')\s]+" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  awk -F: '{print $NF}' | sort -u > artifacts/js_recon/endpoints/endpoints_raw.txt

# WAY 5: React / Vue Router definitions (path: "/dashboard")
grep -roE "path\s*:\s*['\"][^'\"]+['\"]" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  sed "s/path\s*:\s*['\"]//;s/['\"]//" | awk -F: '{print $NF}' | sort -u > artifacts/js_recon/endpoints/endpoints_routes.txt

# WAY 6: CDN False-Positive Cleansing & Master Merging
cat artifacts/js_recon/endpoints/endpoints_*.txt | \
  grep -vE "(cdnjs|googleapis|jquery|bootstrap|react|angular|lodash|moment|npm|github|sentry)" | \
  sort -u > artifacts/js_recon/ALL_FINAL_ENDPOINTS.txt
```

---

## 2. Parameter Mining (Body Keys & Query Strings)

Identify parameters expected by hidden endpoints for BOLA/IDOR, Mass Assignment, and Parameter Tampering testing:

```bash
# 1. Object Parameters (JSON Body Keys)
grep -roiE "(userId|orgId|accountId|tenantId|teamId|projectId|role|isAdmin|isOwner|plan|trial|status|expiry|permission|scope)" \
  artifacts/js_recon/js_beautified/ 2>/dev/null | \
  awk -F: '{print $NF}' | sort -u > artifacts/js_recon/body_parameters.txt

# 2. Query String Parameters (?id=, ?page=, ?format=)
grep -roE "\?[a-zA-Z0-9_\-]+=" artifacts/js_recon/js_beautified/ 2>/dev/null | \
  sed 's/?//;s/=//' | awk -F: '{print $NF}' | sort -u > artifacts/js_recon/query_parameters.txt
```

---

## 3. Server-Side Rendering (SSR) State Extraction (Next.js / Nuxt.js)

Single Page Apps and hybrid frameworks often embed hydration state containing backend API endpoints, internal user IDs, and environment variables directly into HTML response scripts:

```bash
# Extract Next.js and Nuxt initial state JSON objects
head -n 25 artifacts/live_subdomains.txt 2>/dev/null | while read -r host; do
  body=$(curl -sk --max-time 5 "$host")
  
  # Next.js Hydration Blob
  if echo "$body" | grep -q "window\.__NEXT_DATA__"; then
    echo "[SSR-NEXT] Found Next.js state on $host" | tee -a artifacts/js_recon/ssr_state.txt
    echo "$body" | grep -oP 'window\.__NEXT_DATA__\s*=\s*\{.{0,2000}' >> artifacts/js_recon/ssr_next_data.txt
  fi
  
  # Nuxt.js Hydration Blob
  if echo "$body" | grep -q "window\.__NUXT__"; then
    echo "[SSR-NUXT] Found Nuxt.js state on $host" | tee -a artifacts/js_recon/ssr_state.txt
    echo "$body" | grep -oP 'window\.__NUXT__\s*=\s*\{.{0,2000}' >> artifacts/js_recon/ssr_nuxt_data.txt
  fi
done
```

---

## 4. How to Understand and Prioritize Discovered Endpoints

Once `ALL_FINAL_ENDPOINTS.txt` is generated, categorize endpoints into testable targets:

### A. Versioning Analysis (`/v1/`, `/v2/`, `/v3/`)
- Older API versions (`/v1/`) frequently lack modernized security controls (e.g. rate-limiting, strict authentication, or schema validation) that exist in `/v2/`.
- Test if actions restricted in `/v2/users/update` succeed on `/v1/users/update`.

### B. Sensitivity Classification
- **High-Privilege Operations:** `/admin/`, `/staff/`, `/internal/`, `/console/`, `/manage/`.
- **Forgotten & Development Code:** `/debug/`, `/test/`, `/temp/`, `/beta/`, `/demo/`.
- **Data Leakage & Export Endpoints:** `/export/`, `/backup/`, `/dump/`, `/download/`, `/report/`.

### C. IDOR & BOLA Indicators
- Dynamic paths with numeric IDs or placeholders:
  - `/api/v1/users/{id}`
  - `/api/v1/orders/10293`
  - `/api/v1/invoices?userId=123`
- Check whether substituting another user's ID bypasses authorization.

---

## Output Artifacts
- `artifacts/js_recon/ALL_FINAL_ENDPOINTS.txt` — Master list of verified application endpoints.
- `artifacts/js_recon/endpoints/endpoints_high.txt` — High-priority administrative and internal routes.
- `artifacts/js_recon/endpoints/endpoints_dynamic.txt` — Parameterized/template endpoints ready for IDOR probing.
- `artifacts/js_recon/body_parameters.txt` — Harvested JSON body keys for mass assignment.
- `artifacts/js_recon/query_parameters.txt` — Harvested query parameters for injection testing.
