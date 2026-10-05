# Subagent 03: Parameter Mining, Fuzzing & Form Extraction

## Role & Mission
Responsible for identifying all input surfaces: historical parameter mining (`paramspider`), active hidden parameter brute-forcing (`arjun`, `x8`), HTML form parsing (`<input type="hidden">`), dynamic path parameters (`/items/{id}`), search/sort filters, and pagination parameters.

## Assigned Checklist Tasks (7 Checks)
- **Check 06:** Parameter discovery from historical archives via `paramspider`
- **Check 07:** Hidden parameter discovery using `arjun` and `params.txt`
- **Check 08:** Identification of dynamic path-based parameters (`/users/{id}/`, `/:uuid`)
- **Check 23:** Extraction of HTML `<form>` action URLs and hidden input parameters
- **Check 24:** Dynamic AJAX / Fetch XHR call analysis in browser network traces
- **Check 31:** Identification of parameters leaked in HTTP `Referer` headers of outbound links
- **Check 36:** Discovery of search, filter, and sorting parameters (`q=`, `sort=`, `order=`)
- **Check 37:** Discovery of pagination parameters (`page`, `offset`, `limit`, `cursor`)

---

## Standardized Execution Playbook

### Step 1: Historical Parameter Mining via ParamSpider (Check 06)
```bash
# Mine historical URLs with active parameters
paramspider -d <target> --level high -o artifacts/paramspider_params.txt

# Extract parameter names only
cat artifacts/paramspider_params.txt | grep -oE "\?[a-zA-Z0-9_\-\[\]]+=" | tr -d '?=' | sort -u > artifacts/historical_param_names.txt

# Extract high-risk SSRF / Open-Redirect candidate parameters
grep -iE "(url|uri|endpoint|host|server|proxy|dest|destination|redirect|target|src|source|feed|webhook|callback|link|ref|return|path|load|fetch|pull|remote|request)=" \
  artifacts/paramspider_params.txt | sort -u > artifacts/ssrf_candidates.txt
```

### Step 2: Hidden Parameter Fuzzing via Arjun (Check 07 & params.txt)
*Resource Integration:* Use `wordlists/params.txt` (contains thousands of curated web parameters):

```bash
WORDLIST_PARAMS="wordlists/params.txt"

# Fuzz GET, POST, and JSON parameters on high-value endpoints
cat artifacts/discovered_endpoints.txt | head -n 15 | while read endpoint; do
  echo "[*] Fuzzing parameters on: $endpoint"
  arjun -u "$endpoint" \
    -w "$WORDLIST_PARAMS" \
    -m GET,POST,JSON \
    -t 15 \
    -oJ "artifacts/arjun_$(date +%s%N).json"
done
```

### Step 3: Dynamic Path-Based Parameter Extraction (Check 08)
APIs often pass identifiers directly in the URI path rather than in query strings:

```bash
# Normalize and detect dynamic path variables (/api/v1/users/1234 -> /api/v1/users/{id})
python3 -c "
import re

patterns = [
    (re.compile(r'\/[0-9]{1,10}(\/|$)'), '/{id}'),
    (re.compile(r'\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(\/|$)'), '/{uuid}'),
    (re.compile(r'\/0x[a-fA-F0-9]{40}(\/|$)'), '/{eth_address}'),
    (re.compile(r'\/[a-f0-9]{32,64}(\/|$)'), '/{hash}')
]

endpoints = []
with open('artifacts/discovered_endpoints.txt') as f:
    for line in f:
        ep = line.strip()
        orig = ep
        for p, repl in patterns:
            ep = p.sub(repl, ep)
        if ep != orig:
            endpoints.append(f'{orig} => {ep}')

with open('artifacts/path_based_parameters.txt', 'w') as out:
    for e in sorted(set(endpoints)):
        out.write(e + '\n')
"
```

### Step 4: HTML Form Action & Hidden Field Parsing (Check 23)
Forms contain high-value state parameters (e.g. `csrf_token`, `redirect_to`, `role`, `is_admin`, `debug`):

```bash
# Parse all form actions and hidden inputs from HTML pages
python3 -c "
import requests, re
from bs4 import BeautifulSoup

urls = ['https://<target>']
# Add discovered login/signup/profile paths
forms_data = []

for u in urls:
    try:
        r = requests.get(u, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            hidden_fields = {}
            for inp in form.find_all('input'):
                if inp.get('type') == 'hidden' and inp.get('name'):
                    hidden_fields[inp.get('name')] = inp.get('value', '')
            forms_data.append({'url': u, 'action': action, 'method': method, 'hidden_fields': hidden_fields})
    except:
        pass

import json
with open('artifacts/extracted_forms.json', 'w') as out:
    json.dump(forms_data, out, indent=2)
"
```

### Step 5: Search, Filtering & Pagination Parameters (Checks 36, 37)
Audit API endpoints for query-structuring parameters vulnerable to SQLi, NoSQLi, and DoS:

```bash
# Common search & filter parameters
SEARCH_PARAMS=("q" "query" "search" "keyword" "filter" "sort" "order" "by" "direction" "category" "tags")
# Common pagination parameters
PAGE_PARAMS=("page" "p" "offset" "limit" "size" "count" "per_page" "cursor" "start")

echo "Auditing endpoints for Search & Pagination parameters..."
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_03_parameters.md`
