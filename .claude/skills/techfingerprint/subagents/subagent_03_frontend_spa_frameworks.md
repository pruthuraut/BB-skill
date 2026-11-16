# Subagent 03: Modern Frontend Frameworks & Single Page Applications

## Role & Mission
Responsible for analyzing client-side source code, HTML documents, bundle scripts, and DOM markers to pinpoint JavaScript UI frameworks, Single Page Application (SPA) architectures, and Server-Side Rendering (SSR) engines.

## Assigned Checklist Tasks (9 Checks)
- **Check 09:** JavaScript frameworks detection via source code & script bundle analysis
- **Check 10:** React indicators (`_reactRootContainer`, `__REACT_DEVTOOLS_GLOBAL_HOOK__`)
- **Check 11:** Angular indicators (`ng-version`, `ng-app`, `_nghost`, `_ngcontent`)
- **Check 12:** Vue.js indicators (`__vue__`, `data-v-` attributes)
- **Check 33:** Next.js SSR identification (`<script id="__NEXT_DATA__">`, `buildId`)
- **Check 34:** Nuxt.js SSR identification (`window.__NUXT__`, `data-n-head`)
- **Check 35:** Gatsby static site detection (`id="___gatsby"`, `___graphql`)
- **Check 36:** Svelte detection (`class="svelte-..."` scoped attributes)
- **Check 37:** Ember.js detection (`meta name="...ember-cli"`, `data-ember-action`)
- **Check 38:** Meteor.js detection (`__meteor_runtime_config__` global variable)

---

## Standardized Execution Playbook

### Step 1: Automated DOM & Source Code Harvester
Download the primary rendered HTML document and analyze framework indicators:

```bash
curl -sL https://<target> > artifacts/index_page.html
```

### Step 2: Framework Fingerprint Regex Heuristics

```bash
python3 -c "
import re, json

with open('artifacts/index_page.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

frameworks = {}

# Check 10 & 33: React & Next.js
if '__NEXT_DATA__' in content:
    match = re.search(r'<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>', content)
    build_id = 'Unknown'
    if match:
        try:
            data = json.loads(match.group(1))
            build_id = data.get('buildId', 'Unknown')
        except:
            pass
    frameworks['Next.js'] = {'detected': True, 'buildId': build_id}
elif '_reactRootContainer' in content or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in content or 'react.production.min.js' in content:
    frameworks['React'] = {'detected': True}

# Check 11: Angular
ng_ver = re.findall(r'ng-version=\"([0-9\.]+)\"', content)
if ng_ver or '_nghost' in content or '_ngcontent' in content or 'ng-app' in content:
    frameworks['Angular'] = {'detected': True, 'version': ng_ver[0] if ng_ver else 'Unknown'}

# Check 12: Vue.js
if re.search(r'data-v-[a-f0-9]+', content) or '__vue__' in content or '__VUE__' in content:
    frameworks['Vue.js'] = {'detected': True}

# Check 34: Nuxt.js
if 'window.__NUXT__' in content or 'data-n-head' in content:
    frameworks['Nuxt.js'] = {'detected': True}

# Check 35: Gatsby
if 'id=\"___gatsby\"' in content or 'gatsby-script' in content:
    frameworks['Gatsby'] = {'detected': True}

# Check 36: Svelte
if re.search(r'svelte-[a-z0-9]{5,8}', content):
    frameworks['Svelte'] = {'detected': True}

# Check 37: Ember.js
if 'ember-cli' in content or 'data-ember-action' in content:
    frameworks['Ember.js'] = {'detected': True}

# Check 38: Meteor
if '__meteor_runtime_config__' in content:
    frameworks['Meteor.js'] = {'detected': True}

print(json.dumps(frameworks, indent=2))
with open('artifacts/detected_frontend_frameworks.json', 'w') as out:
    json.dump(frameworks, out, indent=2)
"
```

### Step 3: Deep Script Bundle Inspection (Check 09)
Extract imported vendor libraries from compiled Webpack / Vite / Rollup chunks:

```bash
grep -oE 'src="([^"]+\.js[^"]*)"' artifacts/index_page.html | cut -d'"' -f2 | while read script; do
  echo "[*] Parsing script: $script"
  # Look for version numbers in vendor files (e.g. react@18.2.0, vue@3.2.0, jquery@3.6.0)
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_03_frontend_frameworks.md`
