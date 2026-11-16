# Subagent 03: Supply Chain & Dependency Confusion Auditing

## Role & Mission
Responsible for mining software build manifests (`package.json`, `package-lock.json`, `composer.json`, `requirements.txt`) discovered across web applications and GitHub repositories, isolating internal/private package names, querying public package registries (e.g. npm registry), and identifying unclaimed package scopes vulnerable to Dependency Confusion (Namespace Hijacking).

---

## Standardized Execution Playbook

### Step 1: Package Manifest Harvesting
Extract all `package.json` URLs uncovered during historical archiving, crawling, and directory fuzzing:

```bash
mkdir -p artifacts/dependency_confusion/

# Filter package manifests from discovered URLs
cat artifacts/all_discovered_urls.txt 2>/dev/null | grep -iE 'package\.json$' \
  | sort -u > artifacts/dependency_confusion/manifest_urls.txt
```

### Step 2: Extract Dependency & Scope Names
Parse dependencies and devDependencies from discovered manifests:

```bash
cat artifacts/dependency_confusion/manifest_urls.txt | while read -r url; do
  curl -sk --max-time 5 "$url" 2>/dev/null \
    | jq -r '(.dependencies // {}) + (.devDependencies // {}) | keys[]' 2>/dev/null
done | sort -u > artifacts/dependency_confusion/all_package_names.txt

echo "[*] Total extracted package names: $(wc -l < artifacts/dependency_confusion/all_package_names.txt)"
```

### Step 3: Public Registry Availability Probing (NPM Registry)
Query the official npm registry (`registry.npmjs.org`) for each package. If a package returns HTTP 404, it does NOT exist on the public registry:

```bash
cat artifacts/dependency_confusion/all_package_names.txt | while read -r pkg; do
  # Query public registry
  code=$(curl -so /dev/null -w '%{http_code}' --max-time 4 "https://registry.npmjs.org/${pkg}")
  
  if [ "$code" = "404" ]; then
    echo "[UNCLAIMED-PACKAGE] $pkg (HTTP $code)" | tee -a artifacts/dependency_confusion/unclaimed_packages.txt
  fi
done
```

### Step 4: Namespace Pattern & Severity Verification
Not every 404 package on npm is vulnerable to dependency confusion. Apply strict qualification filters to eliminate false positives:

```bash
TARGET_COMPANY="<company_keyword>"

cat artifacts/dependency_confusion/unclaimed_packages.txt 2>/dev/null | while read -r line; do
  pkg=$(echo "$line" | awk '{print $2}')
  
  # Check if package name starts with company prefix, scope (@company), or internal nomenclature
  if echo "$pkg" | grep -qiE "(@${TARGET_COMPANY}|${TARGET_COMPANY}-|internal-|corp-|private-)"; then
    echo "[HIGH-CONFIDENCE-CONFUSION] $pkg is an internal package unreserved on npm!" \
      | tee -a artifacts/dependency_confusion/verified_dependency_confusion.txt
  fi
done
```

### Step 5: Severity Kill Rules for Dependency Confusion
- **KILL** — Package returns 404 on npm, but does NOT match the company's internal naming convention, scope prefix, or private repository naming pattern (could just be a typo or external private fork).
- **KILL** — Claiming or publishing the package on npm without permission. **Bug Bounty Safety Rule:** Never publish a malicious or dummy package to public registries. Document the HTTP 404 status and evidence of internal manifest usage.
- **KEEP (HIGH/CRITICAL)** — Internal private package actively used in production build manifests with company namespace that is unreserved on the public registry.

---

## Output Artifacts
- `artifacts/dependency_confusion/all_package_names.txt` — Harvested package names.
- `artifacts/dependency_confusion/unclaimed_packages.txt` — 404 responses on public npm.
- `artifacts/dependency_confusion/verified_dependency_confusion.txt` — Qualified high-confidence candidates.
