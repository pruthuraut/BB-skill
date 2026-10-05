# Subagent 06: Subdomain Takeover & Dangling Resource Auditing

## Role & Mission
Responsible for analyzing all resolved subdomains for Subdomain Takeovers and dangling DNS records. This audits CNAME, NS, MX, and A pointer misconfigurations where the target domain points to an abandoned, deleted, or unallocated cloud/SaaS resource.

## Assigned Checklist Tasks (2 Checks)
- **Check 25:** Subdomain takeover vulnerability verification on all discovered subdomains
- **Check 28:** Dangling CNAME record auditing pointing to expired third-party cloud services

---

## Standardized Execution Playbook

### Step 1: CNAME Record Extraction & Dangling Identification (Check 28)
Extract all canonical name (CNAME) chains from the resolved DNS dataset:

```bash
# Extract hostnames and their corresponding CNAME records
cat artifacts/resolved_subdomains.json | jq -r 'select(.cname != null) | "\(.host) -> \(.cname[])"' | sort -u > artifacts/cname_chains.txt

# Audit against known high-risk third-party service signatures (can-i-take-over-xyz)
grep -Ei "(amazonaws\.com|s3\.amazonaws\.com|herokuapp\.com|github\.io|fastly\.net|azurewebsites\.net|trafficmanager\.net|pantheonsite\.io|readme\.io|shopify\.com|zendesk\.com|surge\.sh|ghost\.io|bitbucket\.io|unbouncepages\.com|helpjuice\.com|helpscoutdocs\.com|statuspage\.io|cloudapp\.net|wordpress\.com)" artifacts/cname_chains.txt > artifacts/high_risk_cnames.txt
```

### Step 2: Automated Takeover Scanning with Nuclei & Subjack (Check 25 & TBHM v4 Slide 58)
Execute specialized Nuclei takeover templates and subjack against all live subdomains:

```bash
# Update Nuclei templates to include the latest signatures
nuclei -ut

# 1. Run high-concurrency takeover scanning via Nuclei
nuclei -l artifacts/live_subdomains.txt \
  -t http/takeovers/ \
  -t dns/ \
  -severity info,low,medium,high,critical \
  -o artifacts/nuclei_takeovers.txt

# 2. Subjack for CNAME-based dangling cloud resource auditing
subjack -w artifacts/live_subdomains.txt -t 100 -timeout 30 \
  -o artifacts/subjack_takeovers.txt -ssl 2>/dev/null
```

### Step 3: Fast Multi-Fingerprint Grep Loop (Real-Time Fallback)
When scanning large batches of resolved HTTP endpoints, execute this rapid signature matcher:

```bash
# Loop through all live HTTP hosts testing against primary takeover signatures
for host in $(cat artifacts/live_subdomains.txt); do
  body=$(curl -sk --max-time 6 "$host")
  for sig in "There isn't a GitHub Pages site here" \
             "The specified bucket does not exist" \
             "NoSuchBucket" \
             "Repository not found" \
             "Project not found" \
             "Fastly error: unknown domain" \
             "This shop is currently unavailable" \
             "Domain not configured" \
             "404 Not Found" \
             "You're Almost There" \
             "a Netlify site"; do
    echo "$body" | grep -qi "$sig" && echo "[TAKEOVER?] $host — $sig" | tee -a artifacts/grep_takeovers.txt
  done
done
```

### Step 4: High-Value Target Prefix & Cloud Service Prioritization
Prioritize assets displaying the following indicators during triage:
- **Cloud CNAME matches:** `*.s3.amazonaws.com`, `*.pages.dev`, `*.netlify.app`, `*.github.io`, `*.azurewebsites.net`, `*.vercel.app` -> *immediate queue for takeover check*
- **High-value environment prefixes:** `dev-`, `staging-`, `internal-`, `admin-`, `api-`, `test-` -> *prioritize for origin IP bypass and privilege escalation*

### Step 5: Fingerprint & Error String Cross-Verification Matrix
When a dangling CNAME is identified, cross-verify the HTTP response body against known service fingerprints:

| Provider | Canonical Domain Pattern | Signature / Response String | Actionable Claim Method |
|---|---|---|---|
| **AWS S3** | `*.s3.amazonaws.com` | `The specified bucket does not exist` / `NoSuchBucket` | Create bucket in matching region |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here.` | Add `CNAME` in your public repository |
| **Heroku** | `*.herokuapp.com` | `No such app` / `There's nothing here` | Claim via Heroku dashboard |
| **Azure Traffic Mgr** | `*.trafficmanager.net` | `404 Not Found` / Domain Unregistered | Register Traffic Manager profile |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` | Add custom domain in Shopify store |
| **Surge.sh** | `*.surge.sh` | `project not found` | `surge --domain <target_subdomain>` |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | Register Zendesk subdomain |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain` | Claim service in Fastly account |
| **Pantheon** | `*.pantheonsite.io` | `404 error unknown site!` | Add domain in Pantheon project |
| **Netlify** | `*.netlify.app` | `a Netlify site` / `Page not found` | Register custom subdomain on Netlify |

### Step 4: Secondary Verification (Proof-of-Concept Safety)
*Bug Bounty Safety Rule:* Never modify production data or claim destructive ownership without explicit bug bounty program permission. To demonstrate impact safely:
1. Verify the service is unallocated.
2. If safe claiming is permitted by the program brief, host an innocuous text file (e.g. `poc.txt` with your handle).
3. Record raw DNS resolution, CNAME chain, and HTTP response headers.

---

## Output Artifact
Aggregate and document all verified takeover findings into:
`artifacts/subagent_06_takeover_report.md`
```bash
if [ -s "artifacts/nuclei_takeovers.txt" ]; then
  echo "## Verified Subdomain Takeovers" > artifacts/subagent_06_takeover_report.md
  cat artifacts/nuclei_takeovers.txt >> artifacts/subagent_06_takeover_report.md
else
  echo "## Subdomain Takeovers: Zero vulnerable dangling assets identified." > artifacts/subagent_06_takeover_report.md
fi
```
