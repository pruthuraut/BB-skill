---
name: recon-hunter
description: >
  Full-stack recon-to-bug master skill. Runs passive + active recon, attack surface mapping, and
  bug discovery in one continuous 16-phase pipeline — all phases in order, zero skips. Triggers on:
  "recon", "enumerate", "subdomain", "find bugs", "attack surface", "map the target",
  "what's exposed", "scan this", or any domain/IP handed without further instruction.
  Produces a ranked finding list with PoC curl commands. Use for unauthenticated coverage
  before any authenticated testing begins.
version: "1.0.0"
author: "Bug Bounty Multi-Agent Skills Framework"
compatibility:
  - Antigravity / Gemini CLI
  - Claude Code
  - Cursor IDE
  - OpenAI Codex / OpenCode
  - DeepSeek
---

# RECON-HUNTER — Full Recon + Bug Discovery Pipeline

**One rule: impact first. Only report what an attacker can abuse RIGHT NOW.**
Kill theoretical findings before they reach the report.

```
                                  [ TARGET ROOT DOMAIN / IP ]
                                               │
    ┌──────────────────────────────────────────┴──────────────────────────────────────────┐
    ▼                                                                                     ▼
[ PHASE 01-04: PERIMETER & HOST MAPPING ]                             [ PHASE 05-08: URLS, CRAWL & JAVASCRIPT ]
• Phase 01: Passive Subdomain Enumeration (zero-touch)                • Phase 05: Historical URL Collection & Juicy Probing
• Phase 02: DNS Resolution & httpx Fingerprint Pass                   • Phase 06: Active Multi-Engine Crawl (Katana/GoSpider)
• Phase 03: Non-CDN Port Scanning & Service Probing                   • Phase 07: Target-Derived Directory & Endpoint Fuzzing
• Phase 04: Subdomain Takeover & CNAME Dangling Audit                 • Phase 08: JavaScript Analysis, SSR State & Secrets
    │                                                                                     │
    └──────────────────────────────────────────┬──────────────────────────────────────────┘
                                               ▼
    ┌──────────────────────────────────────────┴──────────────────────────────────────────┐
    ▼                                                                                     ▼
[ PHASE 09-12: VULNERABILITY & EXPOSURE ]                             [ PHASE 13-16: PROTOCOLS, SUPPLY & TRIAGE ]
• Phase 09: Nuclei Automated Vulnerability Scan                       • Phase 13: SSRF Entry Point Parameter Mining & OOB
• Phase 10: Cloud Storage & Firebase Bucket Permutation               • Phase 14: GraphQL Discovery & Schema Introspection
• Phase 11: Source Code, VCS & 21 Sensitive Configs                   • Phase 15: Org Secret Hunt & Dependency Confusion
• Phase 12: CORS Origin Reflection & Credential Audit                 • Phase 16: Headless Screenshotting & Visual Triage
    │                                                                                     │
    └──────────────────────────────────────────┬──────────────────────────────────────────┘
                                               ▼
                                 [ CONSOLIDATED FINDINGS TRIAGE ]
                                 • CRITICAL / HIGH / MEDIUM / SSRF
                                 • 60-Second Copyable PoC Curl Standard
                                 • 16-Phase Completed Coverage Ledger
```

---

## Master Skill Delegation Architecture

While `recon-hunter` coordinates the rapid 16-phase pipeline end-to-end, each phase maps directly to our specialized framework skills:

| Phase | Title | Primary Engine / Commands | Specialized Skill Reference |
|---|---|---|---|
| **Phase 01** | Passive Subdomain Enum | `crt.sh`, `subfinder`, `amass`, `chaos`, `cero`, `github-subdomains` | [subdomainenum](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/subdomainenum/SKILL.md) |
| **Phase 02** | DNS Resolution & Tech Detect | `dnsx`, `httpx -title -tech-detect -cdn -follow-redirects` | [techfingerprint](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/SKILL.md) |
| **Phase 03** | Port Scan & Services | `naabu` (non-CDN), `nmap -sV`, unauth service verification | [techfingerprint](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/SKILL.md) |
| **Phase 04** | Subdomain Takeover | `nuclei -t takeovers/`, `subjack`, 11 signature grep loop | [subdomainenum](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/subdomainenum/SKILL.md) |
| **Phase 05** | Historical URLs & Juicy Files | `waybackurls`, `gau`, `waymore`, juicy extension `httpx -mc 200` | [contentdiscovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/SKILL.md) |
| **Phase 06** | Active Web Crawl | `katana -jc -jsl -d 5 -kf all -aff`, `gospider`, `hakrawler` | [linkparamdiscovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/linkparamdiscovery/SKILL.md) |
| **Phase 07** | Directory & Endpoint Fuzzing | Target-derived wordlist (`unfurl`), `ffuf -ac`, API fuzzing | [contentdiscovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/SKILL.md) |
| **Phase 08** | JS Analysis & Secret Extraction| `js-beautify`, `trufflehog`, `gitleaks`, live token validation | [jsrecon](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/jsrecon/SKILL.md) |
| **Phase 09** | Nuclei Automated Vulnerability| `nuclei -severity critical,high,medium`, priority exposures | [contentdiscovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/SKILL.md) |
| **Phase 10** | Cloud Storage & Buckets | Multi-cloud S3/GCS/Azure permutations, Firebase RTDB shallow | [cloud-supplychain](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/cloud-supplychain/SKILL.md) |
| **Phase 11** | Source Code & Config Exposure | `.git/config`, `.env`, Spring actuators, 21 sensitive paths | [contentdiscovery](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/contentdiscovery/SKILL.md) |
| **Phase 12** | CORS Origin Reflection | Arbitrary origin, `Origin: null`, `Allow-Credentials: true` | [api-security](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/SKILL.md) |
| **Phase 13** | SSRF Entry Point Discovery | Regex parameter filtering, Out-Of-Band interactsh verification | [ssrf-audit](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/ssrf-audit/SKILL.md) |
| **Phase 14** | GraphQL Discovery & Schema | `{__typename}` probe, full schema introspection dump | [api-security](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/api-security/SKILL.md) |
| **Phase 15** | Org Secrets & Supply Chain | `trufflehog github --org`, npm package registry 404 audit | [cloud-supplychain](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/cloud-supplychain/SKILL.md) |
| **Phase 16** | Screenshot & Visual Triage | `gowitness file -f subs/live_http.txt --resolution 1280x800` | [techfingerprint](file:///c:/Users/rautp/Documents/BBskill/.agents/skills/techfingerprint/SKILL.md) |

---

## PHASE 0 — Setup

```bash
T="<target_apex_domain>"   # Set apex domain
OUT="artifacts/recon_${T}"
mkdir -p "$OUT"/{subs,urls,js,ports,screenshots,findings,cloud}
```

---

## PHASE 1 — Passive Subdomain Enumeration (zero-touch)

Goal: maximum breadth before touching target infrastructure.

```bash
# 1. Certificate transparency
curl -s "https://crt.sh/?q=%25.$T&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$OUT/subs/raw.txt"

# 2. subfinder (all sources)
subfinder -d "$T" -all -silent >> "$OUT/subs/raw.txt"

# 3. amass passive
amass enum -passive -d "$T" -o "$OUT/subs/amass.txt" 2>/dev/null
cat "$OUT/subs/amass.txt" >> "$OUT/subs/raw.txt"

# 4. chaos (ProjectDiscovery dataset)
chaos -d "$T" -silent 2>/dev/null >> "$OUT/subs/raw.txt"

# 5. github-subdomains (requires GITHUB_TOKEN env)
github-subdomains -d "$T" -t "$GITHUB_TOKEN" -o "$OUT/subs/github.txt" 2>/dev/null
cat "$OUT/subs/github.txt" >> "$OUT/subs/raw.txt"

# 6. cero (TLS SAN scraping)
cero "$T" 2>/dev/null >> "$OUT/subs/raw.txt"

# Deduplicate
sort -u "$OUT/subs/raw.txt" -o "$OUT/subs/all.txt"
wc -l "$OUT/subs/all.txt"
```

**Bug signals during enumeration:**
- Subdomains matching `*.s3.amazonaws.com`, `*.pages.dev`, `*.netlify.app`, `*.github.io`, `*.azurewebsites.net`, `*.vercel.app` -> *queue for takeover check (Phase 4)*
- `dev-`, `staging-`, `internal-`, `admin-`, `api-` prefixes -> *high-value targets, prioritize*

---

## PHASE 2 — DNS Resolution + Live Host Discovery

```bash
# Resolve all subs to live IPs
dnsx -l "$OUT/subs/all.txt" -resp -a -cname -silent -o "$OUT/subs/resolved.txt"
cat "$OUT/subs/resolved.txt" | awk '{print $1}' > "$OUT/subs/live_hosts.txt"

# httpx — full fingerprint pass
httpx -l "$OUT/subs/live_hosts.txt" \
  -title -tech-detect -status-code -content-length \
  -ip -cdn -cname -follow-redirects \
  -mc 200,201,204,301,302,307,401,403,404,500 \
  -o "$OUT/subs/httpx.json" -j -silent

# Extract live HTTP hosts
cat "$OUT/subs/httpx.json" | jq -r '.url' > "$OUT/subs/live_http.txt"
wc -l "$OUT/subs/live_http.txt"
```

**Bug signals:**
- `401`/`403` on `admin.*`, `internal.*`, `api.*` -> *queue for 403 bypass*
- `500` responses -> *server errors, potential injection surface*
- CDN=false + IP exposed -> *origin IP bypass candidate*
- `tech-detect` shows old versions -> *CVE check queue*

---

## PHASE 3 — Port Scanning + Service Discovery

Run only against non-CDN IPs (CDN scanning is wasteful and often out-of-scope).

```bash
# Extract non-CDN IPs from httpx output
cat "$OUT/subs/httpx.json" | jq -r 'select(.cdn==false) | .host' | sort -u > "$OUT/ports/ips.txt"

# Fast port scan — top 1000 + common web/service ports
naabu -l "$OUT/ports/ips.txt" -top-ports 1000 \
  -p 80,443,8080,8443,8888,9000,9200,9300,5601,3000,3001,4000,5000,6379,27017,5432,3306,2375,2376 \
  -o "$OUT/ports/open.txt" -silent

# Service banner + version (nmap on open ports only)
nmap -iL "$OUT/ports/open.txt" -sV --open -T4 \
  --script=banner,http-title,http-server-header \
  -oN "$OUT/ports/nmap.txt" -oX "$OUT/ports/nmap.xml" 2>/dev/null
```

**High-value service signals -> immediate bug checks:**

| Service | Port | Unauthenticated Impact Probe Command |
|---|---|---|
| **Elasticsearch** | 9200/9300 | `curl -sk http://IP:9200/_cat/indices?v` |
| **Kibana** | 5601 | `curl -sk http://IP:5601/api/status` |
| **Redis** | 6379 | `redis-cli -h IP ping` |
| **MongoDB** | 27017 | `mongo --host IP --eval "db.adminCommand('listDatabases')"` |
| **Docker API** | 2375/2376 | `curl -sk http://IP:2375/v1.41/containers/json` |
| **Kubernetes** | 6443/10250 | `curl -sk https://IP:10250/pods -k` |
| **Spring Actuator** | 8080/8443 | `curl -sk http://HOST/actuator` |
| **Prometheus** | 9090 | `curl -sk http://HOST:9090/metrics` |
| **Grafana** | 3000 | Default `admin:admin` login |
| **Jenkins** | 8080 | `curl -sk http://HOST:8080/api/json` |

---

## PHASE 4 — Subdomain Takeover Check

```bash
# 1. nuclei takeover templates against all live hosts
nuclei -l "$OUT/subs/live_http.txt" \
  -t http/takeovers/ \
  -severity medium,high,critical \
  -o "$OUT/findings/takeovers.txt" -silent

# 2. subjack for CNAME-based takeover
subjack -w "$OUT/subs/all.txt" -t 100 -timeout 30 \
  -o "$OUT/findings/subjack.txt" -ssl 2>/dev/null

# 3. Real-time fingerprint grep loop
for host in $(cat "$OUT/subs/live_http.txt"); do
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
    echo "$body" | grep -qi "$sig" && echo "[TAKEOVER?] $host — $sig" | tee -a "$OUT/findings/takeovers.txt"
  done
done
```

---

## PHASE 5 — Historical URL Collection + Secret Hunting in URLs

```bash
# Collect historical URLs — three sources
for host in $(cat "$OUT/subs/live_hosts.txt"); do
  echo "$host" | waybackurls 2>/dev/null >> "$OUT/urls/all.txt"
  echo "$host" | gau --subs 2>/dev/null >> "$OUT/urls/all.txt"
  waymore -i "$host" -mode U -oU /tmp/wm.txt 2>/dev/null
  cat /tmp/wm.txt >> "$OUT/urls/all.txt"
done
sort -u "$OUT/urls/all.txt" -o "$OUT/urls/all.txt"

# Juicy extension filter
grep -iE '\.(bak|backup|sql|db|sqlite|json|xml|yaml|yml|env|config|conf|log|old|gz|zip|tar|7z|rar|pdf|xls|xlsx|doc|docx|csv|pem|key|crt|p12|pfx|jks)(\?|$)' \
  "$OUT/urls/all.txt" > "$OUT/urls/juicy_extensions.txt"

# Parameter URLs (injection candidates)
grep '=' "$OUT/urls/all.txt" | grep -v '\.js\|\.css\|\.png\|\.jpg\|\.gif' > "$OUT/urls/params.txt"

# Admin/sensitive paths
grep -iE '(admin|panel|dashboard|manage|config|debug|test|dev|staging|backup|api|graphql|swagger|actuator|metrics|health|console)' \
  "$OUT/urls/all.txt" > "$OUT/urls/sensitive_paths.txt"

# Probe juicy files — are they still live?
httpx -l "$OUT/urls/juicy_extensions.txt" -mc 200 -o "$OUT/urls/juicy_live.txt" -silent
```

---

## PHASE 6 — Active Crawl (per live host)

```bash
while IFS= read -r HOST; do
  echo "[*] Crawling $HOST"
  
  # katana — JS-aware, follows dynamic imports
  katana -u "$HOST" -jc -jsl -d 5 -kf all -aff -silent \
    -o "$OUT/urls/katana_$(echo "$HOST" | tr '/:' '_').txt" 2>/dev/null
  
  # gospider — link extraction
  gospider -s "$HOST" -d 3 --js -q 2>/dev/null \
    | grep -oP 'https?://[^\s"'"'"']+' >> "$OUT/urls/all.txt"
  
  # hakrawler
  echo "$HOST" | hakrawler -d 3 -subs 2>/dev/null >> "$OUT/urls/all.txt"
done < "$OUT/subs/live_http.txt"

# Deduplicate everything collected
sort -u "$OUT/urls/all.txt" -o "$OUT/urls/all.txt"

# Re-extract JS files
grep -oP 'https?://[^\s"'"'"']+\.js(\?[^\s"'"'"']*)?' "$OUT/urls/all.txt" | sort -u > "$OUT/js/all_js.txt"
```

---

## PHASE 7 — Directory + Endpoint Fuzzing

```bash
# Target-derived wordlist from discovered paths
cat "$OUT/urls/all.txt" | unfurl paths | tr '/' '\n' | sort | uniq -c | sort -rn \
  | awk '$1>1{print $2}' > "$OUT/urls/custom_wordlist.txt"

# ffuf — directory fuzzing on high-value hosts
head -n 20 "$OUT/subs/live_http.txt" | while IFS= read -r HOST; do
  ffuf -u "$HOST/FUZZ" \
    -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt \
    -mc 200,201,204,301,302,307,401,403 \
    -ac -t 40 -timeout 10 \
    -o "$OUT/urls/ffuf_$(echo "$HOST" | tr '/:' '_').json" 2>/dev/null
done

# API endpoint fuzzing
ffuf -u "$TARGET/api/FUZZ" \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,400,401,403,405 -ac -t 30
```

---

## PHASE 8 — JavaScript Analysis + Secret Extraction

```bash
mkdir -p "$OUT/js/files" "$OUT/js/secrets"

# Download all JS files
while IFS= read -r url; do
  fname="$OUT/js/files/$(echo "$url" | md5sum | cut -d' ' -f1).js"
  curl -sk "$url" -o "$fname" 2>/dev/null
done < "$OUT/js/all_js.txt"

# Beautify
for f in "$OUT/js/files/"*.js; do
  js-beautify "$f" -o "${f%.js}.pretty.js" 2>/dev/null
done

# Secret scanning — TruffleHog on JS dir
trufflehog filesystem "$OUT/js/files/" --json 2>/dev/null | tee "$OUT/js/secrets/trufflehog.json"

# Gitleaks on JS dir
gitleaks detect --source="$OUT/js/files/" --report-path="$OUT/js/secrets/gitleaks.json" --no-git 2>/dev/null

# Manual grep patterns for high-impact tokens
grep -rhoP \
  '(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{90,}|sk-ant-[a-zA-Z0-9_-]{95,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9A-Za-z-]{10,}|hf_[a-zA-Z0-9]{34}|sk_live_[a-zA-Z0-9]{24}|r8_[a-zA-Z0-9]{40}|shpss_[a-zA-Z0-9]{32}|vc_[a-zA-Z0-9]{24,}|gsk_[a-zA-Z0-9]{52})' \
  "$OUT/js/files/" | sort -u | tee "$OUT/js/secrets/manual_grep.txt"

# Endpoint extraction from JS
cat "$OUT/js/files/"*.js 2>/dev/null | grep -oP '["'"'"'`](/[a-zA-Z0-9/_-]{3,})['"'"'"`]' \
  | sort -u > "$OUT/urls/js_endpoints.txt"

# SSR state blobs (Next.js & Nuxt.js)
head -n 20 "$OUT/subs/live_http.txt" | while read -r host; do
  body=$(curl -sk "$host")
  echo "$body" | grep -oP 'window\.__NEXT_DATA__\s*=\s*\{.{0,2000}' && echo "[SSR-NEXT] $host" >> "$OUT/findings/ssr_state.txt"
  echo "$body" | grep -oP 'window\.__NUXT__\s*=\s*\{.{0,2000}' && echo "[SSR-NUXT] $host" >> "$OUT/findings/ssr_state.txt"
done
```

**Confirm live secrets immediately:**
```bash
# OpenAI: curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY" | jq '.data[0].id'
# Anthropic: curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" | jq '.models[0].id'
# AWS (Identity check only): aws sts get-caller-identity --no-cli-pager 2>/dev/null
# GitHub: curl -s https://api.github.com/user -H "Authorization: token $KEY" | jq '.login'
# Stripe: curl -s https://api.stripe.com/v1/charges -u "$KEY:" | jq '.object'
```

---

## PHASE 9 — Nuclei Automated Bug Scan

```bash
# Full nuclei run — critical + high + medium, all categories
nuclei -l "$OUT/subs/live_http.txt" \
  -severity critical,high,medium \
  -etags "dos,fuzz,bruteforce" \
  -c 30 -rl 100 \
  -o "$OUT/findings/nuclei_all.txt" \
  -json -o "$OUT/findings/nuclei_all.json" \
  -silent

# High-value specific priority templates
nuclei -l "$OUT/subs/live_http.txt" \
  -t http/exposures/ \
  -t http/misconfiguration/ \
  -t http/cves/ \
  -t http/default-logins/ \
  -severity critical,high \
  -o "$OUT/findings/nuclei_priority.txt" -silent
```

---

## PHASE 10 — Cloud Storage Enumeration

```bash
NAMES=("$T" "${T//./-}" "${T%%.*}" "dev-${T%%.*}" "staging-${T%%.*}" \
       "backup-${T%%.*}" "assets-${T%%.*}" "cdn-${T%%.*}" "static-${T%%.*}" \
       "${T%%.*}-prod" "${T%%.*}-dev" "${T%%.*}-stage" "${T%%.*}-backup")

for name in "${NAMES[@]}"; do
  # AWS S3
  curl -s "https://${name}.s3.amazonaws.com/?list-type=2" \
    | grep -q '<Key>' && echo "[S3-PUBLIC] https://${name}.s3.amazonaws.com" | tee -a "$OUT/findings/cloud.txt"
  
  # Google Cloud Storage
  curl -s "https://storage.googleapis.com/${name}/?list-type=2" \
    | grep -q '<Key>' && echo "[GCS-PUBLIC] https://storage.googleapis.com/${name}" | tee -a "$OUT/findings/cloud.txt"

  # Azure Blob Storage
  curl -s "https://${name}.blob.core.windows.net/?comp=list" \
    | grep -q '<Container>' && echo "[AZURE-PUBLIC] https://${name}.blob.core.windows.net" | tee -a "$OUT/findings/cloud.txt"
done

# Firebase RTDB shallow check
curl -s "https://${T%%.*}-default-rtdb.firebaseio.com/.json?shallow=true" \
  | grep -v '"error"' | grep -q '{' && echo "[FIREBASE-UNAUTH] https://${T%%.*}-default-rtdb.firebaseio.com" | tee -a "$OUT/findings/cloud.txt"
```

---

## PHASE 11 — Source Code + Config Exposure

```bash
# 1. .git exposure check
for host in $(cat "$OUT/subs/live_http.txt"); do
  status=$(curl -so /dev/null -w '%{http_code}' "$host/.git/config")
  [ "$status" = "200" ] && echo "[GIT-EXPOSED] $host" | tee -a "$OUT/findings/source_exposure.txt"
done

# 2. Common configuration and backup files
PATHS=("/.env" "/.env.production" "/.env.local" "/config.json" "/config.yaml" \
       "/wp-config.php.bak" "/database.yml" "/.htpasswd" "/web.config" \
       "/settings.py" "/config.php" "/.DS_Store" "/composer.json" \
       "/package.json" "/Dockerfile" "/docker-compose.yml" \
       "/actuator/env" "/actuator/heapdump" "/.aws/credentials" \
       "/swagger.json" "/openapi.json" "/api-docs" "/graphql")

head -n 50 "$OUT/subs/live_http.txt" | while read -r host; do
  for path in "${PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' --max-time 4 "$host$path")
    [ "$code" = "200" ] && echo "[EXPOSED] $host$path ($code)" | tee -a "$OUT/findings/source_exposure.txt"
  done
done
```

---

## PHASE 12 — CORS Misconfiguration Check

```bash
head -n 30 "$OUT/subs/live_http.txt" | while read -r host; do
  # Test arbitrary origin reflection
  resp=$(curl -sk -H "Origin: https://evil.com" -I "$host/api/" 2>/dev/null)
  if echo "$resp" | grep -qi "access-control-allow-origin: https://evil.com"; then
    if echo "$resp" | grep -qi "access-control-allow-credentials: true"; then
      echo "[CORS-CRITICAL] $host reflects arbitrary origin with credentials!" | tee -a "$OUT/findings/cors.txt"
    fi
  fi
  
  # Test null origin
  resp_null=$(curl -sk -H "Origin: null" -I "$host/api/" 2>/dev/null)
  if echo "$resp_null" | grep -qi "access-control-allow-origin: null"; then
    if echo "$resp_null" | grep -qi "access-control-allow-credentials: true"; then
      echo "[CORS-NULL] $host accepts null origin with credentials" | tee -a "$OUT/findings/cors.txt"
    fi
  fi
done
```

---

## PHASE 13 — SSRF Entry Point Discovery

```bash
# Find URL parameters that could be SSRF entry points
grep '=' "$OUT/urls/params.txt" \
  | grep -iE '(url|uri|endpoint|host|server|proxy|dest|destination|redirect|target|src|source|feed|webhook|callback|link|ref|return|path|load|fetch|pull|remote|request)=' \
  | sort -u > "$OUT/urls/ssrf_candidates.txt"

wc -l "$OUT/urls/ssrf_candidates.txt"
head -n 20 "$OUT/urls/ssrf_candidates.txt"
```

---

## PHASE 14 — GraphQL Discovery + Introspection

```bash
GRAPHQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/query" "/gql" "/graphiql" "/playground")

head -n 30 "$OUT/subs/live_http.txt" | while read -r host; do
  for path in "${GRAPHQL_PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' -X POST \
      -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' \
      "$host$path" 2>/dev/null)
    if [ "$code" = "200" ]; then
      echo "[GRAPHQL] $host$path" | tee -a "$OUT/findings/graphql.txt"
      # Try introspection
      curl -s -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { queryType { name } types { name fields { name } } } }"}' \
        "$host$path" | jq '.data.__schema.types[].name' 2>/dev/null \
        | tee -a "$OUT/findings/graphql.txt"
    fi
  done
done
```

---

## PHASE 15 — Org Secret Hunt & Dependency Confusion

```bash
# 1. TruffleHog GitHub org scan
trufflehog github --org="$ORG_NAME" --token="$GITHUB_TOKEN" \
  --json 2>/dev/null | tee "$OUT/findings/trufflehog_github.json"

# 2. Org repos commit scan
gh repo list "$ORG_NAME" --limit 200 --json nameWithOwner \
  | jq -r '.[].nameWithOwner' | while read -r repo; do
    gitleaks detect --repo="https://github.com/$repo" \
      --report-path="$OUT/findings/gitleaks_$(echo "$repo" | tr '/' '_').json" 2>/dev/null
done

# 3. npm package dependency confusion check
cat "$OUT/urls/all.txt" | grep 'package\.json' | while read -r url; do
  curl -sk "$url" 2>/dev/null | jq -r '(.dependencies // {}) + (.devDependencies // {}) | keys[]' 2>/dev/null
done | sort -u > "$OUT/findings/npm_packages.txt"

while read -r pkg; do
  code=$(curl -so /dev/null -w '%{http_code}' "https://registry.npmjs.org/$pkg")
  [ "$code" = "404" ] && echo "[DEP-CONFUSION?] $pkg not on npm" | tee -a "$OUT/findings/dep_confusion.txt"
done < "$OUT/findings/npm_packages.txt"
```

---

## PHASE 16 — Screenshot + Visual Triage

```bash
# Screenshot all live hosts for quick visual review
gowitness file -f "$OUT/subs/live_http.txt" \
  --screenshot-path "$OUT/screenshots/" \
  --resolution 1280x800 2>/dev/null

gowitness report generate --db-path "$OUT/gowitness.sqlite3" 2>/dev/null
```

---

## SEVERITY KILL RULES (Apply Before Writing Any Report)

- **KILL** — Nuclei false positive with no live data exfiltration or reproduction.
- **KILL** — CORS without `Access-Control-Allow-Credentials: true` (unless sensitive authenticated data leaks).
- **KILL** — `.git` exposed that only shows config with no remote URL or usable commits.
- **KILL** — S3 bucket exists but `ListObjects` returns HTTP 403 `AccessDenied`.
- **KILL** — Dependency confusion package name not matching internal corporate naming pattern.
- **DOWNGRADE P1 -> P2** — Secret confirmed live but read-only scope (e.g., viewer token only).
- **KEEP** — Any secret that passes `sts get-caller-identity` / `auth.test` / `/user` endpoint.

---

## PROOF-OF-CONCEPT STANDARD

Every finding must ship with a copyable curl command a triager can run in 60 seconds:

```bash
# PoC Template
curl -sk -X GET "https://TARGET/PATH" \
  -H "Origin: https://evil.com" \
  | jq '.' | head -20
```

Data exfiltration cap: **50 records max**. Prefer `?shallow=true`, `?limit=1`, `COUNT(*)` over bulk data dumps.

---

## COVERAGE LEDGER

Check off each phase on completion. Do not declare recon done until all boxes are ticked:

- [ ] Phase 1 — Passive Subdomain Enumeration
- [ ] Phase 2 — DNS Resolution & httpx Fingerprint Pass
- [ ] Phase 3 — Port Scanning & Service Discovery
- [ ] Phase 4 — Subdomain Takeover Check
- [ ] Phase 5 — Historical URLs & Juicy File Probing
- [ ] Phase 6 — Active Multi-Engine Crawl
- [ ] Phase 7 — Target-Derived Directory & Endpoint Fuzzing
- [ ] Phase 8 — JavaScript Secret Extraction & SSR State
- [ ] Phase 9 — Nuclei Automated Bug Scan
- [ ] Phase 10 — Cloud Storage & Firebase Enumeration
- [ ] Phase 11 — Source Code & Config Exposure Check
- [ ] Phase 12 — CORS Misconfiguration Verification
- [ ] Phase 13 — SSRF Entry Point Parameter Mining
- [ ] Phase 14 — GraphQL Discovery & Schema Introspection
- [ ] Phase 15 — Org Secret Hunt & Dependency Confusion
- [ ] Phase 16 — Headless Screenshots & Visual Triage
- [ ] Consolidated Triage & Ranked PoC Report Generated
