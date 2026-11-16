# Subagent 02: Infrastructure, Edge CDNs, WAFs & Network Services

## Role & Mission
Responsible for fingerprinting perimeter defenses, Web Application Firewalls (WAFs), Content Delivery Networks (CDNs), hosting cloud providers, and raw open port services to establish origin vs edge boundaries.

## Assigned Checklist Tasks (5 Checks)
- **Check 14:** Cloudflare CDN detection via `cf-ray`, headers, and DNS resolution
- **Check 15:** Hosting provider and network origin identification from IP WHOIS and ASN lookup
- **Check 17:** Web Application Firewall (WAF) detection via `wafw00f`
- **Check 18:** CDN provider identification via canonical CNAME chains
- **Check 20:** Service fingerprinting on open ports using `fingerprintx`

---

## Standardized Execution Playbook

### Step 1: Cloudflare & CDN Edge Detection (Checks 14, 18)
Identify if the target sits behind a reverse-proxy CDN or edge cache:

```bash
# 1. Inspect HTTP Headers for CDN Signatures (Check 14)
curl -sIL https://<target> | grep -iE "(cf-ray|cf-cache-status|__cf_bm|x-amz-cf-id|x-cache|x-served-by|fastly-debug|x-azure-ref|akamai-origin-hop)" > artifacts/edge_headers.txt

# 2. Inspect CNAME DNS Resolution for CDN FQDNs (Check 18)
dig +short CNAME <target> > artifacts/cname_cdn.txt

# CDN Fingerprint Patterns:
# - Cloudflare: *.cloudflare.net, cf-ray header
# - CloudFront: *.cloudfront.net, x-amz-cf-id header
# - Fastly: *.fastly.net, *.fastlylb.net, x-served-by header
# - Akamai: *.edgekey.net, *.edgesuite.net, *.akamaiedge.net
# - Azure CDN: *.azureedge.net, *.trafficmanager.net
# - Incapsula/Imperva: *.incapdns.net, X-CDN: Incapsula
```

### Step 2: WAF Detection with Wafw00f (Check 17)
Determine active firewalls to anticipate payload filtering and block behaviors:

```bash
# Execute wafw00f across target
wafw00f https://<target> -a -o artifacts/wafw00f_results.txt

# Common WAF Signatures:
# AWS WAF: Header 'X-AMZN-Waf-Action', Block 403
# Cloudflare WAF: 403 / 503 with Cloudflare Ray ID & CAPTCHA page
# ModSecurity: 'Mod_Security' or 'NOYB'
# F5 BIG-IP ASM: 'TS' cookies (TSxxxxxxxx), 'BigIP'
# Akamai Kona: Reference Error #18.xxx
```

### Step 3: IP WHOIS, ASN & Hosting Provider Profiling (Check 15)
Discover whether the infrastructure is hosted on AWS, GCP, Azure, DigitalOcean, or on-premise datacenter:

```bash
# Resolve IP address
TARGET_IP=$(dig +short <target> | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -n 1)

# ASN & WHOIS Lookup
whois $TARGET_IP | grep -Ei "(OrgName|netname|descr|country|origin|ASN)" > artifacts/hosting_provider.txt

# Or via Amass Intel:
amass intel -addr $TARGET_IP >> artifacts/hosting_provider.txt
```

### Step 4: Service Fingerprinting on Open Ports via Fingerprintx, Naabu & Nmap (Check 20)
Probe non-standard HTTP and service ports to identify backend daemons on non-CDN infrastructure (CDN scanning is wasteful and out-of-scope):

```bash
# 1. Filter out CDN IP addresses from httpx/DNS output to isolate real origin servers
cat artifacts/httpx_results.json 2>/dev/null | jq -r 'select(.cdn==false) | .host' | sort -u > artifacts/non_cdn_ips.txt

# 2. Fast port scan via naabu across top 1000 and sensitive infrastructure ports
naabu -l artifacts/non_cdn_ips.txt -top-ports 1000 \
  -p 80,443,8080,8443,8888,9000,9200,9300,5601,3000,3001,4000,5000,6379,27017,5432,3306,2375,2376 \
  -o artifacts/open_ports.txt -silent

# 3. Service banner & version extraction (nmap on confirmed open ports only)
nmap -iL artifacts/open_ports.txt -sV --open -T4 \
  --script=banner,http-title,http-server-header \
  -oN artifacts/nmap_services.txt -oX artifacts/nmap_services.xml 2>/dev/null

# 4. Run fingerprintx across common web and service ports
fingerprintx -l artifacts/open_ports.txt --json > artifacts/fingerprintx_services.json
```

### Step 5: High-Value Service Signals & Immediate Unauthenticated Verification
When exposed management, database, or orchestration ports are found, execute immediate unauthenticated impact checks:

| Service | Port | Unauthenticated Impact Probe Command | Expected Indicator |
|---|---|---|---|
| **Elasticsearch** | 9200, 9300 | `curl -sk http://IP:9200/_cat/indices?v` | Lists cluster indices and record counts |
| **Kibana** | 5601 | `curl -sk http://IP:5601/api/status` | `status: "green"` and version metadata |
| **Redis** | 6379 | `redis-cli -h IP -p 6379 ping` | Returns `PONG` (No auth required) |
| **MongoDB** | 27017 | `mongo --host IP --eval "db.adminCommand('listDatabases')"` | Returns database catalog object |
| **Docker API** | 2375, 2376 | `curl -sk http://IP:2375/v1.41/containers/json` | Lists active container JSON objects |
| **Kubernetes Kubelet**| 10250, 6443 | `curl -sk https://IP:10250/pods -k` | Returns pod definitions and environment |
| **Spring Actuator** | 8080, 8443 | `curl -sk http://HOST/actuator` | Returns hypermedia links to `/env`, `/beans` |
| **Prometheus** | 9090 | `curl -sk http://HOST:9090/metrics` | Internal metrics and operational counters |
| **Grafana** | 3000 | `curl -sk http://HOST:3000/api/login/ping` | Default credentials `admin:admin` |
| **Jenkins** | 8080 | `curl -sk http://HOST:8080/api/json` | Returns pipeline jobs and build metadata |

### Step 6: Visual Triage & Screenshot Clustering (Gowitness)
Rapidly triage large numbers of discovered HTTP endpoints to spot login portals, default splash pages, and error pages:

```bash
# Screenshot all live HTTP hosts
gowitness file -f artifacts/live_subdomains.txt \
  --screenshot-path artifacts/screenshots/ \
  --resolution 1280x800 2>/dev/null

# Generate visual report database
gowitness report generate --db-path artifacts/gowitness.sqlite3 2>/dev/null
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_02_infra_edge.md`
