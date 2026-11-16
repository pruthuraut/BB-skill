# Subagent 05: DNS Records, SPF/DMARC, Cloud Infra & Network Auditing

## Role & Mission
Responsible for mining domain and network infrastructure: parsing mail records (SPF/DMARC/MX), scanning TLS/SSL Subject Alternative Names (SAN), discovering cloud storage subdomains (AWS S3, Azure Blob, GCP Storage), auditing internal RFC 1918 IP address leaks, and detecting Punycode / IDN homograph variations.

## Assigned Checklist Tasks (8 Checks)
- **Check 22:** Extract subdomains from SPF records via `include:` and `a:` mechanisms
- **Check 23:** Extract subdomains from DMARC aggregate reports (`rua` and `ruf` tags)
- **Check 29:** Identify internal IP address leaks (RFC 1918 / loopback) in DNS records
- **Check 36:** Query Rapid7 Open Data (Project Sonar) Forward DNS datasets
- **Check 37:** Enumerate cloud subdomains (AWS S3, Azure Blob, GCP Storage, Cloud SSL ranges)
- **Check 38:** Analyze subdomains leaked in email headers (DKIM selectors, MX records)
- **Check 40:** Check for Punycode / Internationalized Domain Name (IDN) homograph variants
- **Check 46:** Direct HTTP/TLS certificate parsing via `openssl s_client`

---

## Standardized Execution Playbook

### Step 1: Mail Security Records Analysis (SPF & DMARC - Checks 22, 23, 38)
Mail infrastructure configurations often list internal mail gateways, support portals, and third-party relay hosts.

```bash
# 1. SPF Record Parsing (Check 22)
dig +short TXT <target> | grep "v=spf1" | tr ' ' '\n' | while read entry; do
  case "$entry" in
    include:*|a:*|mx:*)
      domain=$(echo "$entry" | cut -d':' -f2)
      if echo "$domain" | grep -q "<target>"; then
        echo "$domain" >> spf_subdomains.txt
      fi
      ;;
  esac
done

# 2. DMARC Aggregate Mailbox Hostnames (Check 23)
dig +short TXT _dmarc.<target> | grep -oE "mailto:[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.<target>)" | \
  cut -d'@' -f2 >> dmarc_subdomains.txt

# 3. DKIM Selectors & MX Records (Check 38)
dig +short MX <target> | awk '{print $2}' | sed 's/\.$//' | grep -E "\.<target>$" >> email_infra_subs.txt
for selector in default google k1 mail smtp api dkim2023; do
  dig +short TXT "${selector}._domainkey.<target>" >/dev/null 2>&1
  # If selector resolves, note the record
done
```

### Step 2: Internal IP Address Leak Auditing (Check 29)
*Vulnerability Identification:* DNS records resolving to private IP space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) can expose internal services, staging topologies, or enable DNS rebinding attacks.

```bash
# Audit all resolved records for RFC 1918 IPs
jq -r 'select(.a[]? | test("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|127\\.0\\.0)")) | "\(.host) -> \(.a[])"' artifacts/resolved_subdomains.json > artifacts/internal_ip_leaks.txt

if [ -s "artifacts/internal_ip_leaks.txt" ]; then
  echo "[!] HIGH: Internal RFC 1918 IP address leaks discovered!"
  cat artifacts/internal_ip_leaks.txt
fi
```

### Step 3: Direct TLS/SSL Certificate Subject Alternative Name (SAN) Parsing (Check 46)
Webservers often serve multi-domain certificates that list sibling subdomains in the SAN field:

```bash
# Probe ports 443, 8443, 4443
for port in 443 8443; do
  echo | openssl s_client -connect <target>:${port} -servername <target> 2>/dev/null | \
    openssl x509 -noout -text 2>/dev/null | \
    grep -A1 "Subject Alternative Name:" | \
    grep -oE "DNS:([a-zA-Z0-9._-]+\.<target>)" | sed 's/DNS://g' >> tls_cert_subs.txt
done
```

### Step 4: Cloud Subdomain Enumeration (TBHM v4 Slide 41 & Check 37)
*Methodology:* Discover cloud assets across AWS S3 buckets, Azure Blob storage, and GCP Cloud Storage bearing the target's naming format:

```bash
# 1. Cloudlist (ProjectDiscovery)
cloudlist -d <target> > cloud_assets.txt

# 2. Permutation check for cloud storage buckets
for prefix in "" "dev-" "staging-" "prod-" "assets-" "backup-"; do
  for suffix in "" "-assets" "-backup" "-static" "-internal"; do
    bucket="${prefix}<target_clean>${suffix}"
    # AWS S3 check
    curl -s -I "https://${bucket}.s3.amazonaws.com" | head -n 1 | grep -q "403\|200" && echo "Found S3: ${bucket}" >> cloud_buckets.txt
    # Azure Blob check
    curl -s -I "https://${bucket}.blob.core.windows.net" | head -n 1 | grep -q "400\|200" && echo "Found Azure: ${bucket}" >> cloud_buckets.txt
  done
done
```

### Step 5: Rapid7 Project Sonar Datasets (Check 36)
```bash
# Query FDNS dataset mirrors
curl -s "https://scans.io/data/rapid7/sonar.fdns_v2/" | grep -oE "([a-zA-Z0-9._-]+\.<target>)" >> sonar_subs.txt
```

### Step 6: Punycode / IDN Homograph Analysis (Check 40)
*Methodology:* Convert target characters into lookalike Cyrillic or Greek homoglyphs (e.g. `а` vs `a`), convert to Punycode (`xn--...`), and verify if any variations are registered or active:

```bash
python3 -c "
target = '<target>'
# Example: replace latin 'a' with cyrillic 'а' (\u0430)
if 'a' in target:
    spoofed = target.replace('a', '\u0430')
    punycode = spoofed.encode('idna').decode('utf-8')
    print(f'Punycode variant: {punycode}')
" > punycode_variants.txt
```

### Step 7: Favicon Hash Enumeration (TBHM v4 Haddix Slide 51)
*Methodology:* Calculate the MurmurHash3 (mmh3) of the favicon and query Shodan:

```bash
python3 -c "
import requests, mmh3, codecs
try:
    response = requests.get('https://<target>/favicon.ico', verify=False, timeout=5)
    favicon = codecs.encode(response.content, 'base64')
    hash_val = mmh3.hash(favicon)
    print(f'Favicon MMH3 Hash: {hash_val}')
    print(f'Shodan Query: http.favicon.hash:{hash_val}')
except:
    pass
" > favicon_hash.txt
```

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_05_infra_results.txt`
```bash
cat spf_subdomains.txt dmarc_subdomains.txt email_infra_subs.txt tls_cert_subs.txt cloud_assets.txt sonar_subs.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | tr '[:upper:]' '[:lower:]' | grep -E "\.<target>$" | sort -u > artifacts/subagent_05_infra_results.txt
```
