# API Keys & Tool Configuration Reference for Subdomain Enumeration

To achieve 100% discovery fidelity across the 50 checks, passive tools must be authenticated with their respective free or paid API keys. Below are the configuration paths, environment variables, and config templates.

---

## 1. Subfinder Provider Configuration (`~/.config/subfinder/provider-config.yaml`)

Subfinder uses a YAML file to query multiple passive sources concurrently. 
Create or edit `~/.config/subfinder/provider-config.yaml`:

```yaml
# Subfinder v2 Provider Configuration
binaryedge: []
bufferover: []
c99: []
censys:
  - "<CENSYS_API_ID>:<CENSYS_API_SECRET>"
certspotter:
  - "<CERTSPOTTER_API_TOKEN>"
chaos:
  - "<CHAOS_API_KEY>"
chinaz: []
dnsdb: []
fofa:
  - "<FOFA_EMAIL>:<FOFA_KEY>"
fullhunt: []
github:
  - "<GITHUB_PERSONAL_ACCESS_TOKEN>"
hunter: []
intelx: []
passivetotal: []
recon:
  - "<RECON_DEV_API_KEY>"
robtex: []
securitytrails:
  - "<SECURITYTRAILS_API_KEY>"
shodan:
  - "<SHODAN_API_KEY>"
threatbook: []
virustotal:
  - "<VIRUSTOTAL_API_KEY>"
whoisxmlapi: []
zoomeye:
  - "<ZOOMEYE_API_KEY>"
```

**Execution with API Providers:**
```bash
subfinder -d <target.com> -all -cs -provider-config ~/.config/subfinder/provider-config.yaml -o subfinder_raw.txt
```

---

## 2. OWASP Amass Configuration (`~/.config/amass/config.ini` or `datasources.yaml`)

In Amass v3/v4, data sources are configured in `datasources.yaml`:

```yaml
datasources:
  - name: Censys
    creds:
      apikey: "<CENSYS_API_ID>"
      secret: "<CENSYS_API_SECRET>"
  - name: Chaos
    creds:
      apikey: "<CHAOS_API_KEY>"
  - name: GitHub
    creds:
      apikey: "<GITHUB_PERSONAL_ACCESS_TOKEN>"
  - name: SecurityTrails
    creds:
      apikey: "<SECURITYTRAILS_API_KEY>"
  - name: Shodan
    creds:
      apikey: "<SHODAN_API_KEY>"
  - name: VirusTotal
    creds:
      apikey: "<VIRUSTOTAL_API_KEY>"
  - name: FOFA
    creds:
      username: "<FOFA_EMAIL>"
      apikey: "<FOFA_KEY>"
  - name: ZoomEye
    creds:
      apikey: "<ZOOMEYE_API_KEY>"
```

**Amass Passive & Active Execution:**
```bash
# Pure Passive with Data Sources
amass enum -passive -d <target.com> -config ~/.config/amass/datasources.yaml -o amass_passive.txt

# Active with ASN Correlation (TBHM v4 Haddix Method)
amass enum -active -d <target.com> -brute -w /path/to/commonspeak2.txt -rf /path/to/resolvers.txt -o amass_active.txt
```

---

## 3. Environment Variables (Universal Agent Standard)

Set these environment variables in your environment (`.env` or shell export) so subagents and scripts can ingest them automatically:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SHODAN_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export CENSYS_API_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export CENSYS_API_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SECURITYTRAILS_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export VIRUSTOTAL_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export CHAOS_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export FOFA_EMAIL="user@example.com"
export FOFA_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ZOOMEYE_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export RECON_DEV_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export CERTSPOTTER_TOKEN="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## 4. Multi-Token GitHub Scraping Configuration (`github-subdomains.py`)
*TBHM v4 Slide 39 Rule:* GitHub rate limits searches severely. Use multiple Personal Access Tokens (PATs) and introduce a 6-second sleep between requests:

```bash
python3 github-subdomains.py -d <target.com> -t $GITHUB_TOKEN -o github_subs.txt
```

---

## 5. High-Performance Resolvers List (`resolvers.txt`)
*TBHM v4 Rule:* Never brute-force or resolve with ISP or default home DNS. Validate a fresh public resolver pool using `dnsvalidator`:

```bash
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
```
