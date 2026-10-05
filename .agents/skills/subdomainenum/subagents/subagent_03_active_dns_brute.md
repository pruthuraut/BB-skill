# Subagent 03: Active DNS Resolution, Bruting, Permutations & Wildcards

## Role & Mission
Responsible for active DNS operations: DNS zone transfer checks (AXFR), massive multi-resolver brute-forcing, wildcard DNS detection & filtering, high-speed resolution (massdns/dnsx), SRV record probing, and DNSSEC zone walking.

## Assigned Checklist Tasks (8 Checks)
- **Check 05:** Knockpy subdomain enumeration & DNS zone transfer check
- **Check 17:** DNS brute force with `dnsrecon` / `shuffledns` using vetted wordlists
- **Check 18:** `massdns` high-throughput DNS resolution
- **Check 19:** Wildcard DNS response detection and false-positive stripping
- **Check 20:** DNS Zone Transfer (AXFR) attempts against all authoritative nameservers
- **Check 26:** DNSSEC verification and NSEC zone walking misconfiguration checks
- **Check 27:** Nmap `dns-brute` script execution
- **Check 45:** DNSrecon SRV service record enumeration

---

## Standardized Execution Playbook

### Step 1: Authoritative Nameserver Discovery & AXFR Testing (Checks 05, 20)
Before any brute forcing, identify the authoritative nameservers and test for zone transfers:

```bash
# 1. Discover NS records
dig +short NS <target> > nameservers.txt

# 2. Check AXFR on each nameserver (Check 20)
for ns in $(cat nameservers.txt); do
  echo "[*] Testing AXFR on $ns..."
  dig axfr @$ns <target> | grep -E "IN[ \t]+(A|CNAME)" > "axfr_${ns}.txt"
  if [ -s "axfr_${ns}.txt" ]; then
    echo "[!] CRITICAL: Full Zone Transfer enabled on $ns!"
    cat "axfr_${ns}.txt" | awk '{print $1}' | sed 's/\.$//' >> axfr_discovered.txt
  fi
done

# 3. Knockpy with Zone Transfer Check (Check 05)
knockpy <target> --dns resolvers.txt --json -o knockpy_out/
```

### Step 2: DNSSEC Verification & NSEC Zone Walking (Check 26)
If DNSSEC is misconfigured using `NSEC` instead of `NSEC3`, the entire zone can be enumerated by following the chain of next existing records:

```bash
# Verify DNSSEC
delv <target>
dig +dnssec <target>

# Attempt NSEC Zone Walking using ldns-walk
ldns-walk @$(head -n 1 nameservers.txt) <target> > nsec_walk.txt 2>/dev/null
if [ -s "nsec_walk.txt" ]; then
  cat nsec_walk.txt | awk '{print $1}' | sed 's/\.$//' | sort -u >> dnssec_discovered.txt
fi
```

### Step 3: Wildcard DNS Detection (TBHM v4 Haddix Slide 44 & Check 19)
*Critical Heuristic:* If `randomstring99182374.<target>` resolves, wildcard DNS is enabled. If you do not filter wildcards, your brute-force will yield 100,000+ false positives.

```bash
# Test random non-existent host
RANDOM_HOST="rand-check-$(date +%s%N).<target>"
WILDCARD_IP=$(dig +short $RANDOM_HOST)

if [ -n "$WILDCARD_IP" ]; then
  echo "[!] WARNING: Wildcard DNS detected resolving to: $WILDCARD_IP"
  export HAS_WILDCARD=true
else
  echo "[+] No Wildcard DNS detected."
  export HAS_WILDCARD=false
fi
```

### Step 4: High-Performance Multi-Resolver Brute-Force (Checks 17, 18, 27)
*Tooling Selection (TBHM v4 Slides 43-47):*
Use `shuffledns` (which wraps `massdns`) or direct `massdns` + `dnsx` paired with Jason Haddix's `all.txt` or Assetnote's `commonspeak2`.

```bash
# 1. Prepare trusted resolver pool
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

# 2. ShuffleDNS Brute-forcing (Handles wildcards automatically)
shuffledns -d <target> \
  -w /path/to/commonspeak2-subdomains.txt \
  -r resolvers.txt \
  -m $(which massdns) \
  -o shuffledns_brute.txt

# 3. Nmap DNS Brute Script (Check 27)
nmap --script dns-brute --script-args dns-brute.domain=<target>,dns-brute.threads=25 -oN nmap_dns_brute.txt
```

### Step 5: Mass Resolution & Wildcard Filtering with `dnsx` (Checks 18, 19)
Merge all passive candidates with active brute candidates and resolve with wildcard stripping:

```bash
# Combine all discovered candidate hostnames
cat artifacts/subagent_01_passive_results.txt \
    artifacts/subagent_02_dorking_results.txt \
    shuffledns_brute.txt \
    axfr_discovered.txt \
    dnssec_discovered.txt | sort -u > all_unresolved_candidates.txt

# Resolve using dnsx with automated wildcard filtering (-wd)
dnsx -l all_unresolved_candidates.txt \
  -r resolvers.txt \
  -wd <target> \
  -a -cname -resp \
  -json -o artifacts/resolved_subdomains.json

# Extract clean live FQDNs
cat artifacts/resolved_subdomains.json | jq -r '.host' | sort -u > artifacts/live_subdomains.txt
```

### Step 6: SRV Record Enumeration (Check 45)
```bash
# Check 45: Discover internal services (SIP, LDAP, Kerberos, XMPP, Autodiscover)
dnsrecon -d <target> -t srv | grep -E "SRV[ \t]+" | awk '{print $NF}' | sed 's/\.$//' | sort -u > srv_records.txt
```

### Step 7: Permutation & Alteration Scanning (TBHM v4 Haddix Slide 48)
*Methodology:* Analyze resolved live names and generate permutations (`dev-api`, `api-staging`, `internal-vpn`):

```bash
# Run alterx or gotator on resolved subdomains
alterx -l artifacts/live_subdomains.txt -o permutations.txt
# Resolve newly generated permutations
dnsx -l permutations.txt -r resolvers.txt -wd <target> -o artifacts/live_permutations.txt
cat artifacts/live_permutations.txt >> artifacts/live_subdomains.txt
sort -u artifacts/live_subdomains.txt -o artifacts/live_subdomains.txt
```

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_03_active_results.txt`
```bash
cat artifacts/live_subdomains.txt srv_records.txt | sort -u > artifacts/subagent_03_active_results.txt
```
