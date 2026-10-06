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

Permutation expansion is a supplemental discovery stage supporting Checks 18 and 19; it does not inflate the 50-check completion count.

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
*Methodology:* Treat verified names as evidence of the target's naming conventions. Extract recurring application, environment, region, and numeric labels; then generate a bounded candidate delta around those observations. Do not pipe an unbounded generator directly into resolution because that loses provenance, makes wildcard analysis difficult, and can create millions of low-value queries.

Use three complementary passes:

1. **Observed-name enrichment:** Let `alterx` learn words and numbers from the verified seed set and apply its maintained patterns.
2. **Targeted structural mutations:** Apply dash and dot variations around observed labels, such as environment-before-service, service-before-environment, nested environment labels, and numeric iterations.
3. **Apex label expansion:** Apply a bounded SecLists DNS label tier to the root domain. Start with the 5,000-label list, move to 20,000 only when scope and rate limits permit it, and reserve the 110,000 tier for explicitly expanded runs.

Keep seeds, raw generated names, the candidate delta, DNS evidence, wildcard-filtered results, and new verified names as separate artifacts. Normalize to lowercase FQDNs beneath the exact target suffix and subtract `live_subdomains.txt` before sending DNS queries.

The repository runner implements this flow:

```bash
.agents/skills/subdomainenum/scripts/run_permutations.sh \
  --authorized \
  --domain <target> \
  --seeds artifacts/live_subdomains.txt \
  --resolvers resolvers.txt
```

The default cap is 100,000 generated candidates and the default DNS rate is 100 queries/second. Adjust them downward to match program limits. Use `--wordlist` to select a different authorized tier and `--max-candidates` to make the expansion budget explicit.

Only append `artifacts/permutations/new_live_subdomains.txt` after reviewing `resolved.jsonl` and wildcard evidence. Rerun with `--merge` to update the seed inventory after that review. The runner requires two successful resolution passes and applies automatic wildcard filtering; retain ambiguous wildcard matches outside the live inventory.

**Permutation artifacts:**

- `artifacts/permutations/seeds.txt` — normalized verified inputs
- `artifacts/permutations/raw_generated.txt` — all bounded AlterX output
- `artifacts/permutations/candidate_delta.txt` — generated names not already known
- `artifacts/permutations/resolved.jsonl` — A/AAAA/CNAME response evidence
- `artifacts/permutations/new_live_subdomains.txt` — verified additions only
- `artifacts/permutations/run_metadata.txt` — inputs, limits, rates, tool versions, and counts
- `artifacts/permutations/wildcard_probes.jsonl` — randomized negative-control responses

---

## Output Artifact
Aggregate and normalize all outputs from this subagent into:
`artifacts/subagent_03_active_results.txt`
```bash
cat artifacts/live_subdomains.txt srv_records.txt | sort -u > artifacts/subagent_03_active_results.txt
```
