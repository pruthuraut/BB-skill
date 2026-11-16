# Subagent 01: High-Speed Recursive Fuzzers & Crawlers

## Role & Mission
Responsible for active path enumeration using multi-threaded fuzzing tools (`ffuf`, `gobuster`, `dirsearch`, `feroxbuster`), smart HTTP status code filtering, recursion tuning, and rate-limiting safeguards.

## Assigned Checklist Tasks (4 Checks)
- **Check 01:** `ffuf` fast directory and file fuzzing with recursive mode
- **Check 02:** `gobuster` directory/file brute forcing with high concurrency
- **Check 03:** `dirsearch` recursive directory scanning with multi-extension matrices
- **Check 04:** `feroxbuster` recursive content discovery with auto-filtering and autotune

---

## Standardized Execution Playbook

### Step 1: Baseline Calibration & Soft 404 Detection
Before launching large-scale brute-force, identify wildcard response sizes to calibrate filter switches:

```bash
# Calibrate ffuf baseline filter size
RANDOM_SLUG="probe-slug-$(date +%s%N)"
CALIBRATE_RESP=$(curl -sI "https://<target>/${RANDOM_SLUG}" | head -n 1)
echo "Calibration status: $CALIBRATE_RESP"
```

### Step 2: Target-Derived Wordlist Generation
Before relying solely on generic wordlists, extract paths and directory segments observed in the target's historical and crawled URL corpus to build a high-conversion, target-tailored wordlist:

```bash
# Extract path tokens from crawled and historical URLs
cat artifacts/all_discovered_urls.txt 2>/dev/null | unfurl paths | tr '/' '\n' | \
  sort | uniq -c | sort -rn | awk '$1>1{print $2}' | grep -vE "^[0-9]+$" > artifacts/custom_wordlist.txt

# Merge with core fuzzing dictionaries
cat artifacts/custom_wordlist.txt wordlists/MiniFuzz.txt | sort -u > artifacts/combined_wordlist.txt
```

### Step 3: Ffuf Recursive & Multi-Host Content Fuzzing (Check 01)
Utilize `artifacts/combined_wordlist.txt` or `wordlists/MiniFuzz.txt` with auto-calibration (`-ac`):

```bash
WORDLIST="artifacts/combined_wordlist.txt"

# 1. Single target recursive fuzzing
ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST" \
  -recursion -recursion-depth 2 \
  -e .php,.asp,.aspx,.json,.html,.txt \
  -mc 200,201,204,301,302,307,401,403 \
  -ac \
  -t 40 \
  -o artifacts/ffuf_results.json -of json

# 2. Batch fuzzing across top live HTTP subdomains
head -n 20 artifacts/live_subdomains.txt | while read -r HOST; do
  SAFE_NAME=$(echo "$HOST" | tr '/:' '_')
  ffuf -u "${HOST}/FUZZ" \
    -w "$WORDLIST" \
    -mc 200,201,204,301,302,307,401,403 \
    -ac -t 30 -timeout 10 \
    -o "artifacts/ffuf_${SAFE_NAME}.json" 2>/dev/null
done
```

### Step 3: Gobuster Multi-Threaded Verification (Check 02)
```bash
gobuster dir -u "https://<target>/" \
  -w "$WORDLIST" \
  -t 40 \
  -s "200,204,301,302,307,401,403" \
  -b "404,500" \
  -k \
  -o artifacts/gobuster_results.txt
```

### Step 4: Dirsearch with Deep Extension Matrices (Check 03)
```bash
dirsearch -u "https://<target>/" \
  -w "$WORDLIST" \
  -e php,asp,aspx,jsp,html,json,txt,action,do \
  -r --recursion-depth 2 \
  --random-agent \
  -t 30 \
  -o artifacts/dirsearch_results.txt
```

### Step 5: Feroxbuster Smart Auto-Tuned Crawling (Check 04)
```bash
feroxbuster -u "https://<target>/" \
  -w "$WORDLIST" \
  --smart \
  --depth 2 \
  --threads 30 \
  --extract-links \
  --auto-tune \
  -o artifacts/feroxbuster_results.txt
```

---

## Output Artifact
Aggregate discovered paths into:
`artifacts/subagent_01_fuzzing_paths.txt`
