#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: run_permutations.sh --authorized --domain DOMAIN [options]

Options:
  --seeds FILE            Verified seed names (default: artifacts/live_subdomains.txt)
  --resolvers FILE        Validated DNS resolvers (default: resolvers.txt)
  --wordlist FILE         AlterX word payload (auto-detect SecLists 5K tier)
  --out-dir DIR           Output directory (default: artifacts/permutations)
  --max-candidates N      Maximum generated candidates (default: 100000)
  --rate N                DNS queries per second (default: 100)
  --merge                 Merge confirmed additions into the seed file
  --authorized            Confirm active DNS permutation testing is authorized
  -h, --help              Show this help
EOF
}

DOMAIN=""
SEEDS="artifacts/live_subdomains.txt"
RESOLVERS="resolvers.txt"
WORDLIST=""
OUT_DIR="artifacts/permutations"
MAX_CANDIDATES=100000
RATE=100
AUTHORIZED=0
MERGE=0
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

while (($#)); do
  case "$1" in
    --domain) DOMAIN="${2:?missing value for --domain}"; shift 2 ;;
    --seeds) SEEDS="${2:?missing value for --seeds}"; shift 2 ;;
    --resolvers) RESOLVERS="${2:?missing value for --resolvers}"; shift 2 ;;
    --wordlist) WORDLIST="${2:?missing value for --wordlist}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?missing value for --out-dir}"; shift 2 ;;
    --max-candidates) MAX_CANDIDATES="${2:?missing value for --max-candidates}"; shift 2 ;;
    --rate) RATE="${2:?missing value for --rate}"; shift 2 ;;
    --merge) MERGE=1; shift ;;
    --authorized) AUTHORIZED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

((AUTHORIZED == 1)) || { echo "Refusing active DNS testing without --authorized." >&2; exit 2; }
DOMAIN=$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//;s/\.$//')
[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || {
  echo "Invalid root domain: $DOMAIN" >&2; exit 2;
}
[[ "$MAX_CANDIDATES" =~ ^[1-9][0-9]*$ ]] || { echo "--max-candidates must be positive" >&2; exit 2; }
[[ "$RATE" =~ ^[1-9][0-9]*$ ]] || { echo "--rate must be positive" >&2; exit 2; }
[[ -s "$SEEDS" ]] || { echo "Seed file is missing or empty: $SEEDS" >&2; exit 1; }
[[ -s "$RESOLVERS" ]] || { echo "Resolver file is missing or empty: $RESOLVERS" >&2; exit 1; }

for command_name in alterx dnsx jq awk sed sort comm; do
  command -v "$command_name" >/dev/null || { echo "Required command not found: $command_name" >&2; exit 1; }
done

if [[ -z "$WORDLIST" ]]; then
  for candidate in \
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt; do
    if [[ -s "$candidate" ]]; then WORDLIST="$candidate"; break; fi
  done
fi
[[ -s "$WORDLIST" ]] || { echo "No wordlist found; provide --wordlist FILE." >&2; exit 1; }

mkdir -p "$OUT_DIR"
NORMALIZED_SEEDS="$OUT_DIR/seeds.txt"
RAW_GENERATED="$OUT_DIR/raw_generated.txt"
CANDIDATE_DELTA="$OUT_DIR/candidate_delta.txt"
RESOLVED="$OUT_DIR/resolved.jsonl"
FIRST_PASS="$OUT_DIR/resolved_first_pass.jsonl"
NEW_LIVE="$OUT_DIR/new_live_subdomains.txt"
WILDCARD_PROBES="$OUT_DIR/wildcard_probes.jsonl"
METADATA="$OUT_DIR/run_metadata.txt"

awk -v root="$DOMAIN" '
  {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
    sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "")
    sub(/\/.*/, ""); sub(/:[0-9]+$/, ""); sub(/\.$/, "")
    value=tolower($0)
    if (value == root || (length(value) > length(root) && substr(value, length(value)-length(root), length(root)+1) == "." root)) print value
  }
' "$SEEDS" | LC_ALL=C sort -u > "$NORMALIZED_SEEDS"
[[ -s "$NORMALIZED_SEEDS" ]] || { echo "No seed belongs to $DOMAIN" >&2; exit 1; }
BASE_LIMIT=$((MAX_CANDIDATES / 2))
TARGETED_LIMIT=$((MAX_CANDIDATES - BASE_LIMIT))
((BASE_LIMIT > 0)) || BASE_LIMIT=1
((TARGETED_LIMIT > 0)) || TARGETED_LIMIT=1

alterx -list "$NORMALIZED_SEEDS" -enrich -limit "$BASE_LIMIT" -silent \
  -output "$OUT_DIR/enriched_candidates.txt"

alterx -list "$NORMALIZED_SEEDS" -enrich \
  -pattern '{{word}}.{{suffix}},{{word}}-{{sub}}.{{suffix}},{{sub}}-{{word}}.{{suffix}},{{word}}.{{sub}}.{{suffix}},{{sub}}.{{word}}.{{suffix}},{{sub}}{{number}}.{{suffix}}' \
  -payload "word=$WORDLIST" -limit "$TARGETED_LIMIT" -silent \
  -output "$OUT_DIR/targeted_candidates.txt"

cat "$OUT_DIR/enriched_candidates.txt" "$OUT_DIR/targeted_candidates.txt" \
  | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' \
  | awk -v root="$DOMAIN" -v maximum="$MAX_CANDIDATES" '
      length($0)<=253 && length($0)>length(root) && substr($0,length($0)-length(root),length(root)+1)=="." root {
        if (++count <= maximum) print
      }
    ' | LC_ALL=C sort -u > "$RAW_GENERATED"

comm -23 "$RAW_GENERATED" "$NORMALIZED_SEEDS" > "$CANDIDATE_DELTA"

: > "$WILDCARD_PROBES"
for probe_number in 1 2 3 4 5; do
  probe="perm-${probe_number}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n').$DOMAIN"
  printf '%s\n' "$probe" | dnsx -resolver "$RESOLVERS" -a -aaaa -cname -resp -json -silent \
    >> "$WILDCARD_PROBES" 2>/dev/null || true
done

if [[ -s "$CANDIDATE_DELTA" ]]; then
  dnsx -list "$CANDIDATE_DELTA" -resolver "$RESOLVERS" -a -aaaa -cname -resp \
    -auto-wildcard -wildcard-threshold 5 -retry 2 -rate-limit "$RATE" -json -silent \
    -output "$FIRST_PASS"
  jq -r '.host // empty' "$FIRST_PASS" | LC_ALL=C sort -u > "$OUT_DIR/first_pass_live.txt"
  if [[ -s "$OUT_DIR/first_pass_live.txt" ]]; then
    dnsx -list "$OUT_DIR/first_pass_live.txt" -resolver "$RESOLVERS" -a -aaaa -cname -resp \
      -retry 2 -rate-limit "$RATE" -json -silent -output "$RESOLVED"
  else
    : > "$RESOLVED"
  fi
else
  : > "$FIRST_PASS"
  : > "$RESOLVED"
fi

jq -r '.host // empty' "$RESOLVED" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' \
  | awk -v root="$DOMAIN" '$0 == root || (length($0)>length(root) && substr($0,length($0)-length(root),length(root)+1)=="." root)' \
  | LC_ALL=C sort -u > "$NEW_LIVE"

if ((MERGE == 1)); then
  cat "$NORMALIZED_SEEDS" "$NEW_LIVE" | LC_ALL=C sort -u > "$OUT_DIR/live_subdomains.merged"
  mv "$OUT_DIR/live_subdomains.merged" "$SEEDS"
fi

{
  printf 'started_utc=%s\nfinished_utc=%s\n' "$STARTED_UTC" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'domain=%s\nseeds=%s\nresolvers=%s\nwordlist=%s\n' "$DOMAIN" "$SEEDS" "$RESOLVERS" "$WORDLIST"
  printf 'max_candidates=%s\nrate=%s\nmerged=%s\n' "$MAX_CANDIDATES" "$RATE" "$MERGE"
  printf 'seed_count=%s\ngenerated_count=%s\ncandidate_delta_count=%s\nnew_live_count=%s\n' \
    "$(wc -l < "$NORMALIZED_SEEDS")" "$(wc -l < "$RAW_GENERATED")" \
    "$(wc -l < "$CANDIDATE_DELTA")" "$(wc -l < "$NEW_LIVE")"
  alterx -version 2>&1 | head -n 1 || true
  dnsx -version 2>&1 | head -n 1 || true
} > "$METADATA"

echo "Permutation discovery complete: $OUT_DIR"
