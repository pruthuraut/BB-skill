#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: run_portscan.sh --authorized [options]

Options:
  --input FILE           Targets (default: artifacts/live_subdomains.txt)
  --out-dir DIR          Output directory (default: artifacts/network_portscan)
  --engine ENGINE        naabu, nmap, or masscan (default: naabu)
  --rate N               Packet/request rate (default: 1000)
  --concurrency N        Naabu worker count (default: 50)
  --authorized           Confirm every destination is authorized for port scanning
  -h, --help             Show this help
EOF
}

INPUT="artifacts/live_subdomains.txt"
OUT_DIR="artifacts/network_portscan"
ENGINE="naabu"
RATE="1000"
CONCURRENCY="50"
AUTHORIZED=0

while (($#)); do
  case "$1" in
    --input) INPUT="${2:?missing value for --input}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?missing value for --out-dir}"; shift 2 ;;
    --engine) ENGINE="${2:?missing value for --engine}"; shift 2 ;;
    --rate) RATE="${2:?missing value for --rate}"; shift 2 ;;
    --concurrency) CONCURRENCY="${2:?missing value for --concurrency}"; shift 2 ;;
    --authorized) AUTHORIZED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

((AUTHORIZED == 1)) || { echo "Refusing to scan without --authorized." >&2; exit 2; }
[[ "$RATE" =~ ^[1-9][0-9]*$ ]] || { echo "--rate must be a positive integer" >&2; exit 2; }
[[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]] || { echo "--concurrency must be a positive integer" >&2; exit 2; }
[[ "$ENGINE" =~ ^(naabu|nmap|masscan)$ ]] || { echo "Unsupported engine: $ENGINE" >&2; exit 2; }
if [[ ! -s "$INPUT" && "$INPUT" == "artifacts/live_subdomains.txt" && -s artifacts/resolved_subdomains.json ]]; then
  command -v jq >/dev/null || { echo "jq is required to read artifacts/resolved_subdomains.json" >&2; exit 1; }
  mkdir -p "$OUT_DIR"
  jq -r '.host // empty' artifacts/resolved_subdomains.json > "$OUT_DIR/targets_from_resolved.txt"
  INPUT="$OUT_DIR/targets_from_resolved.txt"
fi
[[ -s "$INPUT" ]] || { echo "Target input is missing or empty: $INPUT" >&2; exit 1; }

for command_name in nmap awk sed sort getent; do
  command -v "$command_name" >/dev/null || { echo "Required command not found: $command_name" >&2; exit 1; }
done
command -v python3 >/dev/null || { echo "Required command not found: python3" >&2; exit 1; }
command -v "$ENGINE" >/dev/null || { echo "Selected engine not found: $ENGINE" >&2; exit 1; }
if [[ "$ENGINE" == naabu ]]; then
  command -v jq >/dev/null || { echo "Required command not found: jq" >&2; exit 1; }
fi

mkdir -p "$OUT_DIR/nmap/discovery" "$OUT_DIR/nmap/services"
TARGETS="$OUT_DIR/targets.txt"
TARGET_IP_MAP="$OUT_DIR/target_ip_map.tsv"
OPEN_PORTS="$OUT_DIR/open_ports.tsv"
COVERAGE="$OUT_DIR/coverage.tsv"
METADATA="$OUT_DIR/run_metadata.txt"

awk '
  {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
    sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "")
    sub(/\/.*/, "")
    sub(/^[^@]*@/, "")
    if ($0 ~ /^\[[0-9A-Fa-f:]+\](:[0-9]+)?$/) {
      sub(/^\[/, ""); sub(/\](:[0-9]+)?$/, "")
    } else {
      sub(/:[0-9]+$/, "")
    }
    if ($0 != "" && $0 !~ /^#/) print tolower($0)
  }
' "$INPUT" | LC_ALL=C sort -u > "$TARGETS"

[[ -s "$TARGETS" ]] || { echo "No valid targets remained after normalization." >&2; exit 1; }

: > "$TARGET_IP_MAP"
while IFS= read -r target; do
  while IFS= read -r ip; do
    printf '%s\t%s\n' "$target" "$ip" >> "$TARGET_IP_MAP"
  done < <(getent ahosts "$target" 2>/dev/null | awk '$2=="STREAM"{print $1}' | sort -u)
done < "$TARGETS"

{
  printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'authorized_confirmed=true\nengine=%s\nrate=%s\nconcurrency=%s\ninput=%s\n' "$ENGINE" "$RATE" "$CONCURRENCY" "$INPUT"
  printf 'target_count=%s\nresolved_address_count=%s\n' "$(wc -l < "$TARGETS")" "$(wc -l < "$TARGET_IP_MAP")"
  "$ENGINE" -version 2>&1 | head -n 2 || true
  nmap --version 2>&1 | head -n 1 || true
} > "$METADATA"

: > "$OPEN_PORTS"
printf 'target\tports\n' > "$COVERAGE"

run_targeted_nmap() {
  local target="$1" ports="$2" safe
  safe=$(printf '%s' "$target" | sed 's/[^A-Za-z0-9._-]/_/g')
  nmap -Pn -sV -sC --open -p "$ports" "$target" \
    -oA "$OUT_DIR/nmap/services/$safe"
}

case "$ENGINE" in
  naabu)
    RAW="$OUT_DIR/naabu.jsonl"
    naabu -list "$TARGETS" -top-ports full -c "$CONCURRENCY" -rate "$RATE" -json -silent -o "$RAW"
    jq -r 'select(.port != null) | [(.host // .ip), (.port | tostring)] | @tsv' "$RAW" \
      | LC_ALL=C sort -u > "$OPEN_PORTS"
    ;;
  nmap)
    : > "$OUT_DIR/nmap_discovery.gnmap"
    while IFS= read -r target; do
      safe=$(printf '%s' "$target" | sed 's/[^A-Za-z0-9._-]/_/g')
      nmap -Pn -p- --min-rate "$RATE" -T4 --open "$target" -oA "$OUT_DIR/nmap/discovery/$safe"
      cat "$OUT_DIR/nmap/discovery/$safe.gnmap" >> "$OUT_DIR/nmap_discovery.gnmap"
      awk -v target="$target" '/Ports:/{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\/open\//){split($i,p,"/"); print target "\t" p[1]}}' \
        "$OUT_DIR/nmap/discovery/$safe.gnmap" >> "$OPEN_PORTS"
    done < "$TARGETS"
    LC_ALL=C sort -u -o "$OPEN_PORTS" "$OPEN_PORTS"
    ;;
  masscan)
    IPS="$OUT_DIR/masscan_ips.txt"
    awk -F '\t' '$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print $2}' "$TARGET_IP_MAP" | sort -u > "$IPS"
    [[ -s "$IPS" ]] || { echo "Masscan mode requires resolved, authorized IPv4 targets." >&2; exit 1; }
    masscan -p1-65535 -iL "$IPS" --rate "$RATE" -oG "$OUT_DIR/masscan.gnmap"
    awk '/Ports:/{ip=$2; for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\/open\//){split($i,p,"/"); print ip "\t" p[1]}}' \
      "$OUT_DIR/masscan.gnmap" | LC_ALL=C sort -u > "$OPEN_PORTS"
    ;;
esac

if [[ -s "$OPEN_PORTS" ]]; then
  while IFS= read -r target; do
    ports=$(awk -F '\t' -v target="$target" '$1==target{print $2}' "$OPEN_PORTS" | sort -nu | paste -sd, -)
    [[ -n "$ports" ]] || continue
    printf '%s\t%s\n' "$target" "$ports" >> "$COVERAGE"
    run_targeted_nmap "$target" "$ports"
  done < <(cut -f1 "$OPEN_PORTS" | sort -u)
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python3 "$SCRIPT_DIR/parse_nmap_xml.py" "$OUT_DIR/nmap/services"/*.xml > "$OUT_DIR/services.tsv"

printf 'finished_utc=%s\nopen_endpoint_count=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(wc -l < "$OPEN_PORTS")" >> "$METADATA"
echo "Port scan complete: $OUT_DIR"
