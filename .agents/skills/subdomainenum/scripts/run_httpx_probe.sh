#!/usr/bin/env bash
set -euo pipefail

authorized=false
input=""
output_dir=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --authorized) authorized=true; shift ;;
    --input) input="${2:?missing --input value}"; shift 2 ;;
    --output-dir) output_dir="${2:?missing --output-dir value}"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[ "$authorized" = true ] || { printf '%s\n' 'refusing active HTTP probing without --authorized' >&2; exit 2; }
[ -f "$input" ] || { printf 'input file not found: %s\n' "$input" >&2; exit 2; }
[ -n "$output_dir" ] || { printf '%s\n' 'missing --output-dir' >&2; exit 2; }
command -v httpx >/dev/null 2>&1 || { printf '%s\n' 'httpx not found' >&2; exit 127; }

mkdir -p "$output_dir/responses"
normalized="$output_dir/authorized_resolved_input.txt"
awk 'NF { h=tolower($0); sub(/\.$/,"",h); if (h ~ /^([a-z0-9_*-]+\.)+[a-z0-9-]+$/) print h }' "$input" | sort -u > "$normalized"
[ -s "$normalized" ] || { printf '%s\n' 'normalized input is empty' >&2; exit 2; }

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
input_hash="$(sha256sum "$normalized" | awk '{print $1}')"
input_count="$(wc -l < "$normalized" | tr -d ' ')"
set +e
httpx -l "$normalized" \
  -p http:80,8080,8000,8888,3000 -p https:443,8443,9443 \
  -sc -cl -title -td -server -ip -cdn -location -favicon \
  -fr -maxr 3 -fep \
  -rl 50 -t 25 -timeout 8 -retries 2 -random-agent \
  -j -o "$output_dir/httpx.jsonl" \
  -sr -srd "$output_dir/responses" \
  -stats -silent 2> "$output_dir/httpx.stderr.log"
exit_status=$?
set -e
finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

: > "$output_dir/live_urls.txt"
: > "$output_dir/live_hosts.txt"
if [ -s "$output_dir/httpx.jsonl" ]; then
  jq -r 'select(.url != null) | .url' "$output_dir/httpx.jsonl" | sort -u > "$output_dir/live_urls.txt"
  jq -r 'select(.host != null) | .host' "$output_dir/httpx.jsonl" | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u > "$output_dir/live_hosts.txt"
fi

{
  printf 'started_utc=%s\n' "$started"
  printf 'finished_utc=%s\n' "$finished"
  printf 'httpx_version=%s\n' "$(httpx -version 2>&1 | tail -n 1)"
  printf 'input_file=%s\n' "$input"
  printf 'normalized_input_sha256=%s\n' "$input_hash"
  printf 'normalized_input_count=%s\n' "$input_count"
  printf 'exit_status=%s\n' "$exit_status"
  printf 'jsonl_lines=%s\n' "$(wc -l < "$output_dir/httpx.jsonl" 2>/dev/null || printf 0)"
  printf 'live_url_count=%s\n' "$(wc -l < "$output_dir/live_urls.txt")"
  printf 'live_host_count=%s\n' "$(wc -l < "$output_dir/live_hosts.txt")"
  printf '%s\n' 'ports=http:80,8080,8000,8888,3000;https:443,8443,9443'
  printf '%s\n' 'limits=rate:50,threads:25,timeout:8,retries:2,max_redirects:3'
} > "$output_dir/run_metadata.txt"

exit "$exit_status"
