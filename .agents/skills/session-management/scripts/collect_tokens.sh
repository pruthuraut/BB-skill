#!/usr/bin/env bash
# Collect freshly issued (unauthenticated) session tokens for entropy analysis (SM-01/02).
# Scope-gated, rate-limited, GET-only by default.
#
# Usage:
#   collect_tokens.sh --target DOMAIN --url URL --cookie NAME [--count 200] [--delay 0.25]
#                     [--out artifacts/session/tokens_raw.txt] [--header 'Name: value']
#
# Each request is made with an empty cookie jar so the server issues a new token.
set -euo pipefail

TARGET="" URL="" COOKIE="" COUNT=200 DELAY=0.25 OUT="artifacts/session/tokens_raw.txt"
EXTRA_HEADERS=()

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --url)    URL="$2"; shift 2 ;;
    --cookie) COOKIE="$2"; shift 2 ;;
    --count)  COUNT="$2"; shift 2 ;;
    --delay)  DELAY="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    --header) EXTRA_HEADERS+=(-H "$2"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$TARGET" ] && [ -n "$URL" ] && [ -n "$COOKIE" ] || usage
[[ "$COUNT" =~ ^[0-9]+$ ]] && [ "$COUNT" -ge 1 ] && [ "$COUNT" -le 20000 ] || { echo "--count must be 1..20000" >&2; exit 2; }

# The URL host must belong to the authorized target.
url_host="$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##' | tr '[:upper:]' '[:lower:]')"
target_lc="$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')"
if [ "$url_host" != "$target_lc" ] && [[ "$url_host" != *".$target_lc" ]]; then
  echo "URL host '$url_host' is not within target '$TARGET'" >&2; exit 3
fi

"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../../scripts/scope_check.sh" "$url_host" || exit $?

mkdir -p "$(dirname "$OUT")"
: > "$OUT"
echo "[*] Collecting $COUNT '$COOKIE' tokens from $URL (delay ${DELAY}s) -> $OUT"

got=0 miss=0
for ((i = 1; i <= COUNT; i++)); do
  hdrs="$(curl -sk -o /dev/null -D - --max-time 15 "${EXTRA_HEADERS[@]}" "$URL" || true)"
  tok="$(printf '%s\n' "$hdrs" | tr -d '\r' \
        | awk -v n="$COOKIE" 'tolower($1)=="set-cookie:" { sub(/^[^:]*:[ \t]*/, ""); split($0, kv, ";");
                               split(kv[1], p, "="); if (p[1]==n) { sub(/^[^=]*=/, "", kv[1]); print kv[1]; exit } }')"
  if [ -n "$tok" ]; then
    printf '%s\n' "$tok" >> "$OUT"; got=$((got + 1))
  else
    miss=$((miss + 1))
    if [ "$miss" -ge 10 ] && [ "$got" -eq 0 ]; then
      echo "[!] No '$COOKIE' Set-Cookie in the first 10 responses; check cookie name/URL." >&2; exit 1
    fi
  fi
  [ $((i % 50)) -eq 0 ] && echo "    $i/$COUNT requests, $got tokens"
  sleep "$DELAY"
done

echo "[+] Collected $got tokens ($miss responses without the cookie)."
echo "    Next: python3 -I $(dirname "$0")/token_entropy.py $OUT"
