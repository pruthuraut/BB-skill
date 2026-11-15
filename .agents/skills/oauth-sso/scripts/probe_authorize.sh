#!/usr/bin/env bash
# Pre-authentication redirect_uri validation differential (OA-03/04).
# Sends each candidate authorize URL WITHOUT cookies and records how the
# authorization server reacts: a validation error vs. a redirect to its login
# page (= the redirect_uri passed initial validation) vs. a redirect straight
# to the candidate (= error-path open redirect, OA-04).
#
# Usage:
#   probe_authorize.sh --target DOMAIN --urls artifacts/oauth/redirect_candidates.tsv
#                      [--delay 1] [--out artifacts/oauth/authorize_probe.tsv] [--max 200]
#
# Input: TSV from redirect_uri_variants.py (3rd column = authorize URL).
set -euo pipefail

TARGET="" URLS="" DELAY=1 OUT="artifacts/oauth/authorize_probe.tsv" MAX=200
usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --urls)   URLS="$2"; shift 2 ;;
    --delay)  DELAY="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    --max)    MAX="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$TARGET" ] && [ -f "$URLS" ] || usage

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../../scripts/scope_check.sh"
target_lc="$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')"

first_url="$(awk -F'\t' 'NR>1 && $3!="" {print $3; exit}' "$URLS")"
[ -n "$first_url" ] || { echo "no authorize URLs in column 3 (run redirect_uri_variants.py with --authorize)" >&2; exit 2; }
as_host="$(printf '%s' "$first_url" | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##' | tr '[:upper:]' '[:lower:]')"
if [ "$as_host" != "$target_lc" ] && [[ "$as_host" != *".$target_lc" ]]; then
  echo "authorization server $as_host is outside target $TARGET; refusing (third-party IdPs are not probed)" >&2; exit 3
fi
"$GATE" "$as_host" || exit $?

mkdir -p "$(dirname "$OUT")"
printf 'category\thttp_code\tlocation_host\tverdict\tbytes\tredirect_uri\n' > "$OUT"
n=0
while IFS=$'\t' read -r cat ruri aurl; do
  [ "$cat" = "category" ] && continue
  [ -n "$aurl" ] || continue
  n=$((n + 1)); [ "$n" -gt "$MAX" ] && break
  hdr="$(mktemp)"
  meta="$(curl -sk --max-time 15 -o /dev/null -D "$hdr" -w '%{http_code}\t%{size_download}' "$aurl" || printf '000\t0')"
  code="${meta%%$'\t'*}"; bytes="${meta##*$'\t'}"
  loc="$(tr -d '\r' < "$hdr" | awk 'tolower($1)=="location:" {sub(/^[^:]*:[ \t]*/, ""); print; exit}')"
  rm -f "$hdr"
  lhost="$(printf '%s' "$loc" | sed -E 's#^[a-zA-Z]+://##; s#[/:?\#].*$##' | tr '[:upper:]' '[:lower:]')"
  verdict="other"
  if [ -n "$loc" ]; then
    case "$loc" in
      *error=*) verdict="redirect-with-error" ;;
    esac
    if [ "$lhost" = "$as_host" ] || [ -z "$lhost" ]; then
      [ "$verdict" = "other" ] && verdict="to-login/consent (passed pre-auth validation?)"
    elif [[ "$loc" == *"$lhost"* ]] && [[ "$ruri" == *"$lhost"* ]]; then
      verdict="REDIRECTED-TO-CANDIDATE ($verdict) - check OA-04"
    fi
  elif [ "$code" = "200" ]; then
    verdict="200 page (login form or error page; compare bytes with baseline)"
  elif [[ "$code" =~ ^4 ]]; then
    verdict="rejected"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$cat" "$code" "${lhost:--}" "$verdict" "$bytes" "$ruri" | tee -a "$OUT"
  sleep "$DELAY"
done < "$URLS"
echo "[+] $n candidates probed -> $OUT"
echo "    Rows whose code/bytes match the 'baseline' row passed pre-auth validation: confirm them in your victim browser."
