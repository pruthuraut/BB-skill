#!/usr/bin/env bash
# Scope-gated sqlmap / ghauri wrapper that enforces the skill's execution classes.
#
# Usage:
#   sqlmap_safe.sh TARGET -u 'https://app.example.com/item?id=1' -p id [--dbms=MySQL] [--technique=BT] ...
#   sqlmap_safe.sh TARGET -r artifacts/sqli/req_item.txt -p id --level 3
#   SQLMAP=ghauri sqlmap_safe.sh TARGET -r req.txt -p id          # ghauri accepts the same core flags
#
# Always refused (class X / destructive): --os-shell --os-pwn --os-cmd --os-smbrelay --os-bof --priv-esc
#   --reg-read/add/del --file-write --file-dest --sql-shell --udf-inject --shared-lib --eval -m -g -l -x (unscoped target sources)
# Class S (needs BB_SQLI_ALLOW_DATA=1): --dump --dump-all --passwords --search --tables --columns --schema
#   --count --users --privileges --roles --sql-query --common-tables --common-columns --statements
# Class X file read (needs BB_SQLI_ALLOW_FILE=1): --file-read
# --risk=3 (OR-based payloads can rewrite every row of an UPDATE/DELETE) needs BB_SQLI_ALLOW_RISK3=1.
# Allowed proof flags (class P): -b/--banner --current-user --current-db --hostname --is-dba -f/--fingerprint --dbs
# Defaults added when absent: --batch --delay=0.5 --timeout=30 --retries=1 --threads=1 --output-dir=artifacts/sqli/sqlmap
# --threads is capped at 3.
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
TARGET=$(printf '%s' "$1" | tr 'A-Z' 'a-z'); shift
HERE=$(cd "$(dirname "$0")" && pwd)
GATE="$HERE/../../../../scripts/scope_check.sh"
BIN=${SQLMAP:-sqlmap}

deny() { echo "[sqlmap_safe] refused: $*" >&2; exit 3; }
need() { [ "${!1:-0}" = "1" ] || deny "$2 requires $1=1 (explicit program permission for that class)"; }

args=("$@")
url=""; req=""; has_delay=0; has_batch=0; has_timeout=0; has_retries=0; has_threads=0; has_out=0
i=0
while [ $i -lt ${#args[@]} ]; do
  a=${args[$i]}
  key=${a%%=*}
  val=""
  [[ "$a" == *=* ]] && val=${a#*=}
  nextval() { if [ -n "$val" ]; then printf '%s' "$val"; else printf '%s' "${args[$((i+1))]:-}"; fi; }
  case "$key" in
    --os-shell|--os-pwn|--os-cmd|--os-smbrelay|--os-bof|--priv-esc|--reg-read|--reg-add|--reg-del|--reg-key|\
    --file-write|--file-dest|--sql-shell|--udf-inject|--shared-lib|--eval|-m|-g|-l|-x)
      deny "$key is outside this skill (command execution, file write, shells, or unscoped target sources)";;
    --dump|--dump-all|--passwords|--search|--tables|--columns|--schema|--count|--users|--privileges|--roles|\
    --sql-query|--common-tables|--common-columns|--statements|-D|-T|-C)
      need BB_SQLI_ALLOW_DATA "$key (class S data access)";;
    --file-read) need BB_SQLI_ALLOW_FILE "$key (class X file read)";;
    --risk)
      r=$(nextval); [ "$r" = "3" ] && need BB_SQLI_ALLOW_RISK3 "--risk=3";;
    --threads)
      t=$(nextval); has_threads=1
      [ "$t" -le 3 ] 2>/dev/null || deny "--threads $t exceeds the cap of 3";;
    -u|--url) url=$(nextval);;
    -r) req=$(nextval);;
    --delay) has_delay=1;;
    --batch) has_batch=1;;
    --timeout) has_timeout=1;;
    --retries) has_retries=1;;
    --output-dir) has_out=1;;
  esac
  i=$((i+1))
done

if [ -n "$url" ]; then
  host=$(printf '%s' "$url" | sed -E 's#^[a-zA-Z]+://##; s#^[^@/]*@##; s#[/:?\#].*$##' | tr 'A-Z' 'a-z')
elif [ -n "$req" ]; then
  [ -f "$req" ] || deny "request file $req not found"
  host=$(grep -im1 '^host:' "$req" | sed -E 's/^[Hh][Oo][Ss][Tt]:[[:space:]]*//; s/:[0-9]+[[:space:]]*$//; s/[[:space:]]//g' | tr 'A-Z' 'a-z')
else
  deny "give -u URL or -r REQUEST_FILE"
fi
[ -n "$host" ] || deny "could not determine the request host"
if [ "$host" != "$TARGET" ] && [[ "$host" != *".$TARGET" ]]; then
  deny "host $host is outside target $TARGET"
fi
bash "$GATE" "$host" || exit $?

extra=()
[ $has_batch -eq 1 ] || extra+=(--batch)
[ $has_delay -eq 1 ] || extra+=(--delay=0.5)
[ $has_timeout -eq 1 ] || extra+=(--timeout=30)
[ $has_retries -eq 1 ] || extra+=(--retries=1)
[ $has_threads -eq 1 ] || extra+=(--threads=1)
if [ $has_out -eq 0 ] && [ "$(basename "$BIN")" = "sqlmap" ]; then
  mkdir -p artifacts/sqli/sqlmap
  extra+=(--output-dir=artifacts/sqli/sqlmap)
fi
command -v "$BIN" >/dev/null 2>&1 || deny "$BIN not installed (see SETUP.md) - or set SQLMAP=/path/to/sqlmap"
echo "[sqlmap_safe] $BIN ${args[*]} ${extra[*]}" >&2
exec "$BIN" "${args[@]}" "${extra[@]}"
