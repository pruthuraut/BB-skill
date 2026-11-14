#!/usr/bin/env bash
# Scope gate for all active testing. Exits 0 only if the target is listed in
# its own scope file. Nothing is assumed authorized.
#
# Usage: scope_check.sh TARGET_DOMAIN [WORKSPACE_ROOT]
#
# Scope file: $WORKSPACE_ROOT/<target>/scope.txt (default root: ~/Documents/bugbounty)
# Required lines:
#   authorized-by: <who granted the testing, e.g. program name or "owner">
#   date: <YYYY-MM-DD>
# Scope lines (one per line):
#   example.com        -> example.com and every *.example.com
#   !admin.example.com -> excluded, never tested even if matched above
set -euo pipefail

target="${1:-}"
root="${2:-${BB_WORKSPACE:-$HOME/Documents/bugbounty}}"
[ -n "$target" ] || { echo "usage: scope_check.sh TARGET_DOMAIN [WORKSPACE_ROOT]" >&2; exit 2; }

target="$(printf '%s' "$target" | tr '[:upper:]' '[:lower:]' | sed -E 's#^https?://##; s#/.*$##; s#\.$##')"
scope_file="$root/$target/scope.txt"

deny() { echo "SCOPE DENIED: $1" >&2; exit 3; }

[ -f "$scope_file" ] || deny "no scope file at $scope_file (create it with authorized-by, date, and in-scope lines)"
grep -qiE '^authorized-by:[[:space:]]*[^[:space:]]' "$scope_file" || deny "scope file lacks 'authorized-by:'"
grep -qE '^date:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' "$scope_file" || deny "scope file lacks 'date: YYYY-MM-DD'"

matches() {  # $1 = pattern (domain, no leading !), returns 0 if target equals or is a subdomain
  local p="$1"
  [ "$target" = "$p" ] || [[ "$target" == *".$p" ]]
}

in_scope=0
while IFS= read -r line; do
  line="$(printf '%s' "$line" | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' | tr '[:upper:]' '[:lower:]')"
  [ -z "$line" ] && continue
  case "$line" in
    authorized-by:*|date:*) continue ;;
    !*) matches "${line#!}" && deny "target is explicitly excluded: ${line#!}" ;;
    *)  matches "$line" && in_scope=1 ;;
  esac
done < "$scope_file"

[ "$in_scope" = 1 ] || deny "$target is not listed in $scope_file"
echo "scope ok: $target (see $scope_file)"
