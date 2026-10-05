#!/usr/bin/env bash
# jsx_pipeline.sh -- Master Bug Bounty JavaScript Reconnaissance Pipeline
# Multi-source harvesting -> Live probing -> Local bundle caching -> js-beautify -> 
# Source map unpacking -> 60+ Secret patterns -> Deep endpoint extraction -> TruffleHog / Slack alerting.

set -uo pipefail

to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

sha1_of_string() {
  if command -v sha1sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha1sum | cut -c1-40
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 1 | cut -c1-40
  else
    printf '%s' "$1" | openssl sha1 | awk '{print $NF}'
  fi
}

mktmpdir() {
  local d
  d="$(mktemp -d 2>/dev/null || mktemp -d -t jsx_recon)"
  printf '%s' "$d"
}

run_with_timeout() {
  local to="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$to" 2>/dev/null; kill -9 "$pid" 2>/dev/null ) &
  local watcher=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  return $rc
}

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

OUT="artifacts/js_recon"
THREADS=20
LIMIT="-"
DOMAINS_STR=""
LISTFILE=""
RUN_TH=false
TH_ALL=false
SLACK_WEBHOOK=""
SKIP_WAYBACK=false
SKIP_GAU=false
SKIP_KATANA=false
HTTP_TIMEOUT=25
TOOL_TIMEOUT=900

log()  { printf '%s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }
err()  { printf '[x] %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
jsx_pipeline.sh -- Master Bug Bounty JavaScript Reconnaissance Engine

Usage:
  ./jsx_pipeline.sh -u example.com
  ./jsx_pipeline.sh -l domains.txt -n 1000 -t 25 -o artifacts/js_recon
  ./jsx_pipeline.sh -u example.com --trufflehog --slack <webhook_url>

Options:
  -u <domain>         Target domain (repeatable or space-separated in quotes)
  -l <file>           File containing target domains (one per line)
  -n <N|->            Max JS files to download ('-' = all, default: all)
  -o <dir>            Output base directory (default: artifacts/js_recon)
  -t <N>              Parallel threads for downloading & scanning (default: 20)
  --trufflehog        Run TruffleHog on downloaded JS files
  --th-all            TruffleHog: include unverified secrets (default: verified only)
  --slack <url>       Slack Incoming Webhook URL for alerting on high-value secrets
  --skip-wayback      Skip Wayback CDX mining
  --skip-gau          Skip gau mining
  --skip-katana       Skip Katana active crawler
  -h, --help          Show this help message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -u) DOMAINS_STR="$DOMAINS_STR $2"; shift 2 ;;
    -l) LISTFILE="$2"; shift 2 ;;
    -n) LIMIT="$2"; shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    --trufflehog) RUN_TH=true; shift ;;
    --th-all) TH_ALL=true; shift ;;
    --slack) SLACK_WEBHOOK="$2"; shift 2 ;;
    --skip-wayback) SKIP_WAYBACK=true; shift ;;
    --skip-gau) SKIP_GAU=true; shift ;;
    --skip-katana) SKIP_KATANA=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [ -n "$LISTFILE" ]; then
  if [ ! -f "$LISTFILE" ]; then err "List file not found: $LISTFILE"; exit 1; fi
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && DOMAINS_STR="$DOMAINS_STR $line"
  done < "$LISTFILE"
fi

if [ -z "$DOMAINS_STR" ]; then
  if [ -s "artifacts/live_subdomains.txt" ]; then
    log "[+] No target explicitly provided: automatically adopting 'artifacts/live_subdomains.txt' from subdomainenum agent..."
    while IFS= read -r line; do
      line="$(printf '%s' "$line" | tr -d '[:space:]')"
      [ -n "$line" ] && DOMAINS_STR="$DOMAINS_STR $line"
    done < "artifacts/live_subdomains.txt"
  else
    usage
    err "Target domain required: supply -u <domain>, -l <file>, or ensure artifacts/live_subdomains.txt exists"
    exit 1
  fi
fi

clean_domain() {
  local d
  d="$(to_lower "$1")"
  d="${d#http://}"
  d="${d#https://}"
  d="${d%%/*}"
  d="${d%%\?*}"
  printf '%s' "$d"
}

DOMAINS=""
for d in $DOMAINS_STR; do
  c="$(clean_domain "$d")"
  [ -z "$c" ] && continue
  case " $DOMAINS " in
    *" $c "*) : ;;
    *) DOMAINS="$DOMAINS $c" ;;
  esac
done
DOMAINS="${DOMAINS# }"

mkdir -p "$OUT" || exit 1

log "==================================================================="
log "[*] Master JS Recon Pipeline Active"
log "[*] Targets       : $DOMAINS"
log "[*] JS Cap Limit  : $LIMIT"
log "[*] Concurrency   : $THREADS threads"
log "[*] Base Directory: $(cd "$OUT" && pwd)"
log "[*] TruffleHog    : $RUN_TH"
log "==================================================================="

have() { command -v "$1" >/dev/null 2>&1; }

send_slack() {
  local msg="$1"
  [ -z "$SLACK_WEBHOOK" ] && return 0
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"[JS-RECON ALERT] $msg\"}" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Harvesting Functions
# ---------------------------------------------------------------------------
collect_wayback() {
  local d="$1"
  local to=$HTTP_TIMEOUT
  [ "$to" -lt 60 ] && to=60
  for pattern in "*.${d}/*" "${d}/*"; do
    curl -sS --max-time "$to" -A "$UA" \
      "http://web.archive.org/cdx/search/cdx?url=${pattern}&output=text&fl=original&collapse=urlkey" \
      2>/dev/null || true
  done
}

collect_gau() {
  local d="$1"
  if ! have gau; then return 0; fi
  run_with_timeout "$TOOL_TIMEOUT" gau --subs --threads 5 "$d" 2>/dev/null || true
}

collect_katana() {
  local d="$1"
  if ! have katana; then return 0; fi
  katana -u "https://$d" -d 3 -jc -silent -concurrency "$THREADS" 2>/dev/null || true
}

collect_hakrawler() {
  local d="$1"
  if ! have hakrawler; then return 0; fi
  echo "https://$d" | hakrawler -depth 2 -plain -subs 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Worker Engine
# ---------------------------------------------------------------------------
write_patterns_file() {
  local path="$1"
  cat > "$path" <<'PATTERNS_EOF'
AWS Access Key ID|\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b
AWS Secret Access Key|aws.{0,30}["']([0-9a-zA-Z/+]{40})["']
AWS S3 Bucket URL|[a-z0-9.-]+\.s3([.-][a-z0-9-]+)?\.amazonaws\.com
AWS Cognito Pool|[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com
Google API Key|AIza[0-9A-Za-z_-]{35}
Google OAuth Client ID|[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
Firebase Realtime DB|https?://[a-z0-9-]+\.firebaseio\.com
Firebase Appspot|[a-z0-9-]+\.appspot\.com
Firebase Config Object|(apiKey|authDomain|databaseURL|storageBucket|messagingSenderId)["']?[[:space:]]*[:=][[:space:]]*["'][^"']{8,}["']
Azure Blob Storage|https?://[a-z0-9]+\.blob\.core\.windows\.net
Heroku API Key|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
DigitalOcean Token|dop_v1_[a-f0-9]{64}
Cloudinary URL|cloudinary://[0-9]{6,}:[A-Za-z0-9_-]+@[a-z0-9-]+
Mapbox Token|pk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{20,}
Algolia Key|algolia.{0,30}["'][a-z0-9]{32}["']
Contentful Token|contentful.{0,30}["'][A-Za-z0-9_-]{43}["']
Datadog API Key|datadog.{0,30}[a-f0-9]{32}
Sentry DSN|https://[0-9a-f]{32}@[a-z0-9.-]+/[0-9]+
Shopify Token|(shpat|shpca|shppa|shpss)_[a-f0-9]{32}
npm Token|npm_[A-Za-z0-9]{36}
PyPI Token|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}
Postman API Key|PMAK-[a-f0-9]{24}-[a-f0-9]{34}
Telegram Bot Token|[0-9]{8,10}:AA[0-9A-Za-z_-]{33}
OpenAI Key|sk-(proj-)?[A-Za-z0-9_-]{20,}
Anthropic Key|sk-ant-[A-Za-z0-9_-]{20,}
HuggingFace Token|hf_[A-Za-z0-9]{34}
GitHub Token|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}
GitHub Fine-Grained PAT|github_pat_[A-Za-z0-9_]{82}
GitLab PAT|glpat-[A-Za-z0-9_-]{20}
Slack Token|xox[baprs]-[A-Za-z0-9-]{10,}
Slack Webhook|https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}
Discord Webhook|https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}
Twilio Account SID|AC[a-f0-9]{32}
Twilio API Key|SK[a-f0-9]{32}
SendGrid Key|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
Mailgun Key|key-[a-z0-9]{32}
Mailchimp Key|[0-9a-f]{32}-us[0-9]{1,2}
Stripe Live Secret|sk_live_[A-Za-z0-9]{24,}
Stripe Live Publishable|pk_live_[A-Za-z0-9]{24,}
Stripe Restricted|rk_live_[A-Za-z0-9]{24,}
JWT Token|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}
Private Key Block|-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----
Basic Auth in URL|[a-zA-Z][a-zA-Z0-9+.-]{2,10}://[^/[:space:]:@'\"]{2,40}:[^/[:space:]:@'\"]{3,40}@[^[:space:]/'\"]+
Bearer Token|[Bb]earer[[:space:]]+[A-Za-z0-9._~+/-]{15,}=*
Authorization Header|["']?[Aa]uthorization["']?[[:space:]]*[:=][[:space:]]*["'][^"']{15,}["']
Hardcoded Password|(password|passwd|pwd|pass)["']?[[:space:]]*[:=][[:space:]]*["'][^"'[:space:]]{6,}["']
Generic API Key/Secret|(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?[[:space:]]*[:=][[:space:]]*["'][A-Za-z0-9-_.]{16,}["']
Private Key in JSON|["']private[_-]?key["'][[:space:]]*:[[:space:]]*["'][^"']{20,}["']
Encryption Key/IV|(aes|encryption)[_-]?(key|iv|secret)["']?[[:space:]]*[:=][[:space:]]*["'][A-Za-z0-9+/=]{16,}["']
GraphQL Endpoint|["'`](/[A-Za-z0-9_/-]*(graphql|gql)[A-Za-z0-9_/-]*)["'`]
Swagger/OpenAPI Spec|["'`][A-Za-z0-9_/-]*(swagger|openapi)[A-Za-z0-9_.-]*\.(json|ya?ml)["'`]
API Versioned Endpoint|["'`](/api/[A-Za-z0-9_/{}$.-]{2,80})["'`]
Admin/Internal Path|["'`](/[A-Za-z0-9_/-]*(admin|internal|private|debug|actuator|console|manage)[A-Za-z0-9_/-]*)["'`]
Source Map Reference|//[#@][[:space:]]*sourceMappingURL=([^[:space:]]+)
Localhost/Internal URL|https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:[0-9]{1,5})?
Private IP Address|(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}
Internal Hostname|[a-z0-9-]+\.(local|internal|corp|lan|intranet)
WebSocket Endpoint|wss?://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9_/.?=&%]*
postMessage Listener|addEventListener\([[:space:]]*["']message["']
Dangerous HTML Sink|(innerHTML|outerHTML|insertAdjacentHTML)[[:space:]]*=
document.write Sink|document\.write(ln)?\(
eval() Usage|\beval[[:space:]]*\(
new Function() Usage|\bnew[[:space:]]+Function[[:space:]]*\(
React dangerouslySetInnerHTML|dangerouslySetInnerHTML
Vue v-html|v-html[[:space:]]*=
Debug/Dev Flag Enabled|(debug|devMode|isDev|testMode|enableDebug)["']?[[:space:]]*[:=][[:space:]]*(true|1|["']true["'])
PATTERNS_EOF
  chmod +r "$path"
}

write_worker_lib() {
  local path="$1"
  cat > "$path" <<'WORKER_LIB_EOF'
#!/usr/bin/env bash

ua_scan() {
  if command -v sha1sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha1sum | cut -c1-40
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 1 | cut -c1-40
  else
    printf '%s' "$1" | openssl sha1 | awk '{print $NF}'
  fi
}

safe_name() {
  local url="$1"
  local base hash
  base="${url%%\?*}"
  base="${base##*/}"
  base="$(printf '%s' "$base" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-60)"
  [ -z "$base" ] && base="index.js"
  hash="$(ua_scan "$url")"
  printf '%s_%s' "$(printf '%s' "$hash" | cut -c1-10)" "$base"
}

scan_one() {
  local url="$1" f="$2" out="$3"
  [ -s "$f" ] || return 0
  head -c 200 "$f" 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -q '^<!doctype html\|^<html' && return 0

  local title rx hits val
  while IFS='|' read -r title rx; do
    [ -z "$title" ] && continue
    [ -z "$rx" ] && continue
    hits="$(grep -Eo -m 5 "$rx" "$f" 2>/dev/null || true)"
    [ -z "$hits" ] && continue
    printf '%s\n' "$hits" | while IFS= read -r val; do
      [ -z "$val" ] && continue
      val="$(printf '%s' "$val" | tr -d '\r\n' | cut -c1-160)"
      printf '%s > %s: %s\n' "$url" "$title" "$val" >> "$out"
    done
  done < "$PATTERNS_FILE"
}
WORKER_LIB_EOF
  chmod +x "$path"
}

write_worker() {
  local libpath="$1" workerpath="$2"
  cat > "$workerpath" <<WORKER_EOF
#!/usr/bin/env bash
. "$libpath"

url="\$1"
name="\$(safe_name "\$url")"
dst_raw="\$RAW_JS_DIR/\$name"
dst_beauty="\$BEAUTY_JS_DIR/\$name"

code="\$(curl -sSL --max-time "\$HTTP_TIMEOUT" --compressed -A "\$UA" \
        -o "\$dst_raw" -w '%{http_code}' "\$url" 2>/dev/null)"

case "\$code" in
  2*)
    if [ -s "\$dst_raw" ]; then
      printf '%s\t%s\n' "\$url" "\$dst_raw" >> "\$DOWNLOADED_FILE"
      
      # Beautify / De-minify if js-beautify is available
      if command -v js-beautify >/dev/null 2>&1; then
        js-beautify "\$dst_raw" > "\$dst_beauty" 2>/dev/null || cp "\$dst_raw" "\$dst_beauty"
      else
        cp "\$dst_raw" "\$dst_beauty"
      fi

      tmpf="\$TMPDIR_RES/\$(printf '%s' "\$url" | cksum | awk '{print \$1}').out"
      scan_one "\$url" "\$dst_beauty" "\$tmpf"

      # Check for exposed source maps (.js.map)
      map_url="\${url}.map"
      map_code="\$(curl -sI --max-time 10 -A "\$UA" -o /dev/null -w '%{http_code}' "\$map_url" 2>/dev/null)"
      if [ "\$map_code" = "200" ]; then
        printf '%s\n' "\$map_url" >> "\$MAPS_FOUND_FILE"
        curl -sSL --max-time "\$HTTP_TIMEOUT" -A "\$UA" -o "\$MAPS_DIR/\${name}.map" "\$map_url" 2>/dev/null || true
      fi
    fi
    ;;
  *)
    rm -f "\$dst_raw"
    ;;
esac
WORKER_EOF
  chmod +x "$workerpath"
}

# ---------------------------------------------------------------------------
# Deep Endpoint & Parameter Extraction
# ---------------------------------------------------------------------------
extract_endpoints_and_params() {
  local bdir="$1" ddir="$2"
  log "    [*] Extracting endpoints & parameters from beautified files..."

  local ep_dir="$ddir/endpoints"
  mkdir -p "$ep_dir"

  # Way 1: Absolute paths starting with /
  grep -roE "['\"](\/[a-zA-Z0-9\-_\.\/]{2,100})['\"]" "$bdir" 2>/dev/null | \
    sed "s/['\"]//g" | awk -F: '{print $NF}' | sort -u > "$ep_dir/endpoints_absolute.txt"

  # Way 2: High-Value keywords (/api/, /v1/, /admin/, /internal/, /graphql/)
  grep -roE "['\"](\/(api|v1|v2|v3|internal|admin|staff|graphql|console|debug)\/[^'\"]+)['\"]" "$bdir" 2>/dev/null | \
    sed "s/['\"]//g" | awk -F: '{print $NF}' | sort -u > "$ep_dir/endpoints_highvalue.txt"

  # Way 3: Dynamic paths with template variables ${id}
  grep -roE "['\"](\/[a-zA-Z0-9\-_\.\/]*\$\{[a-zA-Z0-9_-]+\}[a-zA-Z0-9\-_\.\/]*)['\"]" "$bdir" 2>/dev/null | \
    sed "s/['\"]//g" | awk -F: '{print $NF}' | sort -u > "$ep_dir/endpoints_dynamic.txt"

  # Way 4: React / Vue / Angular Route paths
  grep -roE "path\s*:\s*['\"][^'\"]+['\"]" "$bdir" 2>/dev/null | \
    sed "s/path\s*:\s*['\"]//;s/['\"]//" | awk -F: '{print $NF}' | sort -u > "$ep_dir/endpoints_routes.txt"

  # Way 5: Object Body Parameters
  grep -roiE "(userId|orgId|accountId|tenantId|teamId|projectId|role|isAdmin|isOwner|plan|trial|status|permission|scope)" "$bdir" 2>/dev/null | \
    awk -F: '{print $NF}' | sort -u > "$ep_dir/parameters_body.txt"

  # Way 6: Query String Parameters (?id=, ?page=)
  grep -roE "\?[a-zA-Z0-9_\-]+=" "$bdir" 2>/dev/null | \
    sed 's/?//;s/=//' | awk -F: '{print $NF}' | sort -u > "$ep_dir/parameters_query.txt"

  # Clean CDN False Positives and Merge Final Master List
  cat "$ep_dir"/endpoints_*.txt 2>/dev/null | \
    grep -vE "(cdnjs|googleapis|jquery|bootstrap|react|angular|lodash|moment|npm|github)" | \
    sort -u > "$ddir/ALL_DISCOVERED_ENDPOINTS.txt"

  local nep
  nep="$(wc -l < "$ddir/ALL_DISCOVERED_ENDPOINTS.txt" | tr -d ' ')"
  log "    [+] Discovered $nep unique application endpoints -> $ddir/ALL_DISCOVERED_ENDPOINTS.txt"
}

# ---------------------------------------------------------------------------
# TruffleHog Integration
# ---------------------------------------------------------------------------
run_trufflehog() {
  local domain="$1" jsdir="$2" ddir="$3"
  local tdir="$ddir/tools"
  mkdir -p "$tdir"

  if ! have trufflehog; then
    warn "TruffleHog not installed. Run: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
    return
  fi

  log ""
  log "[*] Running TruffleHog verification scan on $jsdir ..."

  local raw="$tdir/trufflehog.jsonl"
  local txt="$tdir/trufflehog_verified_findings.txt"

  if [ "$TH_ALL" = false ]; then
    trufflehog filesystem "$jsdir" --json --no-update --concurrency "$THREADS" --only-verified > "$raw" 2>/dev/null || true
  else
    trufflehog filesystem "$jsdir" --json --no-update --concurrency "$THREADS" > "$raw" 2>/dev/null || true
  fi

  local count=0
  if [ -s "$raw" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local det ver src show
      det="$(printf '%s' "$line" | grep -oE '"DetectorName":"[^"]+"' | head -n1 | cut -d'"' -f4)"
      ver="$(printf '%s' "$line" | grep -oE '"Verified":(true|false)' | head -n1 | cut -d: -f2)"
      src="$(printf '%s' "$line" | grep -oE '"file":"[^"]+"' | head -n1 | cut -d'"' -f4)"
      show="$(printf '%s' "$line" | grep -oE '"Redacted":"[^"]*"' | head -n1 | cut -d'"' -f4)"
      [ "$ver" = "true" ] && printf '[VERIFIED %s] in %s: %s\n' "$det" "$src" "$show" >> "$txt"
      count=$(( count + 1 ))
    done < "$raw"
    log "    [+] TruffleHog identified $count verified credentials -> $txt"
    if [ -n "$SLACK_WEBHOOK" ] && [ "$count" -gt 0 ]; then
      send_slack "TruffleHog verified $count live credentials on $domain!"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Process Target Domain
# ---------------------------------------------------------------------------
process_domain() {
  local domain="$1"
  local ddir="$OUT/$domain"
  local raw_dir="$ddir/js_raw"
  local beauty_dir="$ddir/js_beautified"
  local maps_dir="$ddir/js_maps"
  mkdir -p "$raw_dir" "$beauty_dir" "$maps_dir"

  log ""
  log ">>> Processing Target: $domain"

  local urls="$ddir/urls_all.txt"
  : > "$urls"

  # 0. Ingest existing artifacts from subdomainenum and contentdiscovery (Zero-Redundancy)
  local inherited=0
  for art in "artifacts/all_discovered_urls.txt" "artifacts/discovered_endpoints.txt" "artifacts/js_files.txt" "artifacts/subagent_01_crawler_links.txt"; do
    if [ -s "$art" ]; then
      grep -i "$domain" "$art" >> "$urls" 2>/dev/null || true
    fi
  done
  sort -u "$urls" -o "$urls"
  inherited="$(wc -l < "$urls" | tr -d ' ')"
  if [ "$inherited" -gt 0 ]; then
    log "    [+] Inherited $inherited URLs from prior agent artifacts (subdomainenum / contentdiscovery)!"
  fi

  # 1. Active & Historical URL Harvesting (Gap-filling if needed)
  if [ "$SKIP_WAYBACK" = false ]; then
    log "    [1/4] Querying Wayback Machine CDX API..."
    collect_wayback "$domain" > "$ddir/urls_wayback.txt" 2>/dev/null || true
    cat "$ddir/urls_wayback.txt" >> "$urls"
  fi

  if [ "$SKIP_GAU" = false ]; then
    log "    [2/4] Harvesting historical archives via gau..."
    collect_gau "$domain" > "$ddir/urls_gau.txt" 2>/dev/null || true
    cat "$ddir/urls_gau.txt" >> "$urls"
  fi

  if [ "$SKIP_KATANA" = false ]; then
    log "    [3/4] Live crawling via Katana..."
    collect_katana "$domain" > "$ddir/urls_katana.txt" 2>/dev/null || true
    cat "$ddir/urls_katana.txt" >> "$urls"
  fi

  log "    [4/4] Fast link traversal via Hakrawler..."
  collect_hakrawler "$domain" > "$ddir/urls_hakrawler.txt" 2>/dev/null || true
  cat "$ddir/urls_hakrawler.txt" >> "$urls"

  sort -u "$urls" -o "$urls"
  local total_harvested
  total_harvested="$(wc -l < "$urls" | tr -d ' ')"
  log "    [*] Total raw URLs collected: $total_harvested"

  # 2. Extension Sorting & Separation
  grep -E "\.js(\?.*)?$" "$urls" | sed -E 's/[?#].*$//' | sort -u > "$ddir/js_urls_all.txt"
  grep -E "\.(json|xml)(\?.*)?$" "$urls" | sort -u > "$ddir/data_endpoints_all.txt"
  grep "=" "$urls" | sort -u > "$ddir/parameterized_urls_all.txt"

  local total_js
  total_js="$(wc -l < "$ddir/js_urls_all.txt" | tr -d ' ')"
  log "    [*] Extracted unique JS URLs : $total_js"
  log "    [*] Extracted Data endpoints : $(wc -l < "$ddir/data_endpoints_all.txt" | tr -d ' ')"
  log "    [*] Extracted Parameter URLs : $(wc -l < "$ddir/parameterized_urls_all.txt" | tr -d ' ')"

  if [ "$LIMIT" = "-" ]; then
    cp "$ddir/js_urls_all.txt" "$ddir/js_urls_to_download.txt"
  else
    head -n "$LIMIT" "$ddir/js_urls_all.txt" > "$ddir/js_urls_to_download.txt"
  fi

  local selected
  selected="$(wc -l < "$ddir/js_urls_to_download.txt" | tr -d ' ')"
  if [ "$selected" -eq 0 ]; then
    warn "No JavaScript URLs found for $domain"
    return
  fi

  # 3. Setup Worker Execution & Pattern Engine
  local tmp_root
  tmp_root="$(mktmpdir)"
  local pat_file="$tmp_root/patterns.txt"
  local lib_file="$tmp_root/lib.sh"
  local worker="$tmp_root/worker.sh"
  local findings_tmp="$tmp_root/findings_parts"
  mkdir -p "$findings_tmp"

  write_patterns_file "$pat_file"
  write_worker_lib "$lib_file"
  write_worker "$lib_file" "$worker"

  export UA
  export HTTP_TIMEOUT
  export PATTERNS_FILE="$pat_file"
  export RAW_JS_DIR="$raw_dir"
  export BEAUTY_JS_DIR="$beauty_dir"
  export MAPS_DIR="$maps_dir"
  export TMPDIR_RES="$findings_tmp"
  export DOWNLOADED_FILE="$ddir/js_downloaded.txt"
  export MAPS_FOUND_FILE="$ddir/sourcemaps_found.txt"

  : > "$DOWNLOADED_FILE"
  : > "$MAPS_FOUND_FILE"

  log "    [*] Downloading, Beautifying & Scanning $selected JS files (threads=$THREADS)..."
  xargs -P "$THREADS" -n 1 "$worker" < "$ddir/js_urls_to_download.txt" >/dev/null 2>&1 || true

  # 4. Consolidate Findings & Reports
  local findings="$ddir/secrets_findings.txt"
  : > "$findings"
  if [ -d "$findings_tmp" ] && [ "$(ls -A "$findings_tmp" 2>/dev/null)" ]; then
    cat "$findings_tmp"/* >> "$findings"
  fi
  sort -u "$findings" -o "$findings"

  local nf
  nf="$(wc -l < "$findings" | tr -d ' ')"
  log "    [+] Pattern scan completed: $nf secret/token occurrences found -> $findings"

  if [ -s "$findings" ]; then
    sed -E 's/^.* > ([^:]+): .*$/\1/' "$findings" | sort | uniq -c | sort -rn > "$ddir/findings_summary.txt"
    log "    [+] Top Finding Categories:"
    head -n 10 "$ddir/findings_summary.txt" | while read -r c rest; do
      [ -n "$c" ] && log "        - $rest: $c hits"
    done
  fi

  # 5. Extract Endpoints & Parameters
  extract_endpoints_and_params "$beauty_dir" "$ddir"

  # 6. TruffleHog Deep Secret Verification
  if [ "$RUN_TH" = true ]; then
    run_trufflehog "$domain" "$beauty_dir" "$ddir"
  fi

  rm -rf "$tmp_root"
  log ">>> Finished domain: $domain | Output saved in: $ddir"
}

# ---------------------------------------------------------------------------
# Main Execution Loop
# ---------------------------------------------------------------------------
START_TIME="$(date +%s)"
for target in $DOMAINS; do
  process_domain "$target"
done
END_TIME="$(date +%s)"
DURATION=$(( END_TIME - START_TIME ))

log ""
log "==================================================================="
log "[*] JS Reconnaissance Pipeline Finished in $((DURATION/60))m$((DURATION%60))s"
log "[*] Results available in: $(cd "$OUT" && pwd)"
log "==================================================================="
