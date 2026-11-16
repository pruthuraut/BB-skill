# Subagent 05: Debug Endpoints, Test Files & API Documentation

## Role & Mission
Responsible for locating exposed server log files, debugging routines, unit testing suites, Prometheus telemetry metrics, and API documentation portals.

## Assigned Checklist Tasks (5 Checks)
- **Check 15:** Search for log files (`error.log`, `access.log`, `debug.log`, `application.log`)
- **Check 16:** Discover debug and telemetry endpoints (`/debug`, `/trace`, `/status`, `/healthz`, `/info`)
- **Check 17:** Discover test files and diagnostic scripts (`test.php`, `test.html`, `info.php`, `phpinfo.php`)
- **Check 18:** Locate API documentation and schemas (`/api-docs`, `/swagger`, `/redoc`, `/graphql`)
- **Check 34:** Discover unprotected Prometheus metrics endpoints (`/metrics`)

---

## Standardized Execution Playbook

### Step 1: Log File Discovery using `log.txt` (Check 15)
Exposed application logs often leak session cookies, Authorization bearer tokens, customer PII, and internal stack traces:

```bash
# Fuzz using the specialized log.txt wordlist from resources
WORDLIST_LOG="wordlists/log.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_LOG" \
  -mc 200 \
  -o artifacts/exposed_logs.json -of json
```

### Step 2: Debug & Healthz Endpoints (Check 16)
```bash
DEBUG_ENDPOINTS=(
  "/debug"
  "/debug/vars"
  "/debug/pprof/"
  "/trace"
  "/status"
  "/health"
  "/healthz"
  "/readyz"
  "/livez"
  "/info"
  "/env"
  "/server-status"
  "/server-info"
)

for dep in "${DEBUG_ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${dep}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] Debug/Health endpoint active: ${dep}" >> artifacts/debug_endpoints.txt
  fi
done
```

### Step 3: Test Scripts & Diagnostic Files (Check 17)
Use `phpunit.txt` from resources to detect abandoned unit tests or PHP diagnostic scripts:

```bash
# Fuzz using phpunit.txt
WORDLIST_PHPUNIT="wordlists/phpunit.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_PHPUNIT" \
  -mc 200 \
  -o artifacts/test_scripts.json -of json

# Check for phpinfo() leakage
for pinfo in "/phpinfo.php" "/info.php" "/test.php" "/pi.php" "/i.php"; do
  curl -sL "https://<target>${pinfo}" | grep -qi "PHP Version" && echo "[!] phpinfo() exposed at: ${pinfo}" >> artifacts/phpinfo_leaks.txt
done
```

### Step 4: API Documentation Portals using `api.txt` (Check 18)
```bash
# Fuzz using api.txt from resources
WORDLIST_API="wordlists/api.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_API" \
  -mc 200 \
  -o artifacts/api_docs.json -of json
```

### Step 5: Prometheus Telemetry Metrics (Check 34)
Exposed metrics disclose cluster hostnames, HTTP request rates, database query latencies, and service names:

```bash
METRICS_PATHS=(
  "/metrics"
  "/actuator/prometheus"
  "/prometheus/metrics"
  "/stats/prometheus"
)

for mp in "${METRICS_PATHS[@]}"; do
  RESP=$(curl -sL "https://<target>${mp}")
  if echo "$RESP" | grep -q "go_gc_duration_seconds"; then
    echo "[!] HIGH VALUE: Unprotected Prometheus telemetry exposed at: ${mp}" >> artifacts/prometheus_metrics.txt
  fi
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_05_debug_apis.md`
