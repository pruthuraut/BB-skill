# Subagent 05: CMS & API Architecture Profiling (GraphQL, Swagger, REST)

## Role & Mission
Responsible for fingerprinting Content Management Systems (WordPress, Joomla, Drupal) and uncovering modern API architectures, documentation portals (Swagger/OpenAPI), GraphQL endpoints, and API gateways.

## Assigned Checklist Tasks (7 Checks)
- **Check 08:** Identify CMS using WPScan (WordPress), Joomscan (Joomla), Droopescan (Drupal)
- **Check 19:** Check for specific CMS version via `readme.html`, `license.txt`, and `changelog` files
- **Check 21:** Detect API gateway from response headers (`X-Request-ID`, `X-Amzn-Trace`, `Kong`, `Envoy`, `Apigee`)
- **Check 22:** Identify GraphQL endpoint via introspection query
- **Check 23:** Check for Swagger / OpenAPI documentation (`/swagger-ui/`, `/api-docs/`, `/openapi.json`)
- **Check 24:** Detect GraphQL Playground or GraphiQL interface at `/graphql`, `/graphiql`, `/playground`
- **Check 25:** Check for WordPress REST API at `/wp-json/wp/v2/`

---

## Standardized Execution Playbook

### Step 1: CMS Identification & Version Auditing (Checks 08, 19)

#### A. WordPress Auditing
```bash
# 1. WPScan passive fingerprinting
wpscan --url https://<target> --stealth --detection passive -o artifacts/wpscan.txt

# 2. Check WordPress version & exposed files (Check 19)
for wp_file in "/readme.html" "/license.txt" "/wp-includes/version.php"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${wp_file}")
  if [ "$STATUS" = "200" ]; then
    echo "Exposed WordPress file: ${wp_file}"
    curl -sL "https://<target>${wp_file}" | grep -iE "(Version|WordPress)" | head -n 3
  fi
done
```

#### B. Joomla & Drupal Auditing
```bash
# Joomla Check
curl -sL "https://<target>/administrator/manifests/files/joomla.xml" | grep -iE "<version>"
# Drupal Check
curl -sL "https://<target>/CHANGELOG.txt" | grep -iE "Drupal [0-9]" | head -n 3
```

### Step 2: WordPress REST API Enumeration (Check 25)
Probe `/wp-json/` to extract exposed user accounts, routes, and custom post types:

```bash
# Fetch root REST index
curl -sL "https://<target>/wp-json/" | jq -r '.name, .description, .namespaces[]' 2>/dev/null

# Enumerate WP Users via REST API
curl -sL "https://<target>/wp-json/wp/v2/users" | jq -r '.[].slug' > artifacts/wp_users.txt
if [ -s "artifacts/wp_users.txt" ]; then
  echo "[+] Leaked WordPress Usernames via REST API:"
  cat artifacts/wp_users.txt
fi
```

### Step 3: API Gateway & Proxy Header Detection (Check 21)
Examine headers that indicate managed enterprise gateways:

```bash
curl -sIL https://<target>/api/ | grep -iE "(X-Amzn-Trace-Id|X-Request-Id|X-Kong-|x-envoy-|X-Apigee-|x-zuul-|X-Tyk-)" > artifacts/api_gateway_headers.txt

# Common Gateway Indicators:
# AWS API Gateway: 'X-Amzn-Trace-Id', 'x-amz-apigw-id'
# Kong: 'X-Kong-Proxy-Latency', 'Server: kong'
# Envoy: 'x-envoy-upstream-service-time', 'server: envoy'
# Apigee: 'X-Apigee-Fault-Flag', 'X-Apigee-Message-ID'
```

### Step 4: Swagger & OpenAPI Documentation Discovery (Check 23)
*TBHM Quick Hit Rule:* Discovering interactive API documentation unlocks the entire attack surface for IDOR, SSRF, and parameter fuzzing.

```bash
SWAGGER_PATHS=(
  "/swagger-ui.html"
  "/swagger-ui/"
  "/swagger/v1/swagger.json"
  "/swagger.json"
  "/swagger/index.html"
  "/api-docs"
  "/api-docs.json"
  "/v1/api-docs"
  "/v2/api-docs"
  "/v3/api-docs"
  "/openapi.json"
  "/openapi.yaml"
  "/api/swagger"
  "/api/docs"
  "/documentation"
)

for p in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${p}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] HIGH VALUE: Interactive Swagger/OpenAPI documentation discovered at: ${p}" >> artifacts/discovered_swagger.txt
  fi
done
```

### Step 5: GraphQL Discovery, Playgrounds & Introspection (Checks 22, 24)
Probe GraphQL endpoints, test for enabled GraphiQL / Apollo Playgrounds, and execute introspection queries:

```bash
GRAPHQL_PATHS=(
  "/graphql"
  "/api/graphql"
  "/v1/graphql"
  "/query"
  "/graphiql"
  "/playground"
  "/graphql/console"
)

# 1. Probe for GraphQL Interfaces (Check 24)
for gp in "${GRAPHQL_PATHS[@]}"; do
  RESP=$(curl -sL -H "Accept: text/html" "https://<target>${gp}")
  if echo "$RESP" | grep -qiE "(GraphQL Playground|GraphiQL|ApolloServer)"; then
    echo "[!] HIGH VALUE: Interactive GraphQL Playground exposed at: ${gp}" >> artifacts/graphql_playgrounds.txt
  fi
done

# 2. Test GraphQL Introspection Query (Check 22)
for gp in "/graphql" "/api/graphql" "/v1/graphql"; do
  INTRO_RES=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    --data '{"query":"query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"}' \
    "https://<target>${gp}")
  
  if echo "$INTRO_RES" | grep -q "__schema"; then
    echo "[!] CRITICAL: Full GraphQL Introspection Enabled at: ${gp}" >> artifacts/graphql_introspection.txt
    echo "$INTRO_RES" > "artifacts/graphql_schema.json"
  fi
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_05_cms_api_architecture.md`
