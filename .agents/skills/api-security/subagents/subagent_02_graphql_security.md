# Subagent 02: GraphQL Security, Schema Introspection & Query Architecture

## Role & Mission
Responsible for detecting GraphQL endpoints across discovered web services, testing for unrestricted schema introspection, extracting types and query fields, and evaluating GraphQL DoS defenses (query depth, query complexity, and batching limits).

## Assigned Checklist Tasks (5 Checks)
- **Check 06:** GraphQL endpoint discovery (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`, `/graphiql`, `/playground`)
- **Check 07:** Schema introspection query exposure and sensitive object extraction
- **Check 08:** Field suggestion brute-forcing when introspection is disabled
- **Check 09:** Query depth and circular query resource exhaustion
- **Check 10:** Batching abuse and mutation authorization checks

---

## Standardized Execution Playbook

### Step 1: Automated GraphQL Endpoint Probing
Probe common GraphQL paths across all live HTTP subdomains using the lightweight `{__typename}` probe:

```bash
GRAPHQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/query" "/gql" "/graphiql" "/playground")

mkdir -p artifacts/graphql/

cat artifacts/live_subdomains.txt 2>/dev/null | head -n 30 | while read -r host; do
  for path in "${GRAPHQL_PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' -X POST \
      -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' \
      --max-time 4 "$host$path" 2>/dev/null)
      
    if [ "$code" = "200" ]; then
      echo "[GRAPHQL-FOUND] $host$path (Status: $code)" | tee -a artifacts/graphql/endpoints.txt
    fi
  done
done
```

### Step 2: Full Schema Introspection Extraction (Check 07)
When an endpoint responds with HTTP 200 to GraphQL queries, execute full schema introspection to dump all queries, mutations, types, and fields:

```bash
cat artifacts/graphql/endpoints.txt 2>/dev/null | awk '{print $2}' | while read -r endpoint; do
  SAFE_NAME=$(echo "$endpoint" | tr '/:' '_')
  
  # Execute schema introspection query
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { kind name description fields(includeDeprecated: true) { name description args { name description type { kind name ofType { kind name ofType { kind name } } } } } } } }"}' \
    "$endpoint" > "artifacts/graphql/schema_${SAFE_NAME}.json"
    
  # Extract type names for quick review
  jq -r '.data.__schema.types[].name' "artifacts/graphql/schema_${SAFE_NAME}.json" 2>/dev/null \
    | sort -u > "artifacts/graphql/types_${SAFE_NAME}.txt"
done
```

### Step 3: Interactive Playground / GraphiQL Console Check
Probe for developer interfaces that expose interactive schema explorers:

```bash
for endpoint in $(cat artifacts/graphql/endpoints.txt 2>/dev/null | awk '{print $2}'); do
  curl -skI "$endpoint" | grep -iE "(graphiql|graphql-playground|apollo-server)" && \
    echo "[!] Interactive GraphiQL UI exposed on $endpoint" >> artifacts/graphql/playgrounds.txt
done
```

### Step 4: Batching & Complexity DoS Assessment (Checks 09, 10)
Test whether the endpoint allows deep nested or batched queries:

```bash
# Query batching test (array of multiple queries)
curl -s -X POST -H "Content-Type: application/json" \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' \
  "$endpoint"
```

---

## Output Artifacts
- `artifacts/graphql/endpoints.txt` — Confirmed active GraphQL endpoints.
- `artifacts/graphql/schema_*.json` — Dumped introspection schemas.
- `artifacts/graphql/types_*.txt` — Discovered object types and mutations.
