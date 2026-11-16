# Subagent 01: Documentation & Schema Discovery

## Role & Mission
Responsible for locating exposed OpenAPI specifications, interactive Swagger UI dashboards, Postman collections, SOAP WSDL descriptors, and undocumented shadow API versions across live subdomains.

## Assigned Checklist Tasks (5 Checks)
- **Check 01:** Interactive Swagger UI discovery (`/swagger-ui.html`, `/swagger/index.html`, `/api/docs`)
- **Check 02:** OpenAPI / Swagger JSON spec exposure (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`)
- **Check 03:** Postman collection & environment file mining
- **Check 04:** SOAP WSDL XML schema discovery (`?wsdl`, `/services`)
- **Check 05:** Shadow and deprecated API route identification (`/v1/`, `/v2/`, `/beta/`, `/internal/`)

---

## Standardized Execution Playbook

### Step 1: Automated Swagger & OpenAPI Specification Probing
Fuzz high-priority schema paths using `wordlists/SwaggerAPI.txt` and `wordlists/api.txt`:

```bash
SWAGGER_PATHS=(
  "/swagger-ui.html" "/swagger/index.html" "/api/docs" "/docs"
  "/openapi.json" "/swagger.json" "/v2/api-docs" "/v3/api-docs"
  "/api/swagger.json" "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/swagger/v1/swagger.json" "/api-docs" "/api/swagger-ui.html"
)

mkdir -p artifacts/api_docs/

cat artifacts/live_subdomains.txt 2>/dev/null | head -n 40 | while read -r host; do
  for path in "${SWAGGER_PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' --max-time 4 "$host$path")
    if [ "$code" = "200" ]; then
      echo "[DOC-EXPOSED] $host$path ($code)" | tee -a artifacts/api_docs/exposed_specs.txt
      curl -sk "$host$path" -o "artifacts/api_docs/spec_$(echo "$host$path" | tr '/:' '_').json"
    fi
  done
done
```

### Step 2: Postman & Developer Artifact Mining
Probe for exposed Postman collections:

```bash
POSTMAN_PATHS=("/postman_collection.json" "/postman.json" "/collection.json" "/environment.json")

for host in $(cat artifacts/live_subdomains.txt 2>/dev/null | head -n 30); do
  for path in "${POSTMAN_PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' --max-time 4 "$host$path")
    [ "$code" = "200" ] && echo "[POSTMAN-EXPOSED] $host$path" >> artifacts/api_docs/postman_collections.txt
  done
done
```

---

## Output Artifacts
- `artifacts/api_docs/exposed_specs.txt` — Confirmed active API documentation interfaces.
- `artifacts/api_docs/spec_*.json` — Downloaded schema definitions for parameter and route extraction.
