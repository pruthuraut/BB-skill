# Subagent 05: API Formats, Legacy Gateways & Functional Workflows

## Role & Mission
Responsible for mapping specialized API architectures, authentication and callback workflows, legacy integration protocols (SOAP, XML-RPC), file upload processors, bulk batch endpoints, and asset CDN storage locations.

## Assigned Checklist Tasks (14 Checks)
- **Check 19:** REST API versioning (`/v1/`, `/v2/`, `/v3/`, `/api/beta/`)
- **Check 20:** GraphQL schema introspection queries (`/graphql`)
- **Check 21:** SOAP WSDL service endpoints (`?wsdl`, `?WSDL`, `?xsd`)
- **Check 22:** XML-RPC remote procedure call endpoints (`/xmlrpc.php`)
- **Check 26:** Image and static asset CDN URLs for secondary storage targets
- **Check 27:** OAuth 2.0 / OpenID Connect discovery endpoints (`/.well-known/`)
- **Check 28:** SAML 2.0 metadata endpoints (`/saml/metadata`, `/federationmetadata.xml`)
- **Check 29:** Callback and redirect parameters in OAuth/SSO flows
- **Check 32:** Email preview templates with dynamic URL parameters
- **Check 33:** Webhook registration endpoints with user-controlled destination URLs
- **Check 34:** File upload endpoints and multipart parameter processing
- **Check 35:** Data export and download endpoints (`format=csv`, `type=xlsx`, `pdf`)
- **Check 38:** Batch and bulk operation endpoints (`/batch`, `/bulk`)

---

## Standardized Execution Playbook

### Step 1: REST API Version Probing (Check 19 & api.txt / API-FUZZ.txt)
*Methodology:* Older API versions (e.g. `/v1/`) frequently retain unpatched vulnerabilities (IDOR, missing authentication, SQLi) long after `/v2/` or `/v3/` has been updated:

```bash
# Substitute version strings across all discovered API paths
python3 -c "
with open('artifacts/discovered_endpoints.txt') as f:
    endpoints = [l.strip() for l in f if '/v' in l]

probes = set()
for ep in endpoints:
    for v in ['/v0/', '/v1/', '/v2/', '/v3/', '/v4/', '/api/beta/', '/api/internal/']:
        modified = re.sub(r'\/v[0-9]+\/', v, ep)
        probes.add(modified)

with open('artifacts/versioned_api_probes.txt', 'w') as out:
    for p in sorted(probes):
        out.write(p + '\n')
"
```

### Step 2: SOAP WSDL & XML-RPC Services (Checks 21, 22 & wad.txt / svc.txt)
Use `wad.txt` and `svc.txt` from resources to detect exposed enterprise service contracts:

```bash
# 1. SOAP WSDL probing (Check 21)
WORDLIST_WAD="wordlists/wad.txt"
WORDLIST_SVC="wordlists/svc.txt"

ffuf -u "https://<target>/FUZZ?wsdl" -w "$WORDLIST_SVC" -mc 200 -o artifacts/soap_wsdl.json -of json

# 2. XML-RPC System Methods (Check 22)
curl -s -X POST -H "Content-Type: text/xml" \
  -d "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" \
  "https://<target>/xmlrpc.php" > artifacts/xmlrpc_response.xml

if grep -q "methodResponse" artifacts/xmlrpc_response.xml; then
  echo "[!] XML-RPC active with system.listMethods!"
fi
```

### Step 3: SAML & OAuth Authentication Flows (Checks 27, 28, 29)
```bash
# 1. SAML Metadata (Check 28)
SAML_PATHS=("/saml/metadata" "/saml2/metadata" "/FederationMetadata/2007-06/FederationMetadata.xml" "/auth/saml/metadata")
for sp in "${SAML_PATHS[@]}"; do
  curl -sL "https://<target>${sp}" | grep -qi "EntityDescriptor" && echo "[!] SAML Metadata exposed at: ${sp}" >> artifacts/saml_endpoints.txt
done

# 2. Callback & Redirect Parameters (Check 29)
# Inspect login/SSO links for redirect targets
grep -Ei "(redirect_uri|redirect_url|return_to|callback|goto|dest)=" artifacts/katana_discovered_urls.txt > artifacts/auth_redirect_params.txt
```

### Step 4: Webhooks, Uploads, Exports & Batch Endpoints (Checks 32, 33, 34, 35, 38)
*High-Value Vulnerability Vectors:*
- **Webhooks (Check 33):** Prime target for SSRF (Server-Side Request Forgery).
- **File Uploads (Check 34):** Prime target for RCE and stored XSS.
- **Exports (Check 35):** Prime target for CSV Injection, SSRF via PDF rendering engines, and DoS.
- **Batch Processing (Check 38):** Prime target for rate-limit bypass and mass assignment.

```bash
# Probe for high-value workflow endpoints
WORKFLOW_PATHS=(
  "/api/v1/webhooks"
  "/webhook/register"
  "/settings/webhooks"
  "/api/upload"
  "/upload/image"
  "/api/v1/export"
  "/export/csv"
  "/reports/download"
  "/api/batch"
  "/api/v1/bulk"
)

for wp in "${WORKFLOW_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${wp}")
  if [ "$STATUS" != "404" ]; then
    echo "[!] Active Workflow Endpoint [HTTP ${STATUS}]: ${wp}" >> artifacts/workflow_endpoints.txt
  fi
done
```

### Step 5: Static Asset CDN URLs (Check 26)
```bash
# Extract third-party and cloud asset CDN endpoints (S3, CloudFront, Azure Blob)
grep -oE "https://[a-zA-Z0-9_\-\.]+\.(amazonaws\.com|cloudfront\.net|azureedge\.net|blob\.core\.windows\.net|storage\.googleapis\.com|imgix\.net)[^\"' ]*" artifacts/katana_discovered_urls.txt | sort -u > artifacts/asset_cdn_targets.txt
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_05_api_workflows.md`
