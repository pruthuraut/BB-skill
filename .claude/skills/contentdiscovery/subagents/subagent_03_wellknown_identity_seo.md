# Subagent 03: Well-Known, SEO & Identity Federation Discovery

## Role & Mission
Responsible for analyzing web crawling directives (`robots.txt`, `sitemap.xml`), standard metadata (`security.txt`), mobile application linking schemas (`assetlinks.json`, `apple-app-site-association`), and OAuth / OpenID Connect discovery endpoints.

## Assigned Checklist Tasks (8 Checks)
- **Check 05:** Inspect `robots.txt` and analyze all `Disallow:` and `Allow:` entries
- **Check 06:** Parse `sitemap.xml` for hidden routes, administrative paths, and site structure
- **Check 07:** Enumerate the `/.well-known/` directory and standard resources
- **Check 46:** Discover and audit exposed `/.well-known/openid-configuration`
- **Check 47:** Discover and audit `/.well-known/oauth-authorization-server`
- **Check 48:** Inspect `/.well-known/assetlinks.json` for Android package and SHA256 leaks
- **Check 49:** Inspect `/.well-known/apple-app-site-association` for iOS universal link routing
- **Check 50:** Inspect `/.well-known/security.txt` and `/security.txt` for policy and contact disclosure

---

## Standardized Execution Playbook

### Step 1: Robots.txt & Sitemap.xml Deep Extraction (Checks 05, 06)
```bash
# 1. Fetch robots.txt and parse Disallowed paths
curl -sL "https://<target>/robots.txt" > artifacts/robots.txt
grep -iE "^(Disallow|Allow):" artifacts/robots.txt | awk '{print $2}' | sort -u > artifacts/disallowed_paths.txt

# 2. Extract sitemaps referenced in robots.txt or root
SITEMAP_URL=$(grep -i "^Sitemap:" artifacts/robots.txt | head -n 1 | awk '{print $2}')
if [ -z "$SITEMAP_URL" ]; then
  SITEMAP_URL="https://<target>/sitemap.xml"
fi

curl -sL "$SITEMAP_URL" > artifacts/sitemap.xml
grep -oE "<loc>(https?://[^<]+)</loc>" artifacts/sitemap.xml | sed -e 's/<loc>//g' -e 's/<\/loc>//g' | sort -u > artifacts/sitemap_urls.txt
```

### Step 2: RFC 8615 `/.well-known/` Resource Probing (Checks 07, 50)
```bash
WELL_KNOWN_FILES=(
  "/.well-known/security.txt"
  "/security.txt"
  "/.well-known/change-password"
  "/.well-known/host-meta"
  "/.well-known/nodeinfo"
  "/.well-known/dnt-policy.txt"
)

for wk in "${WELL_KNOWN_FILES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${wk}")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found .well-known resource: ${wk}" >> artifacts/well_known_found.txt
  fi
done
```

### Step 3: Identity & OAuth Federation Configuration (Checks 46, 47)
*High-Value Intelligence:* `openid-configuration` reveals every authentication endpoint, token endpoint, JWKS URI, userinfo endpoint, supported response types, and claims.

```bash
for oidc in "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server" "/oauth2/.well-known/openid-configuration"; do
  RESP=$(curl -sL "https://<target>${oidc}")
  if echo "$RESP" | grep -qi "issuer"; then
    echo "[!] HIGH VALUE: Identity Provider Configuration Exposed at: ${oidc}" >> artifacts/oidc_configs.txt
    echo "$RESP" | jq . > "artifacts/oidc_schema.json" 2>/dev/null
  fi
done
```

### Step 4: Mobile Universal Linking Schemas (Checks 48, 49)
Mobile app linking configurations expose internal bundle IDs, developer account IDs, and client routing paths:

```bash
# Android App Linking (Check 48)
curl -sL "https://<target>/.well-known/assetlinks.json" > artifacts/assetlinks.json
if grep -q "package_name" artifacts/assetlinks.json; then
  echo "[+] Android App Links Discovered:"
  jq -r '.[].target.package_name' artifacts/assetlinks.json 2>/dev/null
fi

# Apple Universal Links (Check 49)
curl -sL "https://<target>/.well-known/apple-app-site-association" > artifacts/apple-app-site-association.json
if grep -qi "applinks" artifacts/apple-app-site-association.json; then
  echo "[+] iOS Apple App Site Association Discovered:"
  jq -r '.applinks.details[].appID' artifacts/apple-app-site-association.json 2>/dev/null
fi
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_03_wellknown_results.md`
