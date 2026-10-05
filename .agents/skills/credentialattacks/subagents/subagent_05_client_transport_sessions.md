# Subagent 05: Client-Side Security, Transport & Session Policies

## Role & Mission
Responsible for evaluating client-side credential storage (`localStorage`, `sessionStorage`, browser autocomplete), transport layer security (HTTPS enforcement, HSTS), password manager compatibility, step-up 2FA re-authentication policies, and concurrent multi-session revocation rules.

## Assigned Checklist Tasks (7 Checks)
- **Check 17:** Passwords always transmitted strictly over HTTPS without mixed-content
- **Check 18:** Password stored in browser autocomplete (`autocomplete="on"` vs `autocomplete="current-password"`)
- **Check 19:** Password stored in client-side `localStorage` or `sessionStorage`
- **Check 29:** 2FA enforced for sensitive account actions (email/password/payout modification)
- **Check 37:** Simultaneous login policy from multiple geographic locations/IPs
- **Check 38:** Credential rotation policy enforcement
- **Check 39:** Password manager attribute compliance (`autocomplete="new-password"`)

---

## Standardized Execution Playbook

### Step 1: Transport Layer Security & HTTPS Enforcement (Check 17)
```bash
# 1. Check HTTP to HTTPS redirection
curl -sI "http://<target>/login" | grep -iE "(Location: https://|Strict-Transport-Security)"

# 2. Check login form action URL
curl -sL "https://<target>/login" | grep -i '<form' | grep -i 'action="http://' && echo "[!] CRITICAL: Form action submits over insecure HTTP!"
```

### Step 2: Client-Side Storage Inspection (Check 19)
Passwords should NEVER be cached in browser storage (where any XSS vulnerability can extract them immediately):

```javascript
// Run via Browser DevTools Console or Headless Script
function checkStorageForCredentials() {
  const leaks = [];
  ['localStorage', 'sessionStorage'].forEach(store => {
    for (let i = 0; i < window[store].length; i++) {
      const key = window[store].key(i);
      const val = window[store].getItem(key);
      if (/password|passwd|pass|secret|token/i.test(key) || /"password":/i.test(val)) {
        leaks.push({storage: store, key: key, value: val});
      }
    }
  });
  return leaks;
}
console.log(checkStorageForCredentials());
```

### Step 3: Autocomplete & Password Manager Field Semantics (Checks 18, 39)
Inspect `<input type="password">` elements for modern RFC security attributes:

```bash
# Correct secure standard:
# Login form: <input type="password" name="password" autocomplete="current-password">
# Registration / Reset: <input type="password" name="new_password" autocomplete="new-password">

# Insecure legacy configurations:
# <input type="password" autocomplete="on">
curl -sL "https://<target>/login" | grep -oE '<input[^>]+type="password"[^>]*>' > artifacts/password_inputs.txt
```

### Step 4: Step-Up 2FA Re-Authentication on Sensitive Actions (Check 29)
*High-Impact Audit:* Even when logged in with 2FA, changing the primary email, updating payout details, or generating API keys must require re-entering the 2FA code:

```bash
# Attempt updating sensitive settings without providing a 2FA code in the request body or header
curl -s -X POST "https://<target>/api/user/update-email" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' > artifacts/email_change_response.json

if grep -qi "success" artifacts/email_change_response.json; then
  echo "[!] HIGH: Sensitive account action executed without Step-Up 2FA validation!"
fi
```

### Step 5: Concurrent Multi-Session Management (Check 37)
Audit whether authenticating from a new IP/device invalidates existing active sessions or prompts the user:

```bash
# 1. Login from Session A (IP 1)
# 2. Login from Session B (IP 2)
# 3. Check if Session A remains fully authorized or receives 401 Unauthorized
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_05_client_transport_report.md`
